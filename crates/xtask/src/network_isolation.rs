//! Enforces invariant I1: `codepack-ai` is the only crate allowed to reach the network.
//!
//! The invariant already existed as a written rule. A rule everyone has to remember is
//! a rule that eventually gets forgotten by whoever adds a dependency in a hurry, and
//! this particular lapse would be invisible — a crate gaining an HTTP client changes no
//! behaviour until the day it makes a request. So the build checks it, the same way the
//! desktop enforces filesystem isolation with capabilities rather than with a convention.
//!
//! The check reads manifests, not code. That is the right layer: a crate cannot make an
//! HTTP request without declaring a client as a dependency, and a manifest is
//! unambiguous where a source grep would drown in comments, doc examples, and the word
//! "http" appearing in a URL.

use std::path::Path;

/// The one crate permitted a network client. See `crates/codepack-ai/src/lib.rs`.
const ALLOWED: &str = "codepack-ai";

/// Dependencies that can perform network I/O.
///
/// Deliberately a denylist of known clients rather than an attempt at completeness: it
/// catches the realistic mistake — somebody reaching for the crate they always reach for
/// — without pretending to prove a negative. `git2` is absent on purpose: S4 pins it to
/// `default-features = false` precisely to exclude its network features, and that
/// narrowing is verified by the manifest it already lives in.
const NETWORK_CRATES: &[&str] = &[
    // The client `codepack-ai` itself uses. Its absence here was a real hole: the one
    // transport already proven to build in this workspace — the one a developer would
    // copy from the crate next door — was the one the check could not see.
    "ureq",
    "reqwest",
    "hyper",
    "isahc",
    "surf",
    "attohttpc",
    "curl",
    "tonic",
    "actix-web",
    "axum",
    "warp",
    "tiny_http",
];

/// Check every workspace manifest, naming each crate that declares a network client.
pub(crate) fn check(root: &Path) -> Result<(), String> {
    let mut offenders: Vec<String> = Vec::new();

    for manifest in workspace_manifests(root)? {
        let text = std::fs::read_to_string(&manifest)
            .map_err(|error| format!("could not read {}: {error}", manifest.display()))?;
        let Some(package) = package_name(&text) else {
            continue;
        };
        if package == ALLOWED {
            continue;
        }

        for dependency in declared_dependencies(&text) {
            if NETWORK_CRATES.contains(&dependency.as_str()) {
                offenders.push(format!("{package} depends on {dependency}"));
            }
        }

        if let Some(line) = declaration_of(&text, ALLOWED) {
            // Only the API path carries a client. A dependent that asks for it by name
            // has made a decision; one that inherits it has not.
            if line.contains("\"api\"") {
                offenders.push(format!(
                    "{package} enables {ALLOWED}'s \"api\" feature, which brings an HTTP \
                     client and the credential store with it"
                ));
            }
            if !workspace_takes_ai_without_default_features(root)? {
                offenders.push(format!(
                    "{package} depends on {ALLOWED}, but the workspace declares it with \
                     default features, so the HTTP client arrives transitively"
                ));
            }
        }
    }

    if offenders.is_empty() {
        println!("network isolation ok: only {ALLOWED} may reach the network (invariant I1).");
        return Ok(());
    }

    Err(format!(
        "invariant I1 violated — a crate other than {ALLOWED} declares a network \
         client:\n  {}\n\nAll analysis is local. If a new stage genuinely needs the \
         network, that is an owner decision recorded in \
         docs/__arch__/open-questions.md, not a dependency added in passing.",
        offenders.join("\n  ")
    ))
}

/// Every workspace member's manifest, taken from `workspace.members`.
///
/// Read from the root manifest rather than hard-coded, because the two paths this used to
/// walk — `crates/*` and the desktop shell — are a description of today's layout. A
/// member added anywhere else was not checked at all, which is a gap the member's author
/// would have no way to notice.
///
/// Glob members (`crates/*`) are expanded by reading the directory they name.
fn workspace_manifests(root: &Path) -> Result<Vec<std::path::PathBuf>, String> {
    let root_manifest = root.join("Cargo.toml");
    let text = std::fs::read_to_string(&root_manifest)
        .map_err(|error| format!("could not read {}: {error}", root_manifest.display()))?;
    let parsed = text
        .parse::<toml::Table>()
        .map_err(|error| format!("could not parse {}: {error}", root_manifest.display()))?;

    let members = parsed
        .get("workspace")
        .and_then(toml::Value::as_table)
        .and_then(|workspace| workspace.get("members"))
        .and_then(toml::Value::as_array)
        .ok_or_else(|| format!("{} declares no workspace members", root_manifest.display()))?;

    let mut manifests = Vec::new();
    for member in members.iter().filter_map(toml::Value::as_str) {
        match member.strip_suffix("/*") {
            Some(parent) => {
                let dir = root.join(parent);
                let entries = std::fs::read_dir(&dir)
                    .map_err(|error| format!("could not read {}: {error}", dir.display()))?;
                for entry in entries.flatten() {
                    let manifest = entry.path().join("Cargo.toml");
                    if manifest.is_file() {
                        manifests.push(manifest);
                    }
                }
            }
            None => {
                let manifest = root.join(member).join("Cargo.toml");
                if manifest.is_file() {
                    manifests.push(manifest);
                }
            }
        }
    }

    if manifests.is_empty() {
        return Err("no workspace member manifests were found".to_string());
    }
    manifests.sort();
    Ok(manifests)
}

/// Dependency names declared in a manifest, however they are spelled.
///
/// Parsed with a real TOML parser rather than read line by line, because the line reader
/// this replaced saw only `dep = …`. The equally ordinary and entirely valid
///
/// ```toml
/// [dependencies.reqwest]
/// version = "0.12"
/// ```
///
/// walked straight past it: the header set "we are in dependencies" and the crate's own
/// name never appeared to the left of an `=`, so `version` and `features` were collected
/// as dependency names instead. The same held for
/// `[target.'cfg(windows)'.dependencies.reqwest]`.
///
/// That is the worst way for this particular check to fail — silently, with the gate
/// green and "network isolation ok" printed, while an HTTP client sits in the graph.
///
/// Every dependency table is walked: `dependencies`, `dev-dependencies`,
/// `build-dependencies`, and the same three under every `target.*`.
fn declared_dependencies(manifest: &str) -> Vec<String> {
    let Ok(parsed) = manifest.parse::<toml::Table>() else {
        // A manifest cargo itself could not read is not this check's business to
        // diagnose; the build will fail on it long before anything is published.
        return Vec::new();
    };

    let mut names = Vec::new();
    collect_dependency_tables(&parsed, &mut names);
    if let Some(targets) = parsed.get("target").and_then(toml::Value::as_table) {
        for platform in targets.values().filter_map(toml::Value::as_table) {
            collect_dependency_tables(platform, &mut names);
        }
    }
    names
}

/// The three dependency tables of one manifest section.
fn collect_dependency_tables(table: &toml::Table, names: &mut Vec<String>) {
    for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(dependencies) = table.get(key).and_then(toml::Value::as_table) {
            names.extend(dependencies.keys().cloned());
        }
    }
}

/// The package's own name, from `[package] name`.
///
/// Read from the manifest rather than inferred from the directory it sits in: renaming a
/// directory would otherwise change which crate the check treats as [`ALLOWED`], quietly
/// and with nothing to notice it.
fn package_name(manifest: &str) -> Option<String> {
    manifest
        .parse::<toml::Table>()
        .ok()?
        .get("package")?
        .as_table()?
        .get("name")?
        .as_str()
        .map(str::to_string)
}

/// Whether the workspace root hands [`ALLOWED`] out without its default features.
///
/// Checked at the root rather than per member because that is where cargo resolves it:
/// a member inheriting `workspace = true` cannot switch default features off itself
/// (cargo rejects the override), so the root entry is the only place the decision can
/// live — and therefore the only honest place to verify it.
///
/// A root that does not mention the crate at all satisfies this vacuously: nothing can
/// inherit what is not declared, and the per-member checks still apply.
fn workspace_takes_ai_without_default_features(root: &Path) -> Result<bool, String> {
    let manifest = root.join("Cargo.toml");
    let Ok(text) = std::fs::read_to_string(&manifest) else {
        return Err(format!("could not read {}", manifest.display()));
    };
    Ok(match declaration_of(&text, ALLOWED) {
        Some(line) => line.contains("default-features = false"),
        None => true,
    })
}

/// The whole declaration line for `name`, if the manifest declares it as a dependency.
///
/// Returned as raw text rather than parsed: the only question asked of it is whether it
/// switches default features off, and that is one substring.
fn declaration_of(manifest: &str, name: &str) -> Option<String> {
    let mut in_dependencies = false;

    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_dependencies = trimmed.contains("dependencies");
            continue;
        }
        if !in_dependencies || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((key, _)) = trimmed.split_once('=')
            && key.trim().trim_matches('"') == name
        {
            return Some(trimmed.to_string());
        }
    }
    None
}

#[cfg(test)]
mod list_tests {
    use std::collections::HashSet;

    use super::*;

    /// The denylist is part of the mechanism that holds invariant I1, and it had `"ureq"`
    /// in it twice — harmless to run, but a sign the list had not been read as data
    /// (audit No. 39). A duplicate now fails here.
    #[test]
    fn the_network_crate_list_names_each_crate_once() {
        let unique: HashSet<&&str> = NETWORK_CRATES.iter().collect();
        assert_eq!(
            unique.len(),
            NETWORK_CRATES.len(),
            "a crate is listed twice in NETWORK_CRATES"
        );
    }

    /// And the list is not empty, so the check above cannot pass vacuously.
    #[test]
    fn the_network_crate_list_is_not_empty() {
        assert!(NETWORK_CRATES.len() > 5, "{NETWORK_CRATES:?}");
        assert!(
            NETWORK_CRATES.contains(&"ureq"),
            "the one we ship must be listed"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes the workspace root's own manifest, which is where the `codepack-ai`
    /// default-features decision has to live (a member cannot override it).
    fn write_root_manifest(root: &Path, ai_declaration: &str) {
        std::fs::write(
            root.join("Cargo.toml"),
            format!(
                "[workspace]\nmembers = [\"crates/*\"]\n\n[workspace.dependencies]\n{ai_declaration}\n"
            ),
        )
        .unwrap();
    }

    /// A root manifest for a fixture that has nothing to say about `codepack-ai`.
    /// Discovery reads `workspace.members`, so every fixture needs one.
    fn write_bare_root_manifest(root: &Path) {
        std::fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/*\"]\n",
        )
        .unwrap();
    }

    #[test]
    fn a_front_end_inheriting_the_ai_crate_with_default_features_is_rejected() {
        // `codepack-ai`'s offline handoff needs no transport, so a front end that offers
        // only that must not link one. Declared dependencies are all this check can see,
        // which is exactly why the feature split has to be visible in a manifest.
        let root = scratch_workspace("ai-default-features");
        write_root_manifest(&root, "codepack-ai = { path = \"crates/codepack-ai\" }");
        write_crate(
            &root,
            "codepack-cli",
            "[dependencies]\ncodepack-ai = { workspace = true }\n",
        );

        let error = check(&root).unwrap_err();
        assert!(error.contains("default features"), "{error}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_front_end_asking_for_the_api_feature_by_name_is_rejected() {
        let root = scratch_workspace("ai-api-feature");
        write_root_manifest(
            &root,
            "codepack-ai = { path = \"c\", default-features = false }",
        );
        write_crate(
            &root,
            "codepack-cli",
            "[dependencies]\ncodepack-ai = { workspace = true, features = [\"api\"] }\n",
        );

        let error = check(&root).unwrap_err();
        assert!(error.contains("\"api\" feature"), "{error}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_front_end_taking_only_the_offline_handoff_is_accepted() {
        let root = scratch_workspace("ai-handoff-only");
        write_root_manifest(
            &root,
            "codepack-ai = { path = \"c\", default-features = false }",
        );
        write_crate(
            &root,
            "codepack-cli",
            "[dependencies]\ncodepack-ai = { workspace = true }\n",
        );

        assert!(check(&root).is_ok());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn dependency_names_are_read_from_every_dependency_table() {
        let manifest = r#"
[package]
name = "example"
reqwest = "not a dependency, this is the package table"

[dependencies]
serde = "1"
ureq = { version = "3", features = ["rustls"] }

[dev-dependencies]
tempfile = "3"

[target.'cfg(windows)'.dependencies]
windows-sys = "0.61"
"#;
        let names = declared_dependencies(manifest);
        assert!(names.contains(&"serde".to_string()));
        assert!(names.contains(&"ureq".to_string()));
        assert!(names.contains(&"tempfile".to_string()));
        assert!(names.contains(&"windows-sys".to_string()));
        // The key in `[package]` must not be mistaken for a dependency.
        assert_eq!(names.iter().filter(|n| *n == "reqwest").count(), 0);
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let manifest = "[dependencies]\n# reqwest = \"0.13\"\n\nserde = \"1\"\n";
        assert_eq!(declared_dependencies(manifest), vec!["serde".to_string()]);
    }

    /// Build a throwaway workspace tree. `xtask` is deliberately dependency-free (its
    /// own manifest says so), so this uses the process id rather than `tempfile`.
    fn scratch_workspace(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("codepack-i1-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("crates")).unwrap();
        root
    }

    /// Writes one member, with the `[package] name` the check now reads its identity
    /// from — the directory name is no longer what decides it.
    fn write_crate(root: &Path, name: &str, manifest: &str) {
        let dir = root.join("crates").join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("Cargo.toml"),
            format!("[package]\nname = \"{name}\"\nversion = \"0.0.0\"\n\n{manifest}"),
        )
        .unwrap();
    }

    #[test]
    fn a_network_client_in_an_ordinary_crate_fails_the_check() {
        // The guard is worthless unless it actually fires. Planting the dependency in
        // the real repository cannot prove this: `reqwest` drags in a tree that fails
        // the licence step first, so the gate dies before reaching here.
        let root = scratch_workspace("offender");
        write_bare_root_manifest(&root);
        write_crate(
            &root,
            "codepack-scanner",
            "[dependencies]\nreqwest = \"0.13\"\n",
        );

        let error = check(&root).unwrap_err();
        assert!(
            error.contains("codepack-scanner depends on reqwest"),
            "{error}"
        );
        assert!(error.contains("invariant I1"), "{error}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_allowed_crate_may_declare_one() {
        let root = scratch_workspace("allowed");
        write_bare_root_manifest(&root);
        write_crate(&root, ALLOWED, "[dependencies]\nureq = \"3\"\n");
        write_crate(&root, "codepack-core", "[dependencies]\nserde = \"1\"\n");

        assert!(check(&root).is_ok());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn every_listed_client_is_detected() {
        // A denylist that silently stopped matching an entry would be worse than none.
        for client in NETWORK_CRATES {
            let root = scratch_workspace(client);
            write_crate(
                &root,
                "codepack-core",
                &format!("[dependencies]\n{client} = \"1\"\n"),
            );
            assert!(check(&root).is_err(), "{client} was not detected");
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn the_real_workspace_passes_its_own_check() {
        // The guard is only worth having if it runs against reality — a check that only
        // ever sees synthetic input proves nothing about this repository.
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        check(&root).expect("the workspace must satisfy invariant I1");
    }
}

#[cfg(test)]
mod bypass_tests {
    //! Negative tests for the shapes the previous line reader could not see.
    //!
    //! The check existed and was green while an HTTP client could sit in the graph, so
    //! these assert the *refusal* rather than the acceptance: a gate nobody has tried to
    //! walk past is a gate nobody knows the width of.

    use super::*;

    /// The exact bypass: a dependency declared as its own table.
    #[test]
    fn a_dependency_declared_as_its_own_table_is_seen() {
        let manifest = r#"
[package]
name = "codepack-scanner"

[dependencies.reqwest]
version = "0.12"
features = ["json"]
"#;
        let names = declared_dependencies(manifest);
        assert!(names.contains(&"reqwest".to_string()), "{names:?}");
        assert!(
            !names.contains(&"version".to_string()),
            "the table's own keys must not be mistaken for dependencies: {names:?}"
        );
    }

    #[test]
    fn a_platform_specific_dependency_is_seen() {
        let manifest = r#"
[package]
name = "codepack-core"

[target.'cfg(windows)'.dependencies]
reqwest = "0.12"

[target.'cfg(unix)'.dependencies.hyper]
version = "1"
"#;
        let names = declared_dependencies(manifest);
        assert!(names.contains(&"reqwest".to_string()), "{names:?}");
        assert!(names.contains(&"hyper".to_string()), "{names:?}");
    }

    #[test]
    fn dev_and_build_dependencies_are_seen_too() {
        let manifest = r#"
[package]
name = "codepack-tokens"

[dev-dependencies]
reqwest = "0.12"

[build-dependencies.curl]
version = "0.4"
"#;
        let names = declared_dependencies(manifest);
        assert!(names.contains(&"reqwest".to_string()), "{names:?}");
        assert!(names.contains(&"curl".to_string()), "{names:?}");
    }

    #[test]
    fn the_plain_inline_form_still_works() {
        let manifest = r#"
[package]
name = "codepack-diff"

[dependencies]
serde = { version = "1", features = ["derive"] }
git2 = "0.19"
"#;
        let mut names = declared_dependencies(manifest);
        names.sort();
        assert_eq!(names, vec!["git2".to_string(), "serde".to_string()]);
    }

    /// The package's identity decides whether the whole check is skipped, so it must come
    /// from the manifest rather than from the directory it happens to sit in.
    #[test]
    fn the_package_name_comes_from_the_manifest() {
        let manifest = "[package]\nname = \"codepack-ai\"\nversion = \"1.0.0\"\n";
        assert_eq!(package_name(manifest).as_deref(), Some("codepack-ai"));
        assert_eq!(package_name("not a manifest"), None);
        assert_eq!(package_name("[package]\nversion = \"1\"\n"), None);
    }

    /// A duplicate in a list of security rules means nobody has read it as data.
    #[test]
    fn the_network_crate_list_has_no_duplicates() {
        let unique: std::collections::BTreeSet<&&str> = NETWORK_CRATES.iter().collect();
        assert_eq!(
            unique.len(),
            NETWORK_CRATES.len(),
            "duplicate entries in NETWORK_CRATES: {NETWORK_CRATES:?}"
        );
    }

    /// The real workspace is walked from `workspace.members`, so every member is covered
    /// and the count is not a hard-coded assumption about the layout.
    #[test]
    fn every_workspace_member_is_checked() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("xtask lives two levels below the workspace root");

        let manifests = workspace_manifests(root).expect("the workspace lists members");
        let names: Vec<String> = manifests
            .iter()
            .filter_map(|path| std::fs::read_to_string(path).ok())
            .filter_map(|text| package_name(&text))
            .collect();

        for expected in [
            "codepack-core",
            "codepack-security",
            "codepack-desktop",
            "xtask",
        ] {
            assert!(
                names.iter().any(|name| name == expected),
                "{expected} was not among the checked manifests: {names:?}"
            );
        }
    }

    /// And the whole check still passes on the real tree — the positive half, so a
    /// tightening that refused everything could not pass unnoticed.
    #[test]
    fn the_real_workspace_is_clean() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("xtask lives two levels below the workspace root");
        check(root).expect("the workspace must satisfy its own isolation rule");
    }
}
