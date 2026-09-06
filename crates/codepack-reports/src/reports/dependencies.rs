//! `03_dependencies.txt`, ported from legacy
//! `reports/insights/dependencies.py::write_dependency_report`. [`parse_go_mod`] is
//! also reused by [`crate::reports::dependency_intelligence`] (legacy: `dependencies.py`
//! is `dependency_intelligence.py`'s only cross-module import).
//!
//! Cargo.toml is deliberately detected but never parsed: legacy's own comment reads
//! "Full Cargo.toml parsing is skipped on purpose to keep the codebase stdlib-only" —
//! a documented parity choice, not an oversight. BLUEPRINT §A.7 lists Cargo.toml among
//! this report's sources, but the legacy report body only ever notes its *presence*,
//! never parses a dependency section from it. Pulling in a TOML-parsing dependency for
//! this one line would be exactly the unjustified new dependency
//! `.ai/universal/05-security-and-secrets.md` forbids for a small need, so this ports
//! the same "detect, don't parse" choice rather than "fixing" it into a real parse.
//!
//! Every line that echoes content read from a manifest (`package.json` values,
//! `requirements*.txt` lines, `go.mod` requirements) is routed through
//! [`crate::context::redact_line`] before being written — invariant I3
//! (`docs/architecture/invariants.md`): raw file content can carry an inline
//! credential (for example a `git+https://user:token@host/repo` requirement line),
//! not just a package name.

use std::path::Path;

use crate::context::{ReportContext, redact_line, root_entry_exists};
use crate::error::ReportError;
use crate::paths::path_depth;
use crate::plugin::ReportJob;
use crate::profile;
use crate::reports::layout::section_rule;
use crate::text::{read_text_unredacted, safe_read_json};

pub const JOB: ReportJob = ReportJob {
    filename: "03_dependencies.txt",
    profiles: profile::DEPENDENCIES_TXT,
    description: "Dependencies parsed from package.json / requirements*.txt / go.mod.",
    run: write_dependency_report,
};

const REQUIREMENTS_LINE_LIMIT: usize = 300;
const GO_REQUIREMENT_LIMIT: usize = 300;

/// Legacy `parse_go_mod`: a hand-rolled reader (no TOML/Go-module library) supporting
/// both single-line `require pkg v1.0` and block `require ( ... )` syntax.
pub fn parse_go_mod(text: &str) -> (String, Vec<String>) {
    let mut module_name = String::new();
    let mut requirements = Vec::new();
    let mut in_require_block = false;

    for line in text.lines() {
        let stripped = line.trim();
        if let Some(name) = stripped.strip_prefix("module ") {
            module_name = name.trim().to_string();
        } else if stripped == "require (" {
            in_require_block = true;
        } else if in_require_block && stripped == ")" {
            in_require_block = false;
        } else if let Some(rest) = stripped.strip_prefix("require ") {
            requirements.push(rest.trim().to_string());
        } else if in_require_block && !stripped.is_empty() && !stripped.starts_with("//") {
            requirements.push(stripped.to_string());
        }
    }

    (module_name, requirements)
}

/// Renders a JSON scalar the way it should read in plain text — a string as itself, a
/// bool as `true`/`false`, a number as its literal form. `package.json` fields this
/// report quotes (`private`, `version`, ...) are simple scalars in practice; anything
/// else falls back to its compact JSON form rather than panicking on an unexpected
/// shape.
fn describe_json_scalar(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Bool(flag) => flag.to_string(),
        serde_json::Value::Number(number) => number.to_string(),
        other => other.to_string(),
    }
}

fn write_dependency_section(
    out: &mut String,
    title: &str,
    section: Option<&serde_json::Map<String, serde_json::Value>>,
) {
    out.push_str(&format!("\n--- {title} ---\n"));
    match section {
        Some(deps) if !deps.is_empty() => {
            let mut names: Vec<&String> = deps.keys().collect();
            names.sort_by_key(|name| name.to_lowercase());
            for name in names {
                let version = describe_json_scalar(&deps[name]);
                out.push_str(&redact_line(&format!("{name:<45} {version}\n")));
            }
        }
        _ => out.push_str("None.\n"),
    }
}

fn write_dependency_report(ctx: &ReportContext<'_>, output_file: &Path) -> Result<(), ReportError> {
    let package_json_value = safe_read_json(&ctx.staging_root.join("package.json"));
    let package_json = package_json_value.as_object();
    let managers = crate::context::detect_package_managers(ctx.inventory);

    let mut out = String::new();
    out.push_str("=== Dependency Report ===\n");
    out.push_str(&format!("Generated: {}\n", ctx.plan.generated_at));
    out.push_str(&section_rule('='));
    out.push_str("\n\n");

    out.push_str(&format!(
        "Detected package managers: {}\n\n",
        if managers.is_empty() {
            "not detected".to_string()
        } else {
            managers.join(", ")
        }
    ));

    match package_json {
        Some(package_json) => {
            out.push_str("--- package.json metadata ---\n");
            for key in ["name", "version", "type", "private", "packageManager"] {
                if let Some(value) = package_json.get(key) {
                    out.push_str(&redact_line(&format!(
                        "{key:<20}: {}\n",
                        describe_json_scalar(value)
                    )));
                }
            }
            if let Some(engines) = package_json.get("engines").and_then(|v| v.as_object()) {
                out.push_str("engines:\n");
                let mut names: Vec<&String> = engines.keys().collect();
                names.sort();
                for name in names {
                    out.push_str(&redact_line(&format!(
                        "  - {name}: {}\n",
                        describe_json_scalar(&engines[name])
                    )));
                }
            }

            for section in [
                "dependencies",
                "devDependencies",
                "peerDependencies",
                "optionalDependencies",
            ] {
                write_dependency_section(
                    &mut out,
                    section,
                    package_json.get(section).and_then(|v| v.as_object()),
                );
            }
        }
        None => out.push_str("package.json: not found or unreadable.\n"),
    }

    let mut requirements_files: Vec<&crate::context::InventoryFile> = ctx
        .inventory
        .files
        .iter()
        .filter(|file| {
            path_depth(&file.relative_path) == 1 && {
                let lower = file.relative_path.to_lowercase();
                lower.starts_with("requirements") && lower.ends_with(".txt")
            }
        })
        .collect();
    requirements_files.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));

    if !requirements_files.is_empty() {
        out.push_str("\n--- Python requirements files ---\n");
        for file in requirements_files {
            out.push_str(&format!("\nFile: {}\n", file.relative_path));
            match read_text_unredacted(&ctx.resolve(&file.relative_path), None) {
                Some(text) => {
                    let lines: Vec<&str> = text
                        .lines()
                        .map(|line| line.trim())
                        .filter(|line| !line.is_empty() && !line.starts_with('#'))
                        .collect();
                    for line in lines.iter().take(REQUIREMENTS_LINE_LIMIT) {
                        out.push_str(&redact_line(&format!("- {line}\n")));
                    }
                    if lines.len() > REQUIREMENTS_LINE_LIMIT {
                        out.push_str(&format!(
                            "... and {} more\n",
                            lines.len() - REQUIREMENTS_LINE_LIMIT
                        ));
                    }
                }
                None => out.push_str("Could not read this file.\n"),
            }
        }
    }

    if root_entry_exists(&ctx.staging_root, "go.mod") {
        out.push_str("\n--- Go modules ---\n");
        let go_mod_path = ctx.staging_root.join("go.mod");
        let (module_name, requirements) = read_text_unredacted(&go_mod_path, None)
            .map(|text| parse_go_mod(&text))
            .unwrap_or_default();
        out.push_str(&format!(
            "module: {}\n",
            if module_name.is_empty() {
                "not detected".to_string()
            } else {
                module_name
            }
        ));
        for requirement in requirements.iter().take(GO_REQUIREMENT_LIMIT) {
            out.push_str(&redact_line(&format!("- {requirement}\n")));
        }
        if requirements.len() > GO_REQUIREMENT_LIMIT {
            out.push_str(&format!(
                "... and {} more\n",
                requirements.len() - GO_REQUIREMENT_LIMIT
            ));
        }
    }

    if root_entry_exists(&ctx.staging_root, "Cargo.toml") {
        out.push_str("\n--- Rust Cargo ---\n");
        out.push_str(
            "Cargo.toml detected. Full TOML parsing is intentionally not performed without external dependencies.\n",
        );
    }

    std::fs::write(output_file, out).map_err(|source| ReportError::Write {
        path: output_file.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::Fixture;

    #[test]
    fn parses_go_mod_block_and_single_line_requirements() {
        let text = "module example.com/app\n\nrequire (\n\tgithub.com/foo/bar v1.2.3\n\t// a comment\n\tgithub.com/baz/qux v0.1.0\n)\n\nrequire github.com/single/dep v2.0.0\n";
        let (module, requirements) = parse_go_mod(text);
        assert_eq!(module, "example.com/app");
        assert_eq!(
            requirements,
            vec![
                "github.com/foo/bar v1.2.3".to_string(),
                "github.com/baz/qux v0.1.0".to_string(),
                "github.com/single/dep v2.0.0".to_string(),
            ]
        );
    }

    #[test]
    fn malformed_go_mod_yields_empty_result_without_panicking() {
        let (module, requirements) = parse_go_mod("not a go.mod file\njust garbage\n");
        assert_eq!(module, "");
        assert!(requirements.is_empty());
    }

    #[test]
    fn writes_dependencies_for_a_node_and_python_fixture() {
        let fixture = Fixture::new(|root| {
            std::fs::write(
                root.join("package.json"),
                r#"{"name": "demo", "version": "1.0.0", "private": true, "dependencies": {"react": "18.0.0"}, "devDependencies": {"vite": "5.0.0"}}"#,
            )
            .unwrap();
            std::fs::write(
                root.join("requirements.txt"),
                "# comment\n\nrequests==2.31.0\nflask>=3.0\n",
            )
            .unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_dependency_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("name") && content.contains(": demo"));
        assert!(content.contains("private") && content.contains(": true"));
        assert!(content.contains("react"));
        assert!(content.contains("vite"));
        assert!(content.contains("requests==2.31.0"));
        assert!(content.contains("flask>=3.0"));
        assert!(!content.contains("# comment"));
    }

    #[test]
    fn malformed_package_json_falls_back_to_not_found_message() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("package.json"), "{ not valid json").unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_dependency_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("package.json: not found or unreadable."));
    }

    #[test]
    fn cargo_toml_presence_is_noted_but_not_parsed() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_dependency_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("Cargo.toml detected."));
        assert!(!content.contains("[package]"));
    }
}
