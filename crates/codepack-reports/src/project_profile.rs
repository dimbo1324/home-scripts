//! `PROJECT_PROFILE.json`, ported from legacy
//! `reports/insights/project_profile.py::build_project_profile`/
//! `write_project_profile_json`. Field declaration order mirrors the legacy dict's
//! insertion order (invariant I5's spirit, applied to this artifact from day one):
//! `schema_version`, `generated_at`, `project_name`, `source_root`, `copied_root`,
//! `project_type`, `detected_stack`, `stack_by_group`, `package_managers`,
//! `entrypoints`, `commands`, `docker_compose_files`, `npm_scripts`, `capabilities`,
//! `counts`, `risk_level`, `risk_reasons`, `important_config_files`.
//!
//! `important_config_files`/`docker_compose_files` need "is this a known config file"
//! classification; legacy imports `find_config_files` from `config_report.py`. This
//! module now calls [`crate::reports::config::find_config_files`] (Group D's
//! `09_config.txt` report) directly rather than keeping its own copy — an earlier pass
//! (Group G, before Group D existed) carried a self-contained duplicate of the same
//! legacy name/prefix rules, documented as tech debt at the time; that duplicate is
//! removed now that the canonical implementation exists. Legacy's own
//! `project_profile.py::build_project_profile` truncates `important_config_files` to
//! its first 100 entries at its own assignment site — `find_config_files` itself never
//! truncates — so that same truncation happens here, locally, rather than inside the
//! shared helper.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::context::{DetectedStack, ReportContext, root_entry_exists};
use crate::error::ReportError;
use crate::paths::{file_name_of, looks_like_test_path};
use crate::text::{read_text_unredacted, safe_read_json};

pub const PROJECT_PROFILE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProjectCommands {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub install: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dev: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub build: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub test: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub run: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProjectCapabilities {
    pub has_git: bool,
    pub has_ci: bool,
    pub has_tests: bool,
    pub has_docker: bool,
    pub has_env_files: bool,
    pub has_readme: bool,
    pub has_license: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProjectCounts {
    pub files: usize,
    pub folders: usize,
    pub total_size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectProfile {
    pub schema_version: u32,
    pub generated_at: String,
    pub project_name: String,
    pub source_root: String,
    pub copied_root: String,
    pub project_type: String,
    pub detected_stack: Vec<String>,
    pub stack_by_group: DetectedStack,
    pub package_managers: Vec<String>,
    pub entrypoints: Vec<String>,
    pub commands: ProjectCommands,
    pub docker_compose_files: Vec<String>,
    pub npm_scripts: BTreeMap<String, String>,
    pub capabilities: ProjectCapabilities,
    pub counts: ProjectCounts,
    pub risk_level: String,
    pub risk_reasons: Vec<String>,
    pub important_config_files: Vec<String>,
}

/// Legacy `rel_display`: a relative path rendered with a leading `.\`. `configs`
/// already carries backslash-separated relative paths, so only the prefix is added.
/// Omitted originally, which left `important_config_files` as the one list in this
/// artifact whose entries did not match legacy's rendering (found by the golden suite,
/// 2026-07-25).
fn rel_display(relative_path: &str) -> String {
    if relative_path.is_empty() || relative_path == "." {
        ".".to_string()
    } else {
        format!(".\\{relative_path}")
    }
}

fn detect_project_type(ctx: &ReportContext<'_>, stack: &DetectedStack) -> String {
    let has_frontend = !stack.frontend.is_empty()
        || [
            "package.json",
            "vite.config.ts",
            "vite.config.js",
            "next.config.js",
        ]
        .iter()
        .any(|name| root_entry_exists(&ctx.staging_root, name));
    let has_backend = !stack.backend.is_empty()
        || ["pyproject.toml", "requirements.txt", "go.mod", "Cargo.toml"]
            .iter()
            .any(|name| root_entry_exists(&ctx.staging_root, name));

    let has_tkinter = ctx.inventory.files.iter().any(|file| {
        let extension = file.extension.as_str();
        if extension != "py" && extension != "pyw" {
            return false;
        }
        let path = ctx.resolve(&file.relative_path);
        match read_text_unredacted(&path, Some(20_000)) {
            Some(text) => text.contains("import tkinter") || text.contains("from tkinter"),
            None => false,
        }
    });

    if has_frontend && has_backend {
        "fullstack".to_string()
    } else if has_tkinter {
        "python_desktop_tool".to_string()
    } else if has_frontend {
        "frontend".to_string()
    } else if has_backend {
        "backend_or_cli".to_string()
    } else {
        "unknown".to_string()
    }
}

const ENTRYPOINT_CANDIDATES: &[&str] = &[
    "main.py",
    "app.py",
    "server.py",
    "manage.py",
    "src\\main.py",
    "src\\app.py",
    "src\\__main__.py",
    "src\\index.ts",
    "src\\index.tsx",
    "src\\main.ts",
    "src\\main.tsx",
    "src\\App.tsx",
    "cmd\\main.go",
    "main.go",
];

fn detect_entrypoints(ctx: &ReportContext<'_>, package_json: &serde_json::Value) -> Vec<String> {
    let mut found: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for candidate in ENTRYPOINT_CANDIDATES {
        if ctx
            .inventory
            .files
            .iter()
            .any(|file| file.relative_path == *candidate)
        {
            found.insert((*candidate).to_string());
        }
    }

    for key in ["main", "module", "bin"] {
        match package_json.get(key) {
            Some(serde_json::Value::String(value)) => {
                found.insert(format!("package.json:{key} -> {value}"));
            }
            Some(serde_json::Value::Object(map)) => {
                let mut names: Vec<&String> = map.keys().collect();
                names.sort();
                for name in names {
                    if let Some(target) = map[name].as_str() {
                        found.insert(format!("package.json:{key}.{name} -> {target}"));
                    }
                }
            }
            _ => {}
        }
    }

    let mut result: Vec<String> = found.into_iter().collect();
    result.sort_by_key(|value| value.to_lowercase());
    result
}

fn detect_commands(
    ctx: &ReportContext<'_>,
    package_json: &serde_json::Value,
    package_managers: &[String],
) -> ProjectCommands {
    let mut commands = ProjectCommands::default();
    let node_manager = if package_managers.iter().any(|m| m == "pnpm") {
        "pnpm"
    } else if package_managers.iter().any(|m| m == "Yarn") {
        "yarn"
    } else {
        "npm"
    };

    let has_package_json = !package_json.is_null();
    if has_package_json {
        commands.install.push(format!("{node_manager} install"));
    }
    if let Some(scripts) = package_json.get("scripts").and_then(|v| v.as_object()) {
        let mut names: Vec<&String> = scripts.keys().collect();
        names.sort();
        for name in names {
            let command = format!("{node_manager} run {name}");
            let lower = name.to_lowercase();
            if lower.contains("dev") || lower.contains("start") {
                commands.dev.push(command);
            } else if lower.contains("build") {
                commands.build.push(command);
            } else if lower.contains("test") || lower.contains("check") || lower.contains("lint") {
                commands.test.push(command);
            } else {
                commands.run.push(command);
            }
        }
    }

    let root = &ctx.staging_root;
    if root_entry_exists(root, "requirements.txt") {
        commands.install.push("python -m venv .venv".to_string());
        commands
            .install
            .push(".venv\\Scripts\\python -m pip install -r requirements.txt".to_string());
    }
    if root_entry_exists(root, "pyproject.toml") {
        commands
            .install
            .push("python -m pip install -e .".to_string());
        commands.test.push("python -m pytest".to_string());
    }
    if root_entry_exists(root, "go.mod") {
        commands.install.push("go mod download".to_string());
        commands.build.push("go build ./...".to_string());
        commands.test.push("go test ./...".to_string());
    }
    if root_entry_exists(root, "Cargo.toml") {
        commands.build.push("cargo build".to_string());
        commands.test.push("cargo test".to_string());
    }
    if root_entry_exists(root, "docker-compose.yml")
        || root_entry_exists(root, "docker-compose.yaml")
        || root_entry_exists(root, "compose.yml")
        || root_entry_exists(root, "compose.yaml")
    {
        commands.run.push("docker compose up --build".to_string());
    } else if ctx.inventory.files.iter().any(|file| {
        file_name_of(&file.relative_path)
            .to_lowercase()
            .starts_with("dockerfile")
    }) {
        commands
            .build
            .push("docker build -t <image-name> .".to_string());
    }

    commands
}

fn detect_risk_level(ctx: &ReportContext<'_>) -> (String, Vec<String>) {
    let mut reasons = Vec::new();

    let env_files = ctx
        .inventory
        .files
        .iter()
        .filter(|file| {
            file_name_of(&file.relative_path)
                .to_lowercase()
                .starts_with(".env")
        })
        .count();
    if env_files > 0 {
        reasons.push(format!("{env_files} .env-like file(s) detected"));
    }

    let has_tests = ctx
        .inventory
        .files
        .iter()
        .any(|file| looks_like_test_path(&file.relative_path));
    if !has_tests {
        reasons.push("no obvious test files detected".to_string());
    }

    if !ctx.staging_root.join(".github").join("workflows").exists() {
        reasons.push("no GitHub Actions workflow detected".to_string());
    }

    let has_sensitive_name = ctx.inventory.files.iter().any(|file| {
        matches!(
            file_name_of(&file.relative_path).to_lowercase().as_str(),
            "id_rsa" | "id_ed25519" | "credentials.json"
        )
    });
    if has_sensitive_name {
        reasons.push("sensitive credential-like filename detected".to_string());
    }

    if reasons.len() >= 3 {
        ("high".to_string(), reasons)
    } else if !reasons.is_empty() {
        ("medium".to_string(), reasons)
    } else {
        (
            "low".to_string(),
            vec!["no obvious high-level project hygiene risks detected".to_string()],
        )
    }
}

pub fn build_project_profile(ctx: &ReportContext<'_>) -> ProjectProfile {
    let stack = crate::context::detect_stack(&ctx.staging_root, ctx.inventory);
    let package_json = safe_read_json(&ctx.staging_root.join("package.json"));
    let package_managers = crate::context::detect_package_managers(ctx.inventory);
    let configs = crate::reports::config::find_config_files(ctx);
    let (risk_level, risk_reasons) = detect_risk_level(ctx);

    // Legacy stores the bare file name here (`p.name`), not the relative path — it is
    // the one list in this artifact that is not path-shaped.
    let docker_compose_files: Vec<String> = configs
        .iter()
        .filter(|path| {
            matches!(
                file_name_of(path).to_lowercase().as_str(),
                "docker-compose.yml" | "docker-compose.yaml" | "compose.yml" | "compose.yaml"
            )
        })
        .map(|path| file_name_of(path).to_string())
        .collect();

    // Through the shared extractor: `PROJECT_PROFILE.json` is an artifact like any
    // other, and a bundle-wide sweep found an inline credential from a script reaching
    // it. The extractor hands back commands that are already redacted, so there is no
    // raw one to forget here either.
    let npm_scripts: BTreeMap<String, String> = crate::context::package_scripts(ctx)
        .into_iter()
        .map(|script| (script.name, script.command.as_str().to_string()))
        .collect();

    let project_name = ctx
        .staging_root
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();

    ProjectProfile {
        schema_version: PROJECT_PROFILE_SCHEMA_VERSION,
        generated_at: ctx.plan.generated_at.clone(),
        project_name,
        source_root: ctx.source_root.display().to_string(),
        copied_root: ctx.staging_root.display().to_string(),
        project_type: detect_project_type(ctx, &stack),
        detected_stack: stack.flattened(),
        stack_by_group: stack.clone(),
        package_managers,
        entrypoints: detect_entrypoints(ctx, &package_json),
        commands: detect_commands(ctx, &package_json, &stack.package_managers),
        docker_compose_files,
        npm_scripts,
        capabilities: ProjectCapabilities {
            has_git: ctx.source_root.join(".git").exists(),
            has_ci: ctx.staging_root.join(".github").join("workflows").exists(),
            has_tests: ctx
                .inventory
                .files
                .iter()
                .any(|file| looks_like_test_path(&file.relative_path)),
            has_docker: stack
                .infrastructure
                .iter()
                .any(|value| value == "Docker Compose")
                || ctx.inventory.files.iter().any(|file| {
                    file_name_of(&file.relative_path)
                        .to_lowercase()
                        .starts_with("dockerfile")
                }),
            has_env_files: ctx.inventory.files.iter().any(|file| {
                file_name_of(&file.relative_path)
                    .to_lowercase()
                    .starts_with(".env")
            }),
            has_readme: ctx.inventory.files.iter().any(|file| {
                file_name_of(&file.relative_path)
                    .to_lowercase()
                    .starts_with("readme")
            }),
            has_license: ctx.inventory.files.iter().any(|file| {
                file_name_of(&file.relative_path)
                    .to_lowercase()
                    .starts_with("license")
            }),
        },
        counts: ProjectCounts {
            files: ctx.inventory.files.len(),
            folders: ctx.inventory.total_dirs,
            total_size_bytes: ctx.inventory.total_size,
        },
        risk_level,
        risk_reasons,
        important_config_files: configs
            .into_iter()
            .take(100)
            .map(|path| rel_display(&path))
            .collect(),
    }
}

/// Legacy's report job #0. The catalog entry matters as much as the file: legacy
/// derives `REPORT_PLUGINS.json` from the job list, so a profile written outside the
/// catalog (as this crate did until 2026-07-25) silently dropped both
/// `reports/insights/00_project_profile.json` and its catalog entry. The top-level
/// `PROJECT_PROFILE.json` is a copy of this file in legacy (`shutil.copyfile`), which
/// `codepack-engine` reproduces after the catalog has run.
pub const JOB: crate::plugin::ReportJob = crate::plugin::ReportJob {
    filename: "00_project_profile.json",
    profiles: &["quick", "full", "ai_review", "security", "minimal"],
    description: "Machine-readable project profile: stack, entrypoints, commands, risk level.",
    run: write_project_profile_json,
};

pub fn write_project_profile_json(
    ctx: &ReportContext<'_>,
    output_file: &Path,
) -> Result<(), ReportError> {
    let profile = build_project_profile(ctx);
    let rendered = serde_json::to_string_pretty(&profile)
        .map_err(|source| ReportError::Serialize { source })?;
    std::fs::write(output_file, rendered).map_err(|source| ReportError::Write {
        path: output_file.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use codepack_core::CancellationToken;
    use codepack_core::config::Config;
    use codepack_scanner::{ExportIgnoreRules, ScanOptions, build_export_plan};

    #[test]
    fn writes_expected_top_level_shape() {
        let source = tempfile::tempdir().unwrap();
        std::fs::write(source.path().join("Cargo.toml"), "[package]\nname=\"x\"\n").unwrap();
        std::fs::write(source.path().join("README.md"), "# hi\n").unwrap();

        let plan = build_export_plan(
            source.path(),
            &ScanOptions::default(),
            &ExportIgnoreRules::default(),
            &codepack_scanner::no_safety_classification,
            &CancellationToken::new(),
        )
        .unwrap();
        let inventory = crate::context::Inventory::from_plan(&plan);
        let config = Config::default();
        let cancel = CancellationToken::new();
        let ctx = ReportContext {
            source_root: source.path().to_path_buf(),
            staging_root: source.path().to_path_buf(),
            inventory: &inventory,
            plan: &plan,
            scan: None,
            diff: None,
            config: &config,
            cancel: &cancel,
            profile: "full",
        };

        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join("PROJECT_PROFILE.json");
        write_project_profile_json(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["schema_version"], 1);
        assert!(parsed.get("project_type").is_some());
        assert!(parsed.get("detected_stack").is_some());
        assert!(parsed.get("stack_by_group").is_some());
        assert!(parsed.get("commands").is_some());
        assert!(parsed.get("capabilities").is_some());
        assert!(parsed.get("counts").is_some());
        assert!(parsed.get("risk_level").is_some());
        assert!(parsed.get("important_config_files").is_some());
        // "Cargo" comes from the `package_managers` group, which legacy's own
        // `_flatten_stack` includes (it iterates every group of the dict). This
        // expectation previously asserted `["Rust"]`, encoding the bug the golden
        // reference disproved: real legacy output for a pip project lists
        // `["pip/requirements.txt", "Python"]`.
        assert_eq!(
            parsed["detected_stack"],
            serde_json::json!(["Cargo", "Rust"])
        );
    }
}
