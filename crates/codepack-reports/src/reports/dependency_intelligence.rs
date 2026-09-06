//! `26_dependency_intelligence.md`, ported from legacy
//! `reports/insights/dependency_intelligence.py::write_dependency_intelligence_report`.
//! Extends `03_dependencies.txt` with lockfile/hygiene signals; reuses
//! [`crate::reports::dependencies::parse_go_mod`] exactly as legacy's own module does
//! (its only cross-module import).
//!
//! Every line quoting a dependency name/version or a `go.mod` requirement is routed
//! through [`crate::context::redact_line`] before being written — same invariant-I3
//! reasoning as `03_dependencies.txt`.

use std::path::Path;

use crate::context::{ReportContext, redact_line, root_entry_exists};
use crate::error::ReportError;
use crate::plugin::ReportJob;
use crate::profile;
use crate::reports::dependencies::parse_go_mod;
use crate::text::{read_text_unredacted, safe_read_json};

pub const JOB: ReportJob = ReportJob {
    filename: "26_dependency_intelligence.md",
    profiles: profile::DEPENDENCY_INTELLIGENCE_MD,
    description: "Package managers, lock files, and dependency hygiene signals.",
    run: write_dependency_intelligence_report,
};

const GO_REQUIREMENT_LIMIT: usize = 100;
const JS_LOCKFILES: &[&str] = &[
    "pnpm-lock.yaml",
    "package-lock.json",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
];
const PYTHON_MANIFEST_NAMES: &[&str] = &[
    "pyproject.toml",
    "requirements.txt",
    "requirements-dev.txt",
    "poetry.lock",
    "Pipfile",
    "Pipfile.lock",
    "uv.lock",
];

fn section(out: &mut String, title: &str) {
    out.push_str(&format!("\n## {title}\n\n"));
}

fn write_dependency_intelligence_report(
    ctx: &ReportContext<'_>,
    output_file: &Path,
) -> Result<(), ReportError> {
    let package_json_value = safe_read_json(&ctx.staging_root.join("package.json"));
    let package_json = package_json_value.as_object();
    let managers = crate::context::detect_package_managers(ctx.inventory);

    let mut out = String::new();
    out.push_str("# Dependency Intelligence\n");
    out.push_str(&format!("\nGenerated: {}\n", ctx.plan.generated_at));

    section(&mut out, "Detected package managers");
    if managers.is_empty() {
        out.push_str("No known package manager files detected.\n");
    } else {
        for manager in &managers {
            out.push_str(&format!("- {manager}\n"));
        }
    }

    section(&mut out, "JavaScript / TypeScript");
    match package_json {
        Some(package_json) => {
            out.push_str("package.json detected.\n\n");
            for key in [
                "dependencies",
                "devDependencies",
                "peerDependencies",
                "optionalDependencies",
            ] {
                out.push_str(&format!("### {key}\n\n"));
                match package_json.get(key).and_then(|v| v.as_object()) {
                    Some(deps) if !deps.is_empty() => {
                        let mut names: Vec<&String> = deps.keys().collect();
                        names.sort_by_key(|name| name.to_lowercase());
                        for name in names {
                            let version = deps[name].as_str().unwrap_or_default();
                            out.push_str(&redact_line(&format!("- `{name}`: `{version}`\n")));
                        }
                    }
                    _ => out.push_str("None.\n"),
                }
                out.push('\n');
            }

            let lockfiles: Vec<&str> = JS_LOCKFILES
                .iter()
                .copied()
                .filter(|name| root_entry_exists(&ctx.staging_root, name))
                .collect();
            out.push_str(&format!(
                "Lockfile status: {}\n",
                if lockfiles.is_empty() {
                    "missing — add one for reproducible installs".to_string()
                } else {
                    lockfiles.join(", ")
                }
            ));
        }
        None => out.push_str("package.json not detected.\n"),
    }

    section(&mut out, "Python");
    let py_files: Vec<&str> = PYTHON_MANIFEST_NAMES
        .iter()
        .copied()
        .filter(|name| root_entry_exists(&ctx.staging_root, name))
        .collect();
    if py_files.is_empty() {
        out.push_str("No Python dependency metadata detected.\n");
    } else {
        for name in py_files {
            out.push_str(&format!("- `{name}`\n"));
        }
    }

    section(&mut out, "Go");
    if root_entry_exists(&ctx.staging_root, "go.mod") {
        let (module, requirements) = read_text_unredacted(&ctx.staging_root.join("go.mod"), None)
            .map(|text| parse_go_mod(&text))
            .unwrap_or_default();
        out.push_str(&format!(
            "module: `{}`\n\n",
            if module.is_empty() {
                "not detected".to_string()
            } else {
                module
            }
        ));
        for requirement in requirements.iter().take(GO_REQUIREMENT_LIMIT) {
            out.push_str(&redact_line(&format!("- `{requirement}`\n")));
        }
        if requirements.len() > GO_REQUIREMENT_LIMIT {
            out.push_str(&format!(
                "- ... and {} more\n",
                requirements.len() - GO_REQUIREMENT_LIMIT
            ));
        }
    } else {
        out.push_str("go.mod not detected.\n");
    }

    section(&mut out, "Hygiene checks");
    let has_js_lockfile = JS_LOCKFILES
        .iter()
        .any(|name| root_entry_exists(&ctx.staging_root, name));
    if package_json.is_some() && !has_js_lockfile {
        out.push_str("- Add a JS lockfile for reproducibility.\n");
    }
    if root_entry_exists(&ctx.staging_root, "requirements.txt")
        && !root_entry_exists(&ctx.staging_root, "pyproject.toml")
    {
        out.push_str(
            "- Consider adding `pyproject.toml` for tool configuration and packaging metadata.\n",
        );
    }
    if managers.is_empty() {
        out.push_str(
            "- No dependency action required unless this project is expected to be installable.\n",
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
    fn covers_node_and_go_stacks_and_flags_missing_lockfile() {
        let fixture = Fixture::new(|root| {
            std::fs::write(
                root.join("package.json"),
                r#"{"dependencies": {"react": "18.0.0"}}"#,
            )
            .unwrap();
            std::fs::write(
                root.join("go.mod"),
                "module example.com/app\n\nrequire github.com/foo/bar v1.0.0\n",
            )
            .unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_dependency_intelligence_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.starts_with("# Dependency Intelligence"));
        assert!(content.contains("`react`"));
        assert!(content.contains("module: `example.com/app`"));
        assert!(content.contains("github.com/foo/bar v1.0.0"));
        assert!(content.contains("Add a JS lockfile for reproducibility."));
    }

    #[test]
    fn reports_no_data_detected_when_project_has_no_manifests() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("main.rs"), "fn main() {}\n").unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_dependency_intelligence_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("package.json not detected."));
        assert!(content.contains("No Python dependency metadata detected."));
        assert!(content.contains("go.mod not detected."));
        assert!(content.contains("No known package manager files detected."));
    }
}
