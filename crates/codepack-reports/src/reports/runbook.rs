//! `13_runbook.md`, ported from legacy `reports/insights/runbook.py::write_runbook_report`:
//! heuristic setup/run/test/Docker instructions derived from the manifests already
//! present in [`crate::context::Inventory`].

use std::path::Path;

use crate::context::{ReportContext, package_scripts, root_entry_exists};
use crate::error::ReportError;
use crate::paths::file_name_of;
use crate::plugin::ReportJob;
use crate::profile;
use crate::text::safe_read_json;

pub const JOB: ReportJob = ReportJob {
    filename: "13_runbook.md",
    profiles: profile::RUNBOOK_MD,
    description: "Generated setup/run/test/Docker instructions.",
    run: write_runbook_report,
};

fn node_manager(ctx: &ReportContext<'_>) -> &'static str {
    if root_entry_exists(&ctx.staging_root, "pnpm-lock.yaml") {
        "pnpm"
    } else if root_entry_exists(&ctx.staging_root, "yarn.lock") {
        "yarn"
    } else if root_entry_exists(&ctx.staging_root, "bun.lockb")
        || root_entry_exists(&ctx.staging_root, "bun.lock")
    {
        "bun"
    } else {
        "npm"
    }
}

fn compose_files(ctx: &ReportContext<'_>) -> Vec<&'static str> {
    [
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    ]
    .into_iter()
    .filter(|name| root_entry_exists(&ctx.staging_root, name))
    .collect()
}

fn env_examples<'a>(ctx: &ReportContext<'a>) -> Vec<&'a str> {
    let mut names: Vec<&str> = ctx
        .inventory
        .files
        .iter()
        .filter(|file| {
            !file.relative_path.contains('\\')
                && file_name_of(&file.relative_path)
                    .to_lowercase()
                    .starts_with(".env")
        })
        .map(|file| file.relative_path.as_str())
        .collect();
    names.sort_by_key(|name| name.to_lowercase());
    names
}

fn write_runbook_report(ctx: &ReportContext<'_>, output_file: &Path) -> Result<(), ReportError> {
    let package_json = safe_read_json(&ctx.staging_root.join("package.json"));
    let redacted_scripts = package_scripts(ctx);
    let managers = crate::context::detect_package_managers(ctx.inventory);
    let manager = node_manager(ctx);
    let composes = compose_files(ctx);
    let envs = env_examples(ctx);

    let project_name = ctx
        .staging_root
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();

    let mut out = String::new();
    out.push_str(&format!("# Runbook: {project_name}\n\n"));
    out.push_str(&format!("Generated: {}\n\n", ctx.plan.generated_at));
    out.push_str(
        "This runbook is generated heuristically from common project files. Verify commands \
before using them in production.\n\n",
    );

    out.push_str("## Detected package / build systems\n\n");
    if managers.is_empty() {
        out.push_str("- No common package manager detected.\n");
    } else {
        for entry in &managers {
            out.push_str(&format!("- {entry}\n"));
        }
    }

    out.push_str("\n## Setup commands\n\n");
    let mut commands: Vec<String> = Vec::new();
    if !package_json.is_null() {
        commands.push(format!("{manager} install"));
    }
    if root_entry_exists(&ctx.staging_root, "requirements.txt") {
        commands.push("python -m venv .venv".to_string());
        commands.push(".venv\\Scripts\\python -m pip install -r requirements.txt".to_string());
    }
    if root_entry_exists(&ctx.staging_root, "pyproject.toml") {
        commands.push("python -m pip install -e .".to_string());
    }
    if root_entry_exists(&ctx.staging_root, "go.mod") {
        commands.push("go mod download".to_string());
    }
    if root_entry_exists(&ctx.staging_root, "Cargo.toml") {
        commands.push("cargo fetch".to_string());
    }
    if commands.is_empty() {
        out.push_str("No setup commands detected.\n\n");
    } else {
        for command in &commands {
            out.push_str(&format!("```powershell\n{command}\n```\n\n"));
        }
    }

    out.push_str("## Development / run commands\n\n");
    if !redacted_scripts.is_empty() {
        for script in &redacted_scripts {
            let (name, command) = (&script.name, &script.command);
            out.push_str(&format!("- `{manager} run {name}` → `{command}`\n"));
        }
    } else if root_entry_exists(&ctx.staging_root, "main.py") {
        out.push_str("```powershell\npython main.py\n```\n");
    } else {
        out.push_str("No obvious development command detected.\n");
    }

    out.push_str("\n## Test / check commands\n\n");
    let mut test_commands: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    {
        for name in redacted_scripts.iter().map(|script| &script.name) {
            let lower = name.to_lowercase();
            if lower.contains("test")
                || lower.contains("check")
                || lower.contains("lint")
                || lower.contains("type")
            {
                test_commands.insert(format!("{manager} run {name}"));
            }
        }
    }
    if root_entry_exists(&ctx.staging_root, "pyproject.toml")
        || root_entry_exists(&ctx.staging_root, "pytest.ini")
    {
        test_commands.insert("python -m pytest".to_string());
    }
    if root_entry_exists(&ctx.staging_root, "go.mod") {
        test_commands.insert("go test ./...".to_string());
    }
    if root_entry_exists(&ctx.staging_root, "Cargo.toml") {
        test_commands.insert("cargo test".to_string());
    }
    if test_commands.is_empty() {
        out.push_str("- No obvious test/check command detected.\n");
    } else {
        for command in &test_commands {
            out.push_str(&format!("- `{command}`\n"));
        }
    }

    out.push_str("\n## Docker commands\n\n");
    if !composes.is_empty() {
        for path in &composes {
            out.push_str(&format!("- Compose file: `{path}`\n"));
        }
        out.push_str("\n```powershell\ndocker compose up --build\n```\n");
    } else if ctx.inventory.files.iter().any(|file| {
        !file.relative_path.contains('\\')
            && file_name_of(&file.relative_path)
                .to_lowercase()
                .starts_with("dockerfile")
    }) {
        out.push_str("```powershell\ndocker build -t <image-name> .\n```\n");
    } else {
        out.push_str("No Dockerfile/docker-compose file detected.\n");
    }

    out.push_str("\n## Environment/configuration hints\n\n");
    if envs.is_empty() {
        out.push_str("- No .env-like files detected.\n");
    } else {
        for path in &envs {
            out.push_str(&format!("- `{path}`\n"));
        }
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
    fn writes_node_setup_and_test_commands() {
        let fixture = Fixture::new(|root| {
            std::fs::write(
                root.join("package.json"),
                r#"{"scripts": {"build": "vite build", "test": "vitest run"}}"#,
            )
            .unwrap();
            std::fs::write(root.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\n").unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_runbook_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.starts_with("# Runbook:"));
        assert!(content.contains("```powershell\npnpm install\n```"));
        assert!(content.contains("`pnpm run test` → `vitest run`"));
        assert!(content.contains("- `pnpm run test`"));
    }

    #[test]
    fn falls_back_to_no_command_detected_messages_when_nothing_is_present() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("README.md"), "# hi\n").unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_runbook_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("No setup commands detected."));
        assert!(content.contains("No obvious development command detected."));
        assert!(content.contains("No obvious test/check command detected."));
        assert!(content.contains("No Dockerfile/docker-compose file detected."));
        assert!(content.contains("No .env-like files detected."));
    }

    #[test]
    fn detects_docker_compose_and_env_files() {
        let fixture = Fixture::new(|root| {
            std::fs::write(
                root.join("docker-compose.yml"),
                "services:\n  app:\n    image: demo\n",
            )
            .unwrap();
            std::fs::write(root.join(".env.example"), "KEY=value\n").unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_runbook_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("Compose file: `docker-compose.yml`"));
        assert!(content.contains("docker compose up --build"));
        assert!(content.contains(".env.example"));
    }
}
