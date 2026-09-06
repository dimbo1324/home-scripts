//! `04_scripts.txt`, ported from legacy
//! `reports/insights/scripts.py::write_scripts_report`. Every line quoting a
//! `package.json` script command or a raw Makefile target name is routed through
//! [`crate::context::redact_line`] before being written (invariant I3): a script
//! command in particular can embed an inline credential (e.g.
//! `SOME_TOKEN=abc node build.js`), unlike the Group A reports this crate already
//! shipped, which only ever quote paths or computed statistics.
//!
//! The Dockerfile/Compose presence checks here are deliberately **root-level only**,
//! matching legacy's own `copied_root.glob("Dockerfile*")` / `.exists()` calls (not a
//! recursive search) — unlike `10_docker.txt`, which lists every Dockerfile/Compose
//! file project-wide via legacy's `iter_project_files`, and unlike `01_summary.txt`'s
//! broader any-depth "Docker detected" flag. These are genuinely different behaviors
//! per legacy report, not an inconsistency to reconcile.

use std::path::Path;

use regex::Regex;

use crate::context::{ReportContext, package_scripts, redact_line, root_entry_exists};
use crate::error::ReportError;
use crate::paths::path_depth;
use crate::plugin::ReportJob;
use crate::profile;
use crate::reports::layout::section_rule;
use crate::text::read_text_unredacted;

pub const JOB: ReportJob = ReportJob {
    filename: "04_scripts.txt",
    profiles: profile::SCRIPTS_TXT,
    description: "npm/pnpm scripts, Makefile targets, Docker convenience commands.",
    run: write_scripts_report,
};

const MAKEFILE_TARGET_LIMIT: usize = 200;

fn makefile_target_pattern() -> Regex {
    // Legacy `re.match(r"^([A-Za-z0-9_.-]+):(?:\s|$)", line)`.
    Regex::new(r"^([A-Za-z0-9_.-]+):(?:\s|$)").expect("fixed, compile-time-verified literal")
}

fn makefile_targets(text: &str) -> Vec<String> {
    let pattern = makefile_target_pattern();
    let mut targets: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for line in text.lines() {
        if line.starts_with('\t') {
            continue;
        }
        if let Some(captures) = pattern.captures(line)
            && let Some(name) = captures.get(1)
        {
            targets.insert(name.as_str().to_string());
        }
    }
    targets.into_iter().collect()
}

fn is_root_dockerfile(relative_path: &str) -> bool {
    path_depth(relative_path) == 1 && relative_path.to_lowercase().starts_with("dockerfile")
}

fn write_scripts_report(ctx: &ReportContext<'_>, output_file: &Path) -> Result<(), ReportError> {
    let mut out = String::new();
    out.push_str("=== Scripts and Common Commands Report ===\n");
    out.push_str(&format!("Generated: {}\n", ctx.plan.generated_at));
    out.push_str(&section_rule('='));
    out.push_str("\n\n");

    out.push_str("--- package.json scripts ---\n");
    // Through the shared extractor like every other report. The `redact_line` call that
    // used to sit here is gone: the command arrives redacted, and there is no longer a
    // raw one to forget.
    let redacted_scripts = package_scripts(ctx);
    if redacted_scripts.is_empty() {
        out.push_str("No package.json scripts detected.\n");
    } else {
        let manager = if root_entry_exists(&ctx.staging_root, "pnpm-lock.yaml") {
            "pnpm"
        } else {
            "npm"
        };
        for script in &redacted_scripts {
            let (name, command) = (&script.name, &script.command);
            out.push_str(&format!("{manager} run {name:<24} # {command}\n"));
        }
    }

    out.push_str("\n--- Makefile targets ---\n");
    let makefile_name = ["Makefile", "makefile"]
        .into_iter()
        .find(|name| root_entry_exists(&ctx.staging_root, name));
    match makefile_name {
        Some(name) => match read_text_unredacted(&ctx.staging_root.join(name), None) {
            Some(text) => {
                let targets = makefile_targets(&text);
                if targets.is_empty() {
                    out.push_str("No Makefile targets detected.\n");
                }
                for target in targets.iter().take(MAKEFILE_TARGET_LIMIT) {
                    out.push_str(&redact_line(&format!("make {target}\n")));
                }
            }
            None => out.push_str("Could not read Makefile.\n"),
        },
        None => out.push_str("No Makefile detected.\n"),
    }

    out.push_str("\n--- Docker convenience commands ---\n");
    let has_compose = root_entry_exists(&ctx.staging_root, "docker-compose.yml")
        || root_entry_exists(&ctx.staging_root, "docker-compose.yaml");
    let has_dockerfile = ctx
        .inventory
        .files
        .iter()
        .any(|file| is_root_dockerfile(&file.relative_path));
    if has_compose {
        out.push_str("docker compose up --build\n");
        out.push_str("docker compose down\n");
        out.push_str("docker compose logs -f\n");
    } else if has_dockerfile {
        out.push_str(
            "Dockerfile detected. Add a project-specific docker build command if needed.\n",
        );
    } else {
        out.push_str("No Docker/Docker Compose files detected.\n");
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
    fn makefile_targets_ignores_recipe_lines_and_dedupes() {
        let text = "build: deps\n\tcargo build\ntest:\n\tcargo test\nbuild: again\n";
        let targets = makefile_targets(text);
        assert_eq!(targets, vec!["build".to_string(), "test".to_string()]);
    }

    #[test]
    fn makefile_targets_returns_empty_for_garbage_without_panicking() {
        let targets = makefile_targets("not a makefile at all\n???\n\t\tmess\n");
        assert!(targets.is_empty());
    }

    #[test]
    fn writes_npm_scripts_makefile_targets_and_docker_commands() {
        let fixture = Fixture::new(|root| {
            std::fs::write(
                root.join("package.json"),
                r#"{"scripts": {"build": "vite build", "TOKEN=abc test": "vitest"}}"#,
            )
            .unwrap();
            std::fs::write(root.join("Makefile"), "build:\n\techo hi\n").unwrap();
            std::fs::write(root.join("docker-compose.yml"), "services:\n  web:\n").unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_scripts_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("npm run build"));
        assert!(content.contains("make build"));
        assert!(content.contains("docker compose up --build"));
    }

    #[test]
    fn reports_absence_of_scripts_makefile_and_docker() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("main.py"), "x = 1\n").unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_scripts_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("No package.json scripts detected."));
        assert!(content.contains("No Makefile detected."));
        assert!(content.contains("No Docker/Docker Compose files detected."));
    }
}
