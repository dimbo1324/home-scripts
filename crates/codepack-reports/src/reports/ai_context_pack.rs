//! `12_ai_context_pack.md`, ported from legacy
//! `reports/insights/ai_context.py::write_ai_context_pack`: a single, dense Markdown
//! summary meant to be pasted into an AI assistant together with the exported
//! project.
//!
//! The "Suggested review order" section's file references are adjusted from legacy's
//! `reports/insights/`-nested paths (`00_project_profile.json`, ...) to this crate's
//! actual flat layout (`PROJECT_PROFILE.json`, ...) established by earlier Group G/A
//! passes — a layout-consequence content fix, not a scope drift.

use std::path::Path;

use codepack_tokens::format_bytes;

use crate::context::{ReportContext, package_scripts};
use crate::error::ReportError;
use crate::plugin::ReportJob;
use crate::profile;
use crate::reports::config::find_config_files;

pub const JOB: ReportJob = ReportJob {
    filename: "12_ai_context_pack.md",
    profiles: profile::AI_CONTEXT_PACK_MD,
    description: "Drop-in summary for pasting into an AI assistant together with the export.",
    run: write_ai_context_pack,
};

fn write_ai_context_pack(ctx: &ReportContext<'_>, output_file: &Path) -> Result<(), ReportError> {
    let inventory = ctx.inventory;
    let stack = crate::context::detect_stack(&ctx.staging_root, inventory);
    let configs = find_config_files(ctx);
    let project_name = ctx
        .staging_root
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();

    let mut largest: Vec<&crate::context::InventoryFile> = inventory.files.iter().collect();
    largest.sort_by_key(|file| std::cmp::Reverse(file.size));

    let mut out = String::new();
    out.push_str(&format!("# AI Context Pack: {project_name}\n\n"));
    out.push_str(&format!("Generated: {}\n\n", ctx.plan.generated_at));
    out.push_str(
        "This file is intended to be pasted into an AI assistant together with the exported \
project when quick project understanding is needed.\n\n",
    );

    out.push_str("## Project summary\n\n");
    out.push_str(&format!(
        "- Source root: `{}`\n",
        ctx.disclosed_source_root()
    ));
    out.push_str(&format!(
        "- Copied root: `{}`\n",
        ctx.disclosed_staging_root()
    ));
    out.push_str(&format!("- Files: {}\n", inventory.files.len()));
    out.push_str(&format!("- Folders: {}\n", inventory.total_dirs));
    out.push_str(&format!(
        "- Copied size: {}\n",
        format_bytes(inventory.total_size)
    ));

    out.push_str("\n## Detected stack\n\n");
    for (group, values) in [
        ("frontend", &stack.frontend),
        ("backend", &stack.backend),
        ("tools", &stack.tools),
        ("testing", &stack.testing),
        ("styling", &stack.styling),
        ("infrastructure", &stack.infrastructure),
        ("package_managers", &stack.package_managers),
    ] {
        let joined = if values.is_empty() {
            "not detected".to_string()
        } else {
            values.join(", ")
        };
        out.push_str(&format!("- **{group}**: {joined}\n"));
    }

    out.push_str("\n## Main languages\n\n");
    if inventory.by_language.is_empty() {
        out.push_str("- No known language extensions detected.\n");
    } else {
        for stat in inventory.by_language.iter().take(15) {
            out.push_str(&format!("- {}: {} files\n", stat.language, stat.count));
        }
    }

    out.push_str("\n## Scripts / commands\n\n");
    // `pnpm` when the lockfile says so, `npm` otherwise — the same rule the other
    // reports use to name the command a reader would actually type.
    let manager = if crate::context::root_entry_exists(&ctx.staging_root, "pnpm-lock.yaml") {
        "pnpm"
    } else {
        "npm"
    };
    let redacted_scripts = package_scripts(ctx);
    if redacted_scripts.is_empty() {
        out.push_str("- No package.json scripts detected.\n");
    } else {
        for script in &redacted_scripts {
            let (name, command) = (&script.name, &script.command);
            out.push_str(&format!("- `{manager} run {name}` — `{command}`\n"));
        }
    }

    out.push_str("\n## Important configuration files\n\n");
    if configs.is_empty() {
        out.push_str("- No common configuration files detected.\n");
    } else {
        for path in configs.iter().take(80) {
            out.push_str(&format!("- `{path}`\n"));
        }
    }

    out.push_str("\n## Largest files\n\n");
    for file in largest.iter().take(10) {
        out.push_str(&format!(
            "- `{}` — {}\n",
            file.relative_path,
            format_bytes(file.size)
        ));
    }

    out.push_str("\n## Suggested review order\n\n");
    for suggestion in [
        "Read `PROJECT_PROFILE.json` and `01_summary.txt` first.",
        "Use `13_runbook.md` to understand setup, run, and test commands.",
        "Use `15_architecture_report.md` and `16_key_files_report.md` before editing code.",
        "Use `14_dependency_graph.md` / `.mmd` to understand internal imports.",
        "Review `06_security_scan.txt` before sharing the export.",
        "Use `17_code_quality_report.md` and `23_refactoring_opportunities.md` to plan refactors.",
        "Use the `AI_CONTEXT/` folder for a multi-file ChatGPT/Codex handoff.",
    ] {
        out.push_str(&format!("- {suggestion}\n"));
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
    fn writes_expected_sections_and_review_order() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("main.py"), "print('hi')\n").unwrap();
            std::fs::write(
                root.join("package.json"),
                r#"{"dependencies": {"react": "18.0.0"}, "scripts": {"build": "vite build"}}"#,
            )
            .unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_ai_context_pack(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.starts_with("# AI Context Pack:"));
        assert!(content.contains("## Detected stack"));
        assert!(content.contains("- **frontend**: React"));
        assert!(content.contains("`npm run build` — `vite build`"));
        assert!(content.contains("## Suggested review order"));
        assert!(content.contains("Read `PROJECT_PROFILE.json` and `01_summary.txt` first."));
        assert!(content.contains("Use the `AI_CONTEXT/` folder"));
    }

    #[test]
    fn reports_no_scripts_and_no_configs_when_absent() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("main.py"), "print('hi')\n").unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_ai_context_pack(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("No package.json scripts detected."));
        assert!(content.contains("No common configuration files detected."));
    }
}
