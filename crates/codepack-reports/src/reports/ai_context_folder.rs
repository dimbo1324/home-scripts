//! `AI_CONTEXT/`, ported from legacy
//! `reports/insights/ai_context_folder.py::write_ai_context_folder`: eleven small
//! files, each covering one aspect of the project, so an AI assistant can be handed
//! only the relevant context file rather than the whole export.
//!
//! `09_PROMPT_FOR_CODEX.md` always uses the **default** prompt goals — legacy calls
//! `build_custom_prompt(copied_root.name)` here with no `goals` argument, unlike
//! `AI_PROMPTS/CUSTOM_PROMPT.md` (this crate's [`super::ai_prompts`]), which does pass
//! `Config.prompt_goals` through. That asymmetry is legacy's own behavior, reproduced
//! here rather than "fixed" into consistency.

use std::path::Path;

use codepack_tokens::format_bytes;

use crate::context::{ReportContext, package_scripts};
use crate::error::ReportError;
use crate::plugin::ReportJob;
use crate::profile;
use crate::project_profile::build_project_profile;
use crate::reports::ai_prompts::build_custom_prompt;
use crate::reports::config::find_config_files;

pub const JOB: ReportJob = ReportJob {
    filename: "AI_CONTEXT",
    profiles: profile::AI_CONTEXT_FOLDER,
    description: "Multi-file AI context folder for a ChatGPT/Codex-style handoff.",
    run: write_ai_context_folder,
};

fn write_file(dir: &Path, name: &str, content: &str) -> Result<(), ReportError> {
    let path = dir.join(name);
    std::fs::write(&path, content).map_err(|source| ReportError::Write { path, source })
}

fn write_ai_context_folder(ctx: &ReportContext<'_>, output_dir: &Path) -> Result<(), ReportError> {
    std::fs::create_dir_all(output_dir).map_err(|source| ReportError::Write {
        path: output_dir.to_path_buf(),
        source,
    })?;

    let profile = build_project_profile(ctx);
    let configs = find_config_files(ctx);
    let redacted_scripts = package_scripts(ctx);

    let mut sizes: Vec<&crate::context::InventoryFile> = ctx.inventory.files.iter().collect();
    sizes.sort_by_key(|file| std::cmp::Reverse(file.size));

    let project_name = ctx
        .staging_root
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();

    let mut overview = String::new();
    overview.push_str(&format!("# Project Overview: {project_name}\n\n"));
    overview.push_str(&format!("Generated: {}\n\n", ctx.plan.generated_at));
    overview.push_str(&format!("- Project type: **{}**\n", profile.project_type));
    overview.push_str(&format!("- Risk level: **{}**\n", profile.risk_level));
    overview.push_str(&format!("- Files: **{}**\n", profile.counts.files));
    overview.push_str(&format!("- Folders: **{}**\n", profile.counts.folders));
    overview.push_str(&format!(
        "- Size: **{}**\n\n",
        format_bytes(profile.counts.total_size_bytes)
    ));
    overview.push_str("## Detected stack\n\n");
    if profile.detected_stack.is_empty() {
        overview.push_str("- not detected\n");
    } else {
        for item in &profile.detected_stack {
            overview.push_str(&format!("- {item}\n"));
        }
    }
    overview.push_str("\n## Risk reasons\n\n");
    for reason in &profile.risk_reasons {
        overview.push_str(&format!("- {reason}\n"));
    }
    write_file(output_dir, "00_PROJECT_OVERVIEW.md", &overview)?;

    write_file(
        output_dir,
        "01_ARCHITECTURE.md",
        "# Architecture Reading Guide\n\nRead these generated reports first:\n\n\
1. `../01_summary.txt`\n\
2. `../15_architecture_report.md`\n\
3. `../16_key_files_report.md`\n\
4. `../14_dependency_graph.md`\n\
5. `../23_refactoring_opportunities.md`\n",
    )?;

    let mut tree = String::from("# File Tree Snapshot\n\n");
    let mut sorted_paths: Vec<&str> = ctx
        .inventory
        .files
        .iter()
        .map(|file| file.relative_path.as_str())
        .collect();
    sorted_paths.sort_by_key(|path| path.to_lowercase());
    for path in sorted_paths.iter().take(1000) {
        tree.push_str(&format!("- `{path}`\n"));
    }
    write_file(output_dir, "02_FILE_TREE.md", &tree)?;

    let mut entrypoints = String::from("# Entrypoints\n\n");
    if profile.entrypoints.is_empty() {
        entrypoints.push_str("- No obvious entrypoint detected.\n");
    } else {
        for entry in &profile.entrypoints {
            entrypoints.push_str(&format!("- `{entry}`\n"));
        }
    }
    write_file(output_dir, "03_ENTRYPOINTS.md", &entrypoints)?;

    let mut key_files = String::from("# Key Files Reading Order\n\n");
    for file in sizes.iter().take(30) {
        key_files.push_str(&format!(
            "- `{}` — {}\n",
            file.relative_path,
            format_bytes(file.size)
        ));
    }
    write_file(output_dir, "04_KEY_FILES.md", &key_files)?;

    let mut dependencies = String::from("# Dependencies / Commands\n\n## Commands\n\n");
    for (group, commands) in [
        ("install", &profile.commands.install),
        ("dev", &profile.commands.dev),
        ("build", &profile.commands.build),
        ("test", &profile.commands.test),
        ("run", &profile.commands.run),
    ] {
        dependencies.push_str(&format!("### {group}\n"));
        for command in commands {
            dependencies.push_str(&format!("- `{command}`\n"));
        }
        dependencies.push('\n');
    }
    dependencies.push_str("## Config files\n\n");
    for path in configs.iter().take(100) {
        dependencies.push_str(&format!("- `{path}`\n"));
    }
    write_file(output_dir, "05_DEPENDENCIES.md", &dependencies)?;

    write_file(
        output_dir,
        "06_SECURITY_NOTES.md",
        "# Security Notes\n\nReview `../06_security_scan.txt` before sharing this export. \
Generated scanners are heuristic, so manually check `.env`, credentials, tokens, private \
keys, and Git history.\n",
    )?;

    write_file(
        output_dir,
        "07_TODO_FIXME.md",
        "# TODO / FIXME\n\nSee `../07_todo_fixme.txt` for extracted technical-debt markers.\n",
    )?;

    write_file(
        output_dir,
        "08_REFACTORING_TARGETS.md",
        "# Refactoring Targets\n\nSee `../23_refactoring_opportunities.md` and \
`../17_code_quality_report.md`.\n",
    )?;

    write_file(
        output_dir,
        "09_PROMPT_FOR_CODEX.md",
        &build_custom_prompt(&project_name, &[]),
    )?;

    let mut scripts_out = String::from("# Scripts\n\n");
    if redacted_scripts.is_empty() {
        scripts_out.push_str("- No package.json scripts detected.\n");
    } else {
        for script in &redacted_scripts {
            let (name, command) = (&script.name, &script.command);
            scripts_out.push_str(&format!("- `{name}` → `{command}`\n"));
        }
    }
    write_file(output_dir, "10_SCRIPTS.md", &scripts_out)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::Fixture;

    const EXPECTED_FILES: &[&str] = &[
        "00_PROJECT_OVERVIEW.md",
        "01_ARCHITECTURE.md",
        "02_FILE_TREE.md",
        "03_ENTRYPOINTS.md",
        "04_KEY_FILES.md",
        "05_DEPENDENCIES.md",
        "06_SECURITY_NOTES.md",
        "07_TODO_FIXME.md",
        "08_REFACTORING_TARGETS.md",
        "09_PROMPT_FOR_CODEX.md",
        "10_SCRIPTS.md",
    ];

    #[test]
    fn writes_exactly_the_eleven_expected_files() {
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
        let output_dir = out_dir.path().join(JOB.filename);

        write_ai_context_folder(&ctx, &output_dir).unwrap();

        let mut entries: Vec<String> = std::fs::read_dir(&output_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        entries.sort();
        let mut expected: Vec<String> = EXPECTED_FILES.iter().map(|s| s.to_string()).collect();
        expected.sort();
        assert_eq!(entries, expected);

        let overview = std::fs::read_to_string(output_dir.join("00_PROJECT_OVERVIEW.md")).unwrap();
        assert!(overview.contains("Project type"));

        let prompt = std::fs::read_to_string(output_dir.join("09_PROMPT_FOR_CODEX.md")).unwrap();
        assert!(prompt.contains("Оценить архитектуру"));
    }

    #[test]
    fn prompt_for_codex_always_uses_default_goals_regardless_of_config() {
        let fixture = Fixture::new(|_root| {});
        let mut ctx = fixture.context("full");
        let mut config = fixture.config.clone();
        config.prompt_goals = vec!["security_review".to_string()];
        ctx.config = &config;
        let out_dir = tempfile::tempdir().unwrap();
        let output_dir = out_dir.path().join(JOB.filename);

        write_ai_context_folder(&ctx, &output_dir).unwrap();

        let prompt = std::fs::read_to_string(output_dir.join("09_PROMPT_FOR_CODEX.md")).unwrap();
        assert!(prompt.contains("Оценить архитектуру"));
        assert!(!prompt.contains("Проверить безопасность"));
    }
}
