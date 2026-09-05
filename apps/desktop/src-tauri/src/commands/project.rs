//! Opening a project, previewing what an export would do, and scanning for secrets.
//!
//! None of these three write anything, anywhere. A user deciding whether it is safe to
//! share a project must be able to ask without producing a bundle and without a report
//! file appearing in their repository.

use std::collections::HashMap;

use codepack_core::CancellationToken;
use codepack_core::config::Config;
use codepack_security::{SecurityOptions, scan_project as run_security_scan};

use crate::dto::{
    FileExplanation, Finding, PreviewReport, ProjectContext, ResolutionTrace, ScanReport,
    ScanSummary,
};
use crate::error::{CommandError, CommandResult};
use crate::tree;

use super::resolve_project_root;

/// Resolves defaults → global settings → `.codepack.toml` for `path`.
///
/// Nothing is persisted: the result is the *starting point* for the session's editable
/// config, and the user is free to change it on the Settings page without that touching
/// their global file.
///
/// The layering matches the CLI's, minus the flag layer a GUI has no equivalent of: the
/// narrower scope wins, so the project's committed opinion overrides the machine's.
#[tauri::command]
pub fn open_project(path: String) -> CommandResult<ProjectContext> {
    let root = resolve_project_root(&path)?;
    let paths = codepack_core::AppPaths::resolve()?;
    let mut config = codepack_core::config::load(&paths);

    // The same parser the CLI uses (`codepack_core::config::ProjectConfig`), not a
    // second copy of the field list: a key the two front ends disagreed about would give
    // a team different exports from the GUI and from CI for the same committed file.
    // A malformed file is an error rather than a silent skip, for the same reason.
    let mut resolution = ResolutionTrace::default();
    if let Some((file, project)) =
        codepack_core::config::ProjectConfig::load(&root).map_err(CommandError::new)?
    {
        project.apply_to(&mut config);
        resolution.project_config = Some(file.display().to_string());
    }

    Ok(ProjectContext {
        root: root.display().to_string(),
        config,
        resolution,
    })
}

/// What an export *would* include, as a tree the Preview page can render.
///
/// No previous snapshot is consulted, so a `last_export` diff mode degrades to
/// "everything" — the same choice the CLI's `preview` makes, and for the same reason: a
/// preview must not touch the history database.
#[tauri::command]
pub fn preview_project(
    project_root: String,
    config: Config,
    file_overrides: HashMap<String, bool>,
) -> CommandResult<PreviewReport> {
    let root = resolve_project_root(&project_root)?;
    let outcome = codepack_engine::plan_export(
        &root,
        &config,
        &file_overrides,
        None,
        &CancellationToken::new(),
    )?;

    let plan = &outcome.export_plan;
    let estimated_bytes = plan.summary.estimated_included_bytes;
    let root_name = root
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| root.display().to_string());

    Ok(PreviewReport {
        project: root.display().to_string(),
        profile: config.normalized_export_profile().to_string(),
        safe_mode: config.normalized_safe_export_mode().to_string(),
        diff_mode: outcome.diff_selection.mode.clone(),
        included_files: plan.included_files.len(),
        excluded_files: plan.excluded_files.len(),
        skipped_dirs: plan.skipped_dirs.len(),
        estimated_bytes,
        estimated_bytes_human: codepack_tokens::format_bytes(estimated_bytes),
        estimated_tokens: codepack_tokens::estimate_tokens_fallback(estimated_bytes),
        dropped_by_budget: outcome.dropped_by_budget,
        sensitive_count: plan.sensitive_warnings().len(),
        tree: tree::build(plan, &root_name),
    })
}

/// Scans the project for secrets and risky code.
///
/// The config is deliberately overridden before scanning, exactly as the CLI's `scan`
/// does, and for the same reason: scanning the file set an export *would* produce makes
/// the answer always "clean", because safe mode removed the dangerous files before the
/// scanner ever looked. A `.env` full of live credentials would be reported as "no
/// findings" — worse than useless for the question this page exists to answer.
#[tauri::command]
pub fn scan_project(project_root: String, config: Config) -> CommandResult<ScanReport> {
    let root = resolve_project_root(&project_root)?;
    let cancel = CancellationToken::new();

    let scan_config = Config {
        // Look at everything, including what an export would filter out.
        safe_export_mode: "full".to_string(),
        // A secret committed last week is still a secret today.
        diff_export_mode: "all".to_string(),
        // The budget drops low-value files; that says nothing about credentials.
        token_budget: 0,
        // A size limit makes the scanner skip a file whole, invisibly. It is a statement
        // about what is worth shipping, never about what is worth looking at.
        text_file_size_limit_enabled: false,
        ..config
    };

    // Ignore rules still apply: `node_modules` is not the user's secret to answer for,
    // and scanning it would bury real findings in noise.
    let plan = codepack_engine::plan_export(&root, &scan_config, &HashMap::new(), None, &cancel)?;
    let relative_files: Vec<std::path::PathBuf> = plan
        .export_plan
        .included_files
        .iter()
        .map(|file| file.relative_path.split('\\').collect())
        .collect();

    let options = SecurityOptions::from(&scan_config);
    let result = run_security_scan(&root, &relative_files, options.max_bytes_per_file, &cancel)?;

    let critical = result
        .findings
        .iter()
        .filter(|finding| finding.severity == "critical")
        .count();

    Ok(ScanReport {
        project: root.display().to_string(),
        safe_mode: "full".to_string(),
        scanned_files: relative_files.len(),
        summary: ScanSummary {
            sensitive_files: result.summary.sensitive_files,
            potential_secrets: result.summary.potential_secrets,
            risky_code: result.summary.risky_code,
            total_findings: result.summary.total_findings,
            critical,
        },
        findings: result
            .findings
            .into_iter()
            .map(|finding| Finding {
                kind: match finding.kind {
                    codepack_security::FindingKind::SensitiveFile => "sensitive_file",
                    codepack_security::FindingKind::PotentialSecret => "potential_secret",
                    codepack_security::FindingKind::RiskyCode => "risky_code",
                }
                .to_string(),
                severity: finding.severity,
                confidence: finding.confidence,
                file: finding.file,
                line: finding.line,
                rule: finding.rule,
                // Already redacted by `codepack-security` (invariant I3).
                message: finding.message,
            })
            .collect(),
    })
}

/// Why one file did, or did not, end up in an export.
///
/// Thin on purpose: the verdict is `codepack-engine`'s, exactly as the CLI's `explain`
/// command gets it. The preview tree already shows a short reason per excluded file;
/// this answers the fuller question a person asks while looking at that tree — which
/// setting decided it, and whether widening the diff or the safe mode is the fix.
#[tauri::command]
pub fn explain_file(
    project_root: String,
    config: Config,
    file: String,
) -> CommandResult<FileExplanation> {
    let root = resolve_project_root(&project_root)?;
    let explanation =
        codepack_engine::explain::explain_file(&root, &config, std::path::Path::new(&file))
            .map_err(CommandError::new)?;
    Ok(FileExplanation {
        file: explanation.file,
        profile: explanation.profile,
        safe_mode: explanation.safe_mode,
        diff_mode: explanation.diff_mode,
        verdict: explanation.verdict.to_string(),
        reason: explanation.reason,
        group: explanation.group,
        severity: explanation.severity,
        size: explanation.size,
        size_human: explanation.size.map(codepack_tokens::format_bytes),
        skipped_directory: explanation.skipped_directory,
        exists_on_disk: explanation.exists_on_disk,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/main.rs"), "fn main() {}\n").unwrap();
        std::fs::write(dir.path().join("README.md"), "# demo\n").unwrap();
        dir
    }

    fn root_of(dir: &tempfile::TempDir) -> String {
        dir.path().display().to_string()
    }

    #[test]
    fn preview_reports_the_file_counts_and_a_tree() {
        let dir = fixture();
        let report = preview_project(root_of(&dir), Config::default(), HashMap::new()).unwrap();

        assert_eq!(report.included_files, 2);
        assert!(report.tree.is_dir);
        assert!(report.estimated_bytes > 0);
        assert!(!report.estimated_bytes_human.is_empty());
    }

    #[test]
    fn preview_writes_nothing_into_the_project() {
        // The reason a preview exists at all: asking must be free of side effects.
        let dir = fixture();
        let before = std::fs::read_dir(dir.path()).unwrap().count();

        preview_project(root_of(&dir), Config::default(), HashMap::new()).unwrap();

        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), before);
    }

    #[test]
    fn preview_surfaces_a_sensitive_exclusion_as_a_warning_in_the_tree() {
        let dir = fixture();
        std::fs::write(dir.path().join(".env"), "API_KEY=live-value\n").unwrap();

        let report = preview_project(root_of(&dir), Config::default(), HashMap::new()).unwrap();

        assert!(report.sensitive_count >= 1);
        assert_eq!(report.tree.status, "warning");
    }

    #[test]
    fn a_file_override_changes_what_the_preview_includes() {
        let dir = fixture();
        let mut overrides = HashMap::new();
        overrides.insert("README.md".to_string(), false);

        let report = preview_project(root_of(&dir), Config::default(), overrides).unwrap();
        assert_eq!(report.included_files, 1);
    }

    #[test]
    fn scan_looks_at_files_safe_mode_would_have_removed() {
        // The defect this override exists to prevent: scanning the exportable set makes
        // the answer always "clean", because safe mode already dropped the .env.
        let dir = fixture();
        std::fs::write(
            dir.path().join(".env"),
            "API_KEY=sk-not-a-real-key-only-a-fixture\n",
        )
        .unwrap();

        let report = scan_project(root_of(&dir), Config::default()).unwrap();
        assert!(
            report.summary.total_findings > 0,
            "the .env was not scanned; safe mode must not apply here"
        );
        assert_eq!(report.safe_mode, "full");
    }

    #[test]
    fn scan_still_ignores_dependency_directories() {
        // Real findings must not be buried under other people's code.
        let dir = fixture();
        std::fs::create_dir_all(dir.path().join("node_modules/pkg")).unwrap();
        std::fs::write(
            dir.path().join("node_modules/pkg/index.js"),
            "const token = 'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';\n",
        )
        .unwrap();

        let report = scan_project(root_of(&dir), Config::default()).unwrap();
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.file.contains("node_modules")),
            "node_modules was scanned: {:?}",
            report.findings
        );
    }

    #[test]
    fn a_size_limit_in_the_users_config_does_not_blind_the_scan() {
        // Two presets enable this limit; honouring it here would let a
        // credential in a large file pass as "no findings".
        let dir = fixture();
        let padding = "x".repeat(3 * 1024 * 1024);
        std::fs::write(
            dir.path().join("big.py"),
            format!("# {padding}\nAPI_KEY = \"sk-fixture-value-not-real\"\n"),
        )
        .unwrap();

        let config = Config {
            text_file_size_limit_enabled: true,
            max_text_file_mb: 1,
            ..Config::default()
        };
        let report = scan_project(root_of(&dir), config).unwrap();
        assert!(
            report.findings.iter().any(|f| f.file.contains("big.py")),
            "the large file was skipped: {:?}",
            report.findings
        );
    }

    #[test]
    fn open_project_applies_a_committed_project_config() {
        let dir = fixture();
        std::fs::write(
            dir.path()
                .join(codepack_core::config::PROJECT_CONFIG_FILE_NAME),
            "safe_export_mode = \"full\"\nexport_profile = \"minimal\"\n",
        )
        .unwrap();

        let context = open_project(root_of(&dir)).unwrap();
        assert_eq!(context.config.safe_export_mode, "full");
        assert_eq!(context.config.export_profile, "minimal");
        assert!(context.resolution.project_config.is_some());
    }

    #[test]
    fn open_project_without_a_project_config_reports_no_such_source() {
        let dir = fixture();
        let context = open_project(root_of(&dir)).unwrap();
        assert!(context.resolution.project_config.is_none());
    }

    #[test]
    fn a_malformed_project_config_fails_loudly_and_names_the_file() {
        // A mistyped key must not give one team member a different export from the rest.
        let dir = fixture();
        std::fs::write(
            dir.path()
                .join(codepack_core::config::PROJECT_CONFIG_FILE_NAME),
            "safe_moed = \"full\"\n",
        )
        .unwrap();

        let error = open_project(root_of(&dir)).unwrap_err();
        assert!(
            error
                .message
                .contains(codepack_core::config::PROJECT_CONFIG_FILE_NAME),
            "the message must name the file: {}",
            error.message
        );
    }

    #[test]
    fn opening_a_path_that_is_not_a_directory_is_an_error() {
        let dir = fixture();
        let file = dir.path().join("README.md");
        assert!(open_project(file.display().to_string()).is_err());
    }

    // --- explain (2026-09-05) --------------------------------------------------------

    #[test]
    fn explaining_an_included_file_says_so() {
        let dir = fixture();
        let answer =
            explain_file(root_of(&dir), Config::default(), "src/main.rs".to_string()).unwrap();

        assert_eq!(answer.verdict, "included");
        assert!(answer.exists_on_disk);
        assert!(!answer.reason.is_empty());
        assert!(
            answer.size_human.is_some(),
            "the app renders bytes, not only a count"
        );
    }

    #[test]
    fn explaining_a_file_that_is_not_there_says_that_instead() {
        let dir = fixture();
        let answer =
            explain_file(root_of(&dir), Config::default(), "src/nope.rs".to_string()).unwrap();

        assert_eq!(answer.verdict, "not_planned");
        assert!(!answer.exists_on_disk);
    }

    /// The point of moving the verdict into the engine: the app and `codepack explain`
    /// answer from one implementation, so they cannot drift apart.
    #[test]
    fn the_app_and_the_engine_give_the_same_verdict() {
        let dir = fixture();
        let config = Config::default();
        let engine = codepack_engine::explain::explain_file(
            dir.path(),
            &config,
            std::path::Path::new("src/main.rs"),
        )
        .unwrap();
        let app = explain_file(root_of(&dir), config, "src/main.rs".to_string()).unwrap();

        assert_eq!(app.verdict, engine.verdict);
        assert_eq!(app.reason, engine.reason);
        assert_eq!(app.file, engine.file);
        assert_eq!(app.size, engine.size);
    }

    #[test]
    fn a_path_outside_the_project_is_an_error_the_ui_can_show() {
        let dir = fixture();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(
            outside.path().join("stranger.rs"),
            "
",
        )
        .unwrap();

        let error = explain_file(
            root_of(&dir),
            Config::default(),
            outside.path().join("stranger.rs").display().to_string(),
        )
        .unwrap_err();
        assert!(!format!("{error:?}").is_empty());
    }
}
