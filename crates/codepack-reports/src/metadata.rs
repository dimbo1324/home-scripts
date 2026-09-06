//! `manifest.json`/`INDEX.md`, ported from legacy
//! `reports/metadata.py::write_manifest`/`write_index_md`. Both are **pure writer
//! functions**: every value they need is supplied by the caller through
//! [`ManifestInput`] rather than derived from a live pipeline run — the same posture
//! `codepack_diff::report::write_diff_report` was built with ahead of its own real
//! caller. Wiring a real engine run's [`codepack_core::CopyStats`]/
//! [`codepack_core::TextDumpStats`]/[`codepack_core::ArchiveBuildResult`]/
//! [`codepack_diff::DiffSelection`] into this struct is stage S9's job, not this
//! pass's.
//!
//! Field names/order inside `settings`/`ignored_dirs`/`stats`/`archives`/`layout`
//! mirror legacy's dict insertion order exactly (invariant I5). Two differences from
//! legacy are deliberate, not gaps:
//!
//! - `app`/`app_version` are caller-supplied strings — this crate has no build-info
//!   constant of its own (legacy's own `APP_NAME`/`APP_VERSION` live in its
//!   `constants.py`, one layer above any single report crate).
//! - `layout.project_profile` is `"PROJECT_PROFILE.json"` and `layout.reports` lists
//!   this crate's actual flat file names (`crate::catalog::full_report_catalog`)
//!   rather than legacy's `reports/insights/`-nested paths — a consequence of the
//!   flat output layout this stage's earlier passes already established, not a
//!   parity gap introduced here.

use std::path::Path;

use serde::Serialize;

use codepack_core::config::Config;
use codepack_core::{ArchiveBuildResult, CopyStats, ExportPaths, TextDumpStats};
use codepack_diff::{DiffSelection, FileStatus};

use crate::catalog::full_report_catalog;
use crate::error::ReportError;

/// Every already-produced piece of pipeline data `write_manifest` needs. `None` for
/// `archive_result` renders legacy's own `{"status": "not_written_yet"}` fallback
/// (`_archive_payload`); `None` for `diff_selection` renders JSON `null`, matching
/// legacy's `diff_manifest_payload(None) -> None`.
pub struct ManifestInput<'a> {
    pub app_name: &'a str,
    pub app_version: &'a str,
    pub generated_at: String,
    pub paths: &'a ExportPaths,
    pub cancelled: bool,
    pub config: &'a Config,
    pub extra_ignored_dirs: &'a [String],
    pub copy_stats: &'a CopyStats,
    pub text_stats: &'a TextDumpStats,
    pub archive_result: Option<&'a ArchiveBuildResult>,
    pub diff_selection: Option<&'a DiffSelection>,
}

#[derive(Serialize)]
struct ManifestSettings<'a> {
    text_file_size_limit_enabled: bool,
    max_text_file_mb: Option<u32>,
    max_text_file_bytes: Option<u64>,
    max_text_file_human: String,
    redact_secrets: bool,
    keep_staging_folder: bool,
    include_project_in_zip: bool,
    export_profile: &'a str,
    safe_export_mode: &'a str,
    zip_part_limit_mb: u32,
    diff_export_mode: &'a str,
    diff_base_ref: &'a str,
    diff_target_ref: &'a str,
    include_git_patch: bool,
    custom_excluded_files: &'a [String],
    custom_excluded_extensions: &'a [String],
    always_include_files: &'a [String],
    always_include_dirs: &'a [String],
    incremental_export_enabled: bool,
    theme: &'a str,
    watch_enabled: bool,
    watch_clipboard_auto_update: bool,
    prompt_goals: &'a [String],
}

#[derive(Serialize)]
struct ManifestDiffFile<'a> {
    path: &'a str,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    old_path: Option<&'a str>,
}

#[derive(Serialize)]
struct ManifestDeletedFile<'a> {
    path: &'a str,
    status: &'static str,
}

#[derive(Serialize)]
struct ManifestDiffSelection<'a> {
    mode: &'a str,
    diff_base: &'a str,
    limited: bool,
    selected_paths_count: Option<usize>,
    warning: Option<&'a str>,
    files: Vec<ManifestDiffFile<'a>>,
    deleted_files: Vec<ManifestDeletedFile<'a>>,
}

fn diff_selection_payload(selection: &DiffSelection) -> ManifestDiffSelection<'_> {
    let files = selection
        .files
        .iter()
        .filter(|item| item.status != FileStatus::Deleted)
        .map(|item| ManifestDiffFile {
            path: &item.relative_path,
            status: item.status.as_str(),
            old_path: item.old_path.as_deref(),
        })
        .collect();
    let deleted_files = selection
        .deleted()
        .map(|item| ManifestDeletedFile {
            path: &item.relative_path,
            status: "deleted",
        })
        .collect();
    ManifestDiffSelection {
        mode: &selection.mode,
        diff_base: &selection.base,
        limited: selection.is_limited(),
        selected_paths_count: selection.paths.as_ref().map(|paths| paths.len()),
        warning: selection.warning.as_deref(),
        files,
        deleted_files,
    }
}

#[derive(Serialize)]
struct ManifestIgnoredDirs {
    defaults: Vec<String>,
    user_extras: Vec<String>,
    effective: Vec<String>,
}

fn ignored_dirs_payload(extra_ignored_dirs: &[String]) -> ManifestIgnoredDirs {
    let defaults: std::collections::BTreeSet<String> = codepack_scanner::IGNORED_DIR_NAMES
        .iter()
        .map(|name| name.to_lowercase())
        .collect();
    let user_extras: std::collections::BTreeSet<String> = extra_ignored_dirs
        .iter()
        .map(|name| name.to_lowercase())
        .filter(|name| !defaults.contains(name))
        .collect();
    let effective: std::collections::BTreeSet<String> = defaults
        .iter()
        .cloned()
        .chain(user_extras.iter().cloned())
        .collect();
    ManifestIgnoredDirs {
        defaults: defaults.into_iter().collect(),
        user_extras: user_extras.into_iter().collect(),
        effective: effective.into_iter().collect(),
    }
}

#[derive(Serialize)]
struct ManifestStats<'a> {
    copy: &'a CopyStats,
    text_dump: &'a TextDumpStats,
}

#[derive(Serialize)]
struct ManifestArchives<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    split: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    archives: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    archive_names: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    skipped_project_files: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    oversized_files: Option<&'a [String]>,
}

fn archive_payload(archive_result: Option<&ArchiveBuildResult>) -> ManifestArchives<'_> {
    match archive_result {
        None => ManifestArchives {
            status: Some("not_written_yet"),
            split: None,
            output_dir: None,
            archives: None,
            archive_names: None,
            file_count: None,
            skipped_project_files: None,
            oversized_files: None,
        },
        Some(result) => ManifestArchives {
            status: None,
            split: Some(result.split),
            output_dir: result
                .output_dir
                .as_ref()
                .map(|path| path.display().to_string()),
            archives: Some(
                result
                    .archives
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect(),
            ),
            archive_names: Some(
                result
                    .archives
                    .iter()
                    .map(|path| {
                        path.file_name()
                            .map(|name| name.to_string_lossy().into_owned())
                            .unwrap_or_default()
                    })
                    .collect(),
            ),
            file_count: Some(result.file_count),
            skipped_project_files: Some(result.skipped_project_files),
            oversized_files: Some(&result.oversized_files),
        },
    }
}

#[derive(Serialize)]
struct ManifestLayout {
    project_dir: String,
    project_profile: &'static str,
    reports: Vec<&'static str>,
}

#[derive(Serialize)]
struct ManifestDocument<'a> {
    app: &'a str,
    app_version: &'a str,
    generated_at: &'a str,
    bundle_name: &'a str,
    source_root: String,
    project_name: &'a str,
    cancelled: bool,
    settings: ManifestSettings<'a>,
    diff_selection: Option<ManifestDiffSelection<'a>>,
    ignored_dirs: ManifestIgnoredDirs,
    notes: Vec<&'static str>,
    stats: ManifestStats<'a>,
    archives: ManifestArchives<'a>,
    layout: ManifestLayout,
}

const NOTES: &[&str] = &[
    "Git data is collected from the ORIGINAL project; the .git directory is never copied into the bundle.",
    "Safe Export mode may have removed secrets or local data during copy; check the security report before sharing externally.",
    "All other reports describe the copied project (see the project folder inside the bundle).",
    "Symlinks were skipped during copy to avoid accidental escape from the project tree.",
    "If archive splitting was needed, extract every ZIP file from the archive-set folder into the same destination.",
];

pub fn write_manifest(input: &ManifestInput<'_>, output_file: &Path) -> Result<(), ReportError> {
    let config = input.config;
    let max_text_file_bytes = config.effective_max_text_file_bytes();
    let settings = ManifestSettings {
        text_file_size_limit_enabled: config.text_file_size_limit_enabled,
        max_text_file_mb: if config.text_file_size_limit_enabled {
            Some(config.max_text_file_mb)
        } else {
            None
        },
        max_text_file_bytes,
        max_text_file_human: max_text_file_bytes
            .map(codepack_tokens::format_bytes)
            .unwrap_or_else(|| "unlimited".to_string()),
        redact_secrets: config.redact_secrets,
        keep_staging_folder: config.keep_staging_folder,
        include_project_in_zip: config.include_project_in_zip,
        export_profile: config.normalized_export_profile(),
        safe_export_mode: config.normalized_safe_export_mode(),
        zip_part_limit_mb: config.zip_part_limit_mb,
        diff_export_mode: config.normalized_diff_export_mode(),
        diff_base_ref: &config.diff_base_ref,
        diff_target_ref: &config.diff_target_ref,
        include_git_patch: config.include_git_patch,
        custom_excluded_files: &config.custom_excluded_files,
        custom_excluded_extensions: &config.custom_excluded_extensions,
        always_include_files: &config.always_include_files,
        always_include_dirs: &config.always_include_dirs,
        incremental_export_enabled: config.incremental_export_enabled,
        theme: config.normalized_theme(),
        watch_enabled: config.watch_enabled,
        watch_clipboard_auto_update: config.watch_clipboard_auto_update,
        prompt_goals: &config.prompt_goals,
    };

    let document = ManifestDocument {
        app: input.app_name,
        app_version: input.app_version,
        generated_at: &input.generated_at,
        bundle_name: &input.paths.bundle_name,
        source_root: codepack_core::config::disclosed_root(
            input.config,
            &input.paths.source_root,
            &input.paths.project_name,
        ),
        project_name: &input.paths.project_name,
        cancelled: input.cancelled,
        settings,
        diff_selection: input.diff_selection.map(diff_selection_payload),
        ignored_dirs: ignored_dirs_payload(input.extra_ignored_dirs),
        notes: NOTES.to_vec(),
        stats: ManifestStats {
            copy: input.copy_stats,
            text_dump: input.text_stats,
        },
        archives: archive_payload(input.archive_result),
        layout: ManifestLayout {
            project_dir: format!("{}/", input.paths.project_name),
            project_profile: "PROJECT_PROFILE.json",
            reports: full_report_catalog()
                .into_iter()
                .map(|(name, _)| name)
                .collect(),
        },
    };

    let rendered = serde_json::to_string_pretty(&document)
        .map_err(|source| ReportError::Serialize { source })?;
    std::fs::write(output_file, rendered).map_err(|source| ReportError::Write {
        path: output_file.to_path_buf(),
        source,
    })
}

/// [`write_manifest`]'s `INDEX.md` sibling, ported from legacy `write_index_md`. Takes
/// the same subset of already-produced data legacy's own function needs: paths,
/// config, and the effective ignored-directory set.
pub struct IndexInput<'a> {
    pub app_name: &'a str,
    pub app_version: &'a str,
    pub generated_at: String,
    pub project_name: &'a str,
    pub config: &'a Config,
    pub extra_ignored_dirs: &'a [String],
}

pub fn write_index_md(input: &IndexInput<'_>, output_file: &Path) -> Result<(), ReportError> {
    let config = input.config;
    let ignored = ignored_dirs_payload(input.extra_ignored_dirs);
    let max_text_file_bytes = config.effective_max_text_file_bytes();

    let mut out = String::new();
    out.push_str(&format!("# Export bundle: `{}`\n\n", input.project_name));
    out.push_str(&format!(
        "_Generated by {} v{} on {}._\n\n",
        input.app_name, input.app_version, input.generated_at
    ));
    out.push_str(
        "This archive bundles a project copy together with machine- and human-readable \
reports.\n\n",
    );

    out.push_str("## Bundle contents\n\n");
    out.push_str(&format!(
        "- `{}/` — working copy of the project (without `.git`, `node_modules`, user-configured \
extras and files filtered by Safe Export mode).\n",
        input.project_name
    ));
    out.push_str("- `manifest.json` — machine-readable metadata about this export.\n");
    out.push_str("- `PROJECT_PROFILE.json` — machine-readable project passport.\n");
    out.push_str("- `reports/` — generated reports and AI handoff material.\n\n");

    out.push_str("## Reports\n\n");
    for (relative_path, description) in full_report_catalog() {
        out.push_str(&format!("- `{relative_path}` — {description}\n"));
    }

    out.push_str("\n## Settings used for this export\n\n");
    out.push_str(&format!(
        "- Max text-file size: **{}**\n",
        max_text_file_bytes
            .map(codepack_tokens::format_bytes)
            .unwrap_or_else(|| "unlimited".to_string())
    ));
    out.push_str(&format!(
        "- Secret redaction: **{}**\n",
        if config.redact_secrets {
            "enabled"
        } else {
            "disabled"
        }
    ));
    out.push_str(&format!(
        "- Safe Export mode: **{}**\n",
        config.normalized_safe_export_mode()
    ));
    out.push_str(&format!(
        "- Diff Export mode: **{}**\n",
        config.normalized_diff_export_mode()
    ));
    out.push_str(&format!(
        "- Incremental Export: **{}**\n",
        if config.incremental_export_enabled {
            "enabled"
        } else {
            "disabled"
        }
    ));
    out.push_str(&format!(
        "- Archive part limit: **{} MB**\n",
        config.zip_part_limit_mb
    ));
    out.push_str(&format!(
        "- Project included in ZIP: **{}**\n",
        if config.include_project_in_zip {
            "yes"
        } else {
            "no (reports only)"
        }
    ));
    out.push_str(&format!(
        "- Staging folder kept: **{}**\n",
        if config.keep_staging_folder {
            "yes"
        } else {
            "no"
        }
    ));
    out.push_str(&format!(
        "- Ignored directories: {}\n",
        ignored
            .effective
            .iter()
            .map(|name| format!("`{name}`"))
            .collect::<Vec<_>>()
            .join(", ")
    ));

    out.push_str("\n## Notes\n\n");
    for note in NOTES {
        out.push_str(&format!("- {note}\n"));
    }

    std::fs::write(output_file, out).map_err(|source| ReportError::Write {
        path: output_file.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use codepack_core::config::Config;

    fn sample_paths() -> ExportPaths {
        ExportPaths {
            desktop: "/desktop".into(),
            source_root: "/source/demo".into(),
            project_name: "demo".to_string(),
            bundle_name: "demo_export".to_string(),
            staging_dir: "/staging".into(),
            final_zip: "/out/demo.zip".into(),
            archive_set_dir: "/out/demo_archive_set".into(),
            project_dir: "/staging/demo".into(),
            reports_dir: "/staging/demo_reports".into(),
            insights_dir: "/staging/demo_reports/insights".into(),
            manifest_file: "/staging/manifest.json".into(),
            project_profile_file: "/staging/PROJECT_PROFILE.json".into(),
            index_file: "/staging/INDEX.md".into(),
            structure_report: "/staging/01_structure.txt".into(),
            git_report: "/staging/02_git.txt".into(),
            text_dump: "/staging/03_text_dump.txt".into(),
        }
    }

    #[test]
    fn write_manifest_matches_legacy_field_names_and_archives_not_written_yet_fallback() {
        let config = Config::default();
        let paths = sample_paths();
        let copy_stats = CopyStats::default();
        let text_stats = TextDumpStats::default();
        let input = ManifestInput {
            app_name: "codepack",
            app_version: "0.1.0",
            generated_at: "2026-07-24T00:00:00Z".to_string(),
            paths: &paths,
            cancelled: false,
            config: &config,
            extra_ignored_dirs: &[],
            copy_stats: &copy_stats,
            text_stats: &text_stats,
            archive_result: None,
            diff_selection: None,
        };
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join("manifest.json");

        write_manifest(&input, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["app"], "codepack");
        assert_eq!(parsed["bundle_name"], "demo_export");
        assert_eq!(parsed["project_name"], "demo");
        assert_eq!(parsed["cancelled"], false);
        assert_eq!(parsed["archives"]["status"], "not_written_yet");
        assert_eq!(parsed["diff_selection"], serde_json::Value::Null);
        assert!(parsed["settings"].get("prompt_goals").is_some());
        assert!(parsed["settings"].get("export_profile").is_some());
        assert!(
            !parsed["ignored_dirs"]["defaults"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(parsed["layout"]["project_profile"], "PROJECT_PROFILE.json");
        assert_eq!(parsed["layout"]["project_dir"], "demo/");
        let reports = parsed["layout"]["reports"].as_array().unwrap();
        assert!(reports.iter().any(|value| value == "01_summary.txt"));
        assert!(reports.iter().any(|value| value == "PROJECT_PROFILE.json"));
    }

    #[test]
    fn write_manifest_includes_archive_result_when_supplied() {
        let config = Config::default();
        let paths = sample_paths();
        let copy_stats = CopyStats::default();
        let text_stats = TextDumpStats::default();
        let archive_result = ArchiveBuildResult {
            archives: vec!["/out/demo_part_001.zip".into()],
            output_dir: Some("/out/demo_archive_set".into()),
            split: true,
            file_count: 12,
            skipped_project_files: 0,
            oversized_files: Vec::new(),
        };
        let input = ManifestInput {
            app_name: "codepack",
            app_version: "0.1.0",
            generated_at: "2026-07-24T00:00:00Z".to_string(),
            paths: &paths,
            cancelled: false,
            config: &config,
            extra_ignored_dirs: &["my_custom_dir".to_string()],
            copy_stats: &copy_stats,
            text_stats: &text_stats,
            archive_result: Some(&archive_result),
            diff_selection: None,
        };
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join("manifest.json");

        write_manifest(&input, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["archives"]["split"], true);
        assert_eq!(parsed["archives"]["file_count"], 12);
        assert!(parsed["archives"].get("status").is_none());
        assert!(
            parsed["ignored_dirs"]["user_extras"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "my_custom_dir")
        );
    }

    #[test]
    fn write_index_md_lists_settings_and_reports() {
        let config = Config::default();
        let input = IndexInput {
            app_name: "codepack",
            app_version: "0.1.0",
            generated_at: "2026-07-24T00:00:00Z".to_string(),
            project_name: "demo",
            config: &config,
            extra_ignored_dirs: &[],
        };
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join("INDEX.md");

        write_index_md(&input, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.starts_with("# Export bundle: `demo`"));
        assert!(content.contains("## Reports"));
        assert!(content.contains("`01_summary.txt` —"));
        assert!(content.contains("`PROJECT_PROFILE.json` —"));
        assert!(content.contains("## Settings used for this export"));
        assert!(content.contains("## Notes"));
    }
}
