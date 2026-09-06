//! Archive entries and the logical-group classifier (BLUEPRINT §A.8, legacy
//! `services/archive_service.py::classify_archive_group`/`_iter_archive_entries`).

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use codepack_core::{CancellationToken, ExportPaths, file_groups};

use crate::error::{ArchiveError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveEntry {
    pub path: PathBuf,
    pub arcname: PathBuf,
    pub size: u64,
    pub group: &'static str,
}

const METADATA_TOP_LEVEL_NAMES: [&str; 3] = ["index.md", "manifest.json", "project_profile.json"];
const TEST_COMPONENT_NAMES: [&str; 2] = ["__tests__", "spec"];
// Assembled from `codepack_core::file_groups` rather than typed out, so an extension
// added for both classifiers reaches both. Where this classifier's legacy original was
// wider than the export plan's, the difference is a named set rather than an unexplained
// extra entry (audit No. 24). Membership is what these are asked for, so the assembled
// order is immaterial.
static DOC_FILE_NAMES: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    file_groups::joined(
        file_groups::DOC_NAMES_SHARED,
        file_groups::DOC_NAMES_ARCHIVE_ONLY,
    )
});
static DOC_SUFFIXES: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| file_groups::DOC_SHARED.to_vec());
static PYTHON_SUFFIXES: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| file_groups::PYTHON_SHARED.to_vec());
static FRONTEND_SUFFIXES: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    file_groups::joined(
        file_groups::FRONTEND_SHARED,
        file_groups::FRONTEND_ARCHIVE_ONLY,
    )
});
static BACKEND_SUFFIXES: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    file_groups::joined(
        file_groups::BACKEND_SHARED,
        file_groups::BACKEND_ARCHIVE_ONLY,
    )
});
static CONFIG_SUFFIXES: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    file_groups::joined(file_groups::CONFIG_SHARED, file_groups::CONFIG_ARCHIVE_ONLY)
});
static ASSET_SUFFIXES: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| file_groups::ASSET_SHARED.to_vec());
static DATA_SUFFIXES: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| file_groups::joined(file_groups::DATA_SHARED, file_groups::DATA_ARCHIVE_ONLY));

/// Lowercased path components of `arcname`, mirroring Python's
/// `[part.casefold() for part in arcname.parts]`. `to_lowercase` rather than a true
/// Unicode casefold: every legacy comparison set is ASCII, so the two agree for every
/// input this classifier actually receives.
fn lowercase_components(arcname: &Path) -> Vec<String> {
    arcname
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => Some(part.to_string_lossy().to_lowercase()),
            _ => None,
        })
        .collect()
}

/// First-match-wins port of `classify_archive_group` (`archive_service.py`). Order is
/// load-bearing: the `reports/`-prefix and any-depth test-component checks run before
/// any extension-based check.
pub fn classify_archive_group(arcname: &Path, project_name: &str) -> &'static str {
    let parts = lowercase_components(arcname);
    let suffix = arcname
        .extension()
        .map(|ext| ext.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let name = arcname
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    if parts.is_empty() || METADATA_TOP_LEVEL_NAMES.contains(&parts[0].as_str()) {
        return "00_metadata";
    }
    if parts[0] == "reports" {
        if parts.iter().any(|part| part == "ai_context") {
            return "02_ai_context";
        }
        if parts.iter().any(|part| part == "ai_prompts") {
            return "03_ai_prompts";
        }
        return "01_reports";
    }
    if parts.iter().any(|part| {
        part == "test" || part == "tests" || TEST_COMPONENT_NAMES.contains(&part.as_str())
    }) {
        return "20_tests";
    }
    if DOC_FILE_NAMES.contains(&name.as_str()) || DOC_SUFFIXES.contains(&suffix.as_str()) {
        return "30_docs";
    }
    if PYTHON_SUFFIXES.contains(&suffix.as_str()) {
        return "40_python_source";
    }
    if FRONTEND_SUFFIXES.contains(&suffix.as_str()) {
        return "41_frontend_source";
    }
    if BACKEND_SUFFIXES.contains(&suffix.as_str()) {
        return "42_backend_or_system_source";
    }
    if CONFIG_SUFFIXES.contains(&suffix.as_str()) || name.starts_with("dockerfile") {
        return "50_config_and_locks";
    }
    if ASSET_SUFFIXES.contains(&suffix.as_str()) {
        return "60_assets_and_binary_docs";
    }
    if DATA_SUFFIXES.contains(&suffix.as_str()) {
        return "70_data_and_exports";
    }
    if !parts.is_empty() && parts[0] == project_name.to_lowercase() {
        return "80_other_project_files";
    }
    "90_other"
}

fn is_inside(path: &Path, parent: &Path) -> bool {
    path.starts_with(parent)
}

/// Walks `paths.staging_dir`, classifying every file into an [`ArchiveEntry`]. When
/// `include_project` is `false`, files under `paths.project_dir` are skipped and
/// counted instead of collected. Cancellation is checked per file inside the walk
/// loop; a cancelled walk simply stops early and returns whatever was collected so
/// far, honestly partial rather than an error (the caller decides what an interrupted
/// collection means for the overall build result).
///
/// Unlike legacy's `_iter_archive_entries`, this does not `resolve()` (canonicalize)
/// either path before comparing: `staging_dir`/`project_dir` are supplied by the same
/// pipeline run and already share a consistent absolute-path form, so a plain
/// `starts_with` prefix check is sufficient and avoids extra filesystem calls.
pub fn collect_entries(
    paths: &ExportPaths,
    include_project: bool,
    cancel: &CancellationToken,
) -> Result<(Vec<ArchiveEntry>, u32)> {
    let mut entries = Vec::new();
    let mut skipped_project_files = 0u32;

    let walker = walkdir::WalkDir::new(&paths.staging_dir).follow_links(false);
    for entry in walker {
        if cancel.is_cancelled() {
            break;
        }
        let entry = entry.map_err(|source| ArchiveError::Walk {
            path: paths.staging_dir.clone(),
            source,
        })?;
        if entry.path_is_symlink() || !entry.file_type().is_file() {
            continue;
        }
        let file_path = entry.into_path();
        if !include_project && is_inside(&file_path, &paths.project_dir) {
            skipped_project_files += 1;
            continue;
        }
        let arcname = file_path
            .strip_prefix(&paths.staging_dir)
            .map(Path::to_path_buf)
            .unwrap_or_else(|_| PathBuf::from(file_path.file_name().unwrap_or_default()));
        // Matches legacy's `try: size = stat().st_size except Exception: size = 0`:
        // an unreadable file still gets archived-planning-visible with size 0 rather
        // than aborting the whole walk.
        let size = std::fs::metadata(&file_path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        let group = classify_archive_group(&arcname, &paths.project_name);
        entries.push(ArchiveEntry {
            path: file_path,
            arcname,
            size,
            group,
        });
    }

    Ok((entries, skipped_project_files))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify(path: &str) -> &'static str {
        classify_archive_group(Path::new(path), "demo-project")
    }

    #[test]
    fn top_level_index_md_is_metadata() {
        assert_eq!(classify("INDEX.md"), "00_metadata");
    }

    #[test]
    fn top_level_manifest_json_is_metadata() {
        assert_eq!(classify("manifest.json"), "00_metadata");
    }

    #[test]
    fn top_level_project_profile_json_is_metadata() {
        assert_eq!(classify("PROJECT_PROFILE.json"), "00_metadata");
    }

    #[test]
    fn nested_index_md_is_not_metadata() {
        assert_ne!(classify("sub/INDEX.md"), "00_metadata");
    }

    #[test]
    fn reports_prefix_wins_regardless_of_extension() {
        assert_eq!(classify("reports/06_security_scan.py"), "01_reports");
    }

    #[test]
    fn reports_ai_context_subfolder() {
        assert_eq!(classify("reports/AI_CONTEXT/file.md"), "02_ai_context");
    }

    #[test]
    fn reports_ai_prompts_subfolder() {
        assert_eq!(classify("reports/AI_PROMPTS/review.md"), "03_ai_prompts");
    }

    #[test]
    fn test_component_at_any_depth_wins_over_extension() {
        assert_eq!(classify("src/deep/tests/unit_test.py"), "20_tests");
        assert_eq!(classify("src/deep/test/unit.rs"), "20_tests");
        assert_eq!(classify("src/__tests__/component.tsx"), "20_tests");
        assert_eq!(classify("src/spec/thing.rb"), "20_tests");
    }

    #[test]
    fn docs_by_name_and_suffix() {
        assert_eq!(classify("README.md"), "30_docs");
        assert_eq!(classify("LICENSE"), "30_docs");
        assert_eq!(classify("CHANGELOG.md"), "30_docs");
        assert_eq!(classify("notes.rst"), "30_docs");
        assert_eq!(classify("notes.adoc"), "30_docs");
        assert_eq!(classify("notes.txt"), "30_docs");
    }

    #[test]
    fn python_source() {
        assert_eq!(classify("app.py"), "40_python_source");
        assert_eq!(classify("app.pyw"), "40_python_source");
        assert_eq!(classify("app.pyi"), "40_python_source");
    }

    #[test]
    fn frontend_source() {
        for ext in [
            "js", "jsx", "ts", "tsx", "mjs", "cjs", "css", "scss", "sass", "html", "vue", "svelte",
            "astro",
        ] {
            assert_eq!(classify(&format!("file.{ext}")), "41_frontend_source");
        }
    }

    #[test]
    fn backend_or_system_source() {
        for ext in [
            "go", "rs", "java", "kt", "kts", "cs", "cpp", "c", "h", "hpp", "rb", "php",
        ] {
            assert_eq!(
                classify(&format!("file.{ext}")),
                "42_backend_or_system_source"
            );
        }
    }

    #[test]
    fn config_and_locks_by_suffix() {
        for ext in [
            "json",
            "yaml",
            "yml",
            "toml",
            "ini",
            "cfg",
            "conf",
            "lock",
            "dockerfile",
        ] {
            assert_eq!(classify(&format!("file.{ext}")), "50_config_and_locks");
        }
    }

    #[test]
    fn dockerfile_prefix_wins_without_matching_extension() {
        assert_eq!(classify("Dockerfile.prod"), "50_config_and_locks");
        assert_eq!(classify("dockerfile"), "50_config_and_locks");
    }

    #[test]
    fn assets_and_binary_docs() {
        for ext in [
            "png", "jpg", "jpeg", "gif", "webp", "svg", "ico", "pdf", "docx", "xlsx", "pptx",
        ] {
            assert_eq!(
                classify(&format!("file.{ext}")),
                "60_assets_and_binary_docs"
            );
        }
    }

    #[test]
    fn data_and_exports() {
        for ext in ["csv", "tsv", "sql", "xml"] {
            assert_eq!(classify(&format!("file.{ext}")), "70_data_and_exports");
        }
    }

    #[test]
    fn unclassified_file_under_project_top_level_folder() {
        assert_eq!(
            classify_archive_group(Path::new("demo-project/weird.bin"), "demo-project"),
            "80_other_project_files"
        );
    }

    #[test]
    fn unclassified_file_elsewhere_is_other() {
        assert_eq!(
            classify_archive_group(Path::new("weird.bin"), "demo-project"),
            "90_other"
        );
    }

    #[test]
    fn metadata_check_is_case_insensitive() {
        assert_eq!(classify("Manifest.JSON"), "00_metadata");
    }

    #[test]
    fn collect_entries_walks_staging_and_classifies() {
        let temp = tempfile::tempdir().expect("tempdir");
        let staging = temp.path().join("staging");
        let project_dir = staging.join("demo-project");
        std::fs::create_dir_all(project_dir.join("src")).expect("mkdir");
        std::fs::write(project_dir.join("src").join("main.rs"), b"fn main() {}").expect("write");
        std::fs::write(staging.join("manifest.json"), b"{}").expect("write");

        let paths = ExportPaths {
            desktop: temp.path().to_path_buf(),
            source_root: temp.path().to_path_buf(),
            project_name: "demo-project".to_string(),
            bundle_name: "demo-project_export".to_string(),
            staging_dir: staging.clone(),
            final_zip: temp.path().join("out.zip"),
            archive_set_dir: temp.path().join("archive_set"),
            project_dir: project_dir.clone(),
            reports_dir: staging.join("reports"),
            insights_dir: staging.join("reports"),
            manifest_file: staging.join("manifest.json"),
            project_profile_file: staging.join("PROJECT_PROFILE.json"),
            index_file: staging.join("INDEX.md"),
            structure_report: staging.join("structure.md"),
            git_report: staging.join("git.md"),
            text_dump: staging.join("dump.txt"),
        };

        let cancel = CancellationToken::new();
        let (entries, skipped) = collect_entries(&paths, true, &cancel).expect("collect");
        assert_eq!(skipped, 0);
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.group == "00_metadata"));
        assert!(
            entries
                .iter()
                .any(|e| e.group == "42_backend_or_system_source")
        );
    }

    #[test]
    fn collect_entries_skips_project_files_when_excluded() {
        let temp = tempfile::tempdir().expect("tempdir");
        let staging = temp.path().join("staging");
        let project_dir = staging.join("demo-project");
        std::fs::create_dir_all(&project_dir).expect("mkdir");
        std::fs::write(project_dir.join("main.rs"), b"fn main() {}").expect("write");
        std::fs::write(staging.join("manifest.json"), b"{}").expect("write");

        let paths = ExportPaths {
            desktop: temp.path().to_path_buf(),
            source_root: temp.path().to_path_buf(),
            project_name: "demo-project".to_string(),
            bundle_name: "demo-project_export".to_string(),
            staging_dir: staging.clone(),
            final_zip: temp.path().join("out.zip"),
            archive_set_dir: temp.path().join("archive_set"),
            project_dir: project_dir.clone(),
            reports_dir: staging.join("reports"),
            insights_dir: staging.join("reports"),
            manifest_file: staging.join("manifest.json"),
            project_profile_file: staging.join("PROJECT_PROFILE.json"),
            index_file: staging.join("INDEX.md"),
            structure_report: staging.join("structure.md"),
            git_report: staging.join("git.md"),
            text_dump: staging.join("dump.txt"),
        };

        let cancel = CancellationToken::new();
        let (entries, skipped) = collect_entries(&paths, false, &cancel).expect("collect");
        assert_eq!(skipped, 1);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].group, "00_metadata");
    }

    #[test]
    fn collect_entries_stops_early_when_cancelled_up_front() {
        let temp = tempfile::tempdir().expect("tempdir");
        let staging = temp.path().join("staging");
        std::fs::create_dir_all(&staging).expect("mkdir");
        std::fs::write(staging.join("a.txt"), b"a").expect("write");
        std::fs::write(staging.join("b.txt"), b"b").expect("write");

        let paths = ExportPaths {
            desktop: temp.path().to_path_buf(),
            source_root: temp.path().to_path_buf(),
            project_name: "demo-project".to_string(),
            bundle_name: "demo-project_export".to_string(),
            staging_dir: staging.clone(),
            final_zip: temp.path().join("out.zip"),
            archive_set_dir: temp.path().join("archive_set"),
            project_dir: staging.join("demo-project"),
            reports_dir: staging.join("reports"),
            insights_dir: staging.join("reports"),
            manifest_file: staging.join("manifest.json"),
            project_profile_file: staging.join("PROJECT_PROFILE.json"),
            index_file: staging.join("INDEX.md"),
            structure_report: staging.join("structure.md"),
            git_report: staging.join("git.md"),
            text_dump: staging.join("dump.txt"),
        };

        let cancel = CancellationToken::new();
        cancel.cancel();
        let (entries, _skipped) = collect_entries(&paths, true, &cancel).expect("collect");
        assert!(entries.is_empty());
    }
}
