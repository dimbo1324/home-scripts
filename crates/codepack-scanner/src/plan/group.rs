//! `PlannedFile.group` classification, ported from legacy `_classify_group`. Checked
//! in this exact if/elif order — the first matching bucket wins.

use std::path::Path;

use codepack_core::file_groups;

pub(super) fn classify_group(relative_path: &Path) -> &'static str {
    let name = relative_path
        .file_name()
        .map(|value| value.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let suffix = relative_path
        .extension()
        .map(|value| value.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let is_test_segment = relative_path.components().any(|component| {
        let part = component.as_os_str().to_string_lossy().to_lowercase();
        part == "test" || part == "tests" || part == "__tests__"
    });

    if is_test_segment || name.starts_with("test_") {
        return "tests";
    }
    // The sets come from `codepack_core::file_groups`, shared with the archive's own
    // classifier. The two are parity ports of different legacy functions and stay two
    // classifiers, but they no longer keep two independently drifting lists of
    // extensions — which is how `.rb` came to be "backend" in one and "other" here
    // (audit No. 24). Where this one's legacy original was narrower or wider, the
    // difference is a named set rather than a silent omission.
    let has = |set: &[&str]| set.contains(&suffix.as_str());

    if has(file_groups::PYTHON_SHARED) {
        return "python_source";
    }
    if has(file_groups::FRONTEND_SHARED) {
        return "frontend_source";
    }
    if has(file_groups::BACKEND_SHARED) {
        return "backend_or_system_source";
    }
    if has(file_groups::DOC_SHARED) || file_groups::DOC_NAMES_SHARED.contains(&name.as_str()) {
        return "docs";
    }
    // `dockerfile` is matched as a name prefix here and as a suffix in the archive: two
    // spellings of one intention, both inherited from legacy.
    if has(file_groups::CONFIG_SHARED) || name.starts_with("dockerfile") {
        return "config_and_locks";
    }
    if has(file_groups::ASSET_SHARED) {
        return "assets_and_binary_docs";
    }
    if has(file_groups::DATA_SHARED) || has(file_groups::DATA_PLAN_ONLY) {
        return "data_and_exports";
    }
    "other"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tests_bucket_wins_over_extension_rules() {
        assert_eq!(classify_group(Path::new("tests/test_utils.py")), "tests");
        assert_eq!(
            classify_group(Path::new("src/__tests__/App.test.tsx")),
            "tests"
        );
        assert_eq!(classify_group(Path::new("test_something.py")), "tests");
    }

    #[test]
    fn python_source() {
        assert_eq!(classify_group(Path::new("src/main.py")), "python_source");
        assert_eq!(classify_group(Path::new("stub.pyi")), "python_source");
    }

    #[test]
    fn frontend_source() {
        assert_eq!(classify_group(Path::new("src/App.tsx")), "frontend_source");
        assert_eq!(classify_group(Path::new("style.css")), "frontend_source");
    }

    #[test]
    fn backend_or_system_source() {
        assert_eq!(
            classify_group(Path::new("main.go")),
            "backend_or_system_source"
        );
        assert_eq!(
            classify_group(Path::new("lib.rs")),
            "backend_or_system_source"
        );
    }

    #[test]
    fn docs() {
        assert_eq!(classify_group(Path::new("README.md")), "docs");
        assert_eq!(classify_group(Path::new("LICENSE")), "docs");
        assert_eq!(classify_group(Path::new("notes.txt")), "docs");
    }

    #[test]
    fn config_and_locks() {
        assert_eq!(
            classify_group(Path::new("package.json")),
            "config_and_locks"
        );
        assert_eq!(classify_group(Path::new("Dockerfile")), "config_and_locks");
        assert_eq!(classify_group(Path::new("Cargo.lock")), "config_and_locks");
    }

    #[test]
    fn assets_and_binary_docs() {
        assert_eq!(
            classify_group(Path::new("logo.png")),
            "assets_and_binary_docs"
        );
        assert_eq!(
            classify_group(Path::new("report.pdf")),
            "assets_and_binary_docs"
        );
    }

    #[test]
    fn data_and_exports() {
        assert_eq!(classify_group(Path::new("dump.sql")), "data_and_exports");
        assert_eq!(classify_group(Path::new("app.sqlite3")), "data_and_exports");
    }

    #[test]
    fn other_is_the_fallback() {
        assert_eq!(classify_group(Path::new("binary.exe")), "other");
    }
}
