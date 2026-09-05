//! [`ReportContext`]: the one struct every report job reads from. Built once per
//! export run by the (future, S9) engine and passed by reference into every
//! [`crate::plugin::ReportJob::run`] call.
//!
//! `scan`/`diff` are `Option` on purpose: this pass (Group G+A) never constructs a
//! real [`codepack_security::ScanResult`] or [`codepack_diff::DiffSelection`] — those
//! only exist once Group B's security-scan adapter and a future diff-aware report
//! actually run the upstream crates — but the fields are real, typed members from day
//! one so a later group's addition of a security/diff-aware report needs no struct
//! redesign (churn the task explicitly asked to avoid).

mod inventory;
mod package_scripts;
mod stack;

pub use inventory::{ExtensionStat, Inventory, InventoryFile, LanguageStat, any_file_name};
pub use package_scripts::{PackageScript, RedactedCommand, package_scripts};
pub use stack::{DetectedStack, detect_package_managers, detect_stack};

use std::path::{Path, PathBuf};

use codepack_core::CancellationToken;
use codepack_core::config::Config;
use codepack_diff::DiffSelection;
use codepack_scanner::ExportPlan;
use codepack_security::ScanResult;

/// Everything a report job needs to read, borrowed from the caller for the duration
/// of one export run.
pub struct ReportContext<'a> {
    pub source_root: PathBuf,
    pub staging_root: PathBuf,
    pub inventory: &'a Inventory,
    pub plan: &'a ExportPlan,
    pub scan: Option<&'a ScanResult>,
    pub diff: Option<&'a DiffSelection>,
    pub config: &'a Config,
    pub cancel: &'a CancellationToken,
    pub profile: &'a str,
}

impl<'a> ReportContext<'a> {
    /// [`crate::paths::resolve`] against [`Self::staging_root`] — the one place a
    /// report should turn a `PlannedFile.relative_path` back into an openable file.
    pub fn resolve(&self, relative_path: &str) -> PathBuf {
        crate::paths::resolve(&self.staging_root, relative_path)
    }

    /// The language this run's artifacts are written in.
    ///
    /// A method rather than a field: every report reaches it the same way, and the
    /// context's shape — which a good deal of test code builds by hand — does not move.
    pub fn artifact_language(&self) -> crate::i18n::Language {
        crate::i18n::Language::from_config(self.config)
    }
}

/// Redacts secrets from a single line of report output before it is written.
/// Every report that quotes raw file content (as opposed to just a file path or a
/// computed statistic) must route the quoted text through this — invariant I3
/// (`docs/architecture/invariants.md`): a finding's/line's text is redacted before it
/// reaches a report.
///
/// Uses `codepack_security::patterns::keyword::redacted_line`, not the narrower
/// `codepack_security::redact_secrets` — the former also matches `DATABASE_URL`/
/// `JWT_SECRET`/`ACCESS_KEY`/`CLIENT_SECRET` (`SCAN_KEYWORDS`), which the latter does
/// not. Legacy's own `docker_report.py` imported this exact stronger function for the
/// identical purpose; review found the plain `redact_secrets` call here left common
/// secret-carrying variable names (`DATABASE_URL=...`) unredacted across every report
/// that quotes raw content — a real narrowing versus legacy, not a documented gap.
pub fn redact_line(line: &str) -> String {
    codepack_security::patterns::keyword::redacted_line(line)
}

/// True when `staging_root`/`name` exists on disk. A single, bounded existence check
/// — not a directory walk (this crate's scope boundary).
pub fn root_entry_exists(root: &Path, name: &str) -> bool {
    root.join(name).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every report reaches the artifact language the same way, so the one method has
    /// to answer from the configuration it was handed rather than from a default.
    #[test]
    fn the_context_reports_the_configured_artifact_language() {
        use codepack_core::config::Config;
        use codepack_scanner::{ExportIgnoreRules, ScanOptions, build_export_plan};

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("main.py"),
            "x = 1
",
        )
        .unwrap();
        let cancel = CancellationToken::new();
        let plan = build_export_plan(
            dir.path(),
            &ScanOptions::default(),
            &ExportIgnoreRules::default(),
            &codepack_scanner::no_safety_classification,
            &cancel,
        )
        .unwrap();
        let inventory = Inventory::from_plan(&plan);

        for (setting, expected) in [
            ("en", crate::i18n::Language::En),
            ("ru", crate::i18n::Language::Ru),
        ] {
            let config = Config {
                artifact_language: setting.to_string(),
                ..Config::default()
            };
            let ctx = ReportContext {
                source_root: dir.path().to_path_buf(),
                staging_root: dir.path().to_path_buf(),
                inventory: &inventory,
                plan: &plan,
                scan: None,
                diff: None,
                config: &config,
                cancel: &cancel,
                profile: "full",
            };
            assert_eq!(ctx.artifact_language(), expected, "setting {setting}");
        }
    }

    /// Invariant I3 is absolute, and `redact_line` is the single gate every report that
    /// quotes file content passes through — so the choice of the *stronger* redaction
    /// function is itself worth pinning, not just the fact that redaction happens.
    #[test]
    fn redact_line_covers_the_keywords_the_narrower_function_misses() {
        // The exact regression that made this function exist: `redact_secrets` alone
        // does not know DATABASE_URL, so a connection string survived into every report
        // that quoted raw content.
        for line in [
            "DATABASE_URL=postgres://user:pw@host/db",
            "JWT_SECRET=abcdef0123456789",
            "ACCESS_KEY=AKIAIOSFODNN7EXAMPLE",
            "CLIENT_SECRET=shhh-do-not-tell",
        ] {
            let redacted = redact_line(line);
            let value = line.split_once('=').expect("fixture has a value").1;
            assert!(
                !redacted.contains(value),
                "value survived redaction of {line:?}: {redacted}"
            );
            assert!(redacted.contains("<REDACTED>"), "no marker in {redacted}");
        }
    }

    #[test]
    fn redact_line_leaves_ordinary_content_alone_apart_from_trimming() {
        assert_eq!(redact_line("   let total = a + b;  "), "let total = a + b;");
        assert_eq!(redact_line("fn main() {}"), "fn main() {}");
    }

    #[test]
    fn root_entry_exists_distinguishes_present_from_absent() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();

        assert!(root_entry_exists(dir.path(), "package.json"));
        // Directories count too: several callers probe for `.git`.
        assert!(root_entry_exists(dir.path(), "src"));
        assert!(!root_entry_exists(dir.path(), "Cargo.toml"));
    }

    #[test]
    fn resolve_turns_a_backslash_joined_relative_path_into_a_real_nested_path() {
        // `PlannedFile.relative_path` is backslash-joined on every platform, so
        // resolving must split on it rather than hand the string to `Path::new`, which
        // would treat it as one flat filename off Windows.
        let dir = tempfile::tempdir().unwrap();
        let plan = crate::test_support::build_plan(dir.path());
        let inventory = Inventory::from_plan(&plan);
        let config = codepack_core::config::Config::default();
        let cancel = CancellationToken::new();
        let ctx = ReportContext {
            source_root: dir.path().to_path_buf(),
            staging_root: dir.path().to_path_buf(),
            inventory: &inventory,
            plan: &plan,
            scan: None,
            diff: None,
            config: &config,
            cancel: &cancel,
            profile: "full",
        };

        let resolved = ctx.resolve("src\\utils\\helper.py");
        assert_eq!(
            resolved,
            dir.path().join("src").join("utils").join("helper.py")
        );
        assert!(resolved.starts_with(dir.path()));
    }
}
