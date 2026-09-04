//! Reading `.codepack-allow` on behalf of a command.
//!
//! The screening itself — what a listed fingerprint means, and what a caller is handed
//! back — lives in `codepack_security::allow`, so the export pipeline and the reports
//! reach the same verdict this front end does (Q26). What stays here is the one thing
//! that is a front end's business: turning a malformed-file error into a `CliError` the
//! command layer can print.
//!
//! **A suppressed finding is counted and reported, never silently dropped.** The exit
//! code is computed from what survives, which is the entire point of the feature: a
//! finding a team has reviewed and written down should stop failing their pipeline. It
//! also means a typo in the file can un-fail a build, which is exactly why
//! `codepack-core` rejects a malformed fingerprint at load time instead of letting it
//! sit there matching nothing.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use codepack_core::allowlist::Allowlist;

use crate::error::{CliError, Result};

pub(crate) use codepack_security::allow::{Screened, SuppressedFinding, fingerprint_of, screen};

/// Reads `.codepack-allow` from `project_root`, if present.
///
/// A missing file is not an error and yields no index. A malformed one is an error:
/// silently ignoring it would leave a reviewer believing findings are accepted when they
/// are still being reported, or worse, believing the file is being honoured when a
/// syntax error means it is not.
pub(crate) fn load(project_root: &Path) -> Result<Option<(PathBuf, BTreeMap<String, String>)>> {
    match Allowlist::load(project_root) {
        Ok(None) => Ok(None),
        Ok(Some((path, allowlist))) => Ok(Some((path, allowlist.index()))),
        Err(error) => Err(CliError::message(error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codepack_security::{Finding, FindingKind, ScanResult, ScanSummary};

    fn finding(rule: &str, file: &str, message: &str, severity: &str) -> Finding {
        Finding {
            kind: FindingKind::PotentialSecret,
            severity: severity.to_string(),
            confidence: "high".to_string(),
            file: file.to_string(),
            line: Some(1),
            rule: rule.to_string(),
            message: message.to_string(),
        }
    }

    fn result_with(findings: Vec<Finding>) -> ScanResult {
        ScanResult {
            summary: ScanSummary::default(),
            findings,
        }
    }

    #[test]
    fn a_listed_finding_is_suppressed_and_an_unlisted_one_survives() {
        let listed = finding("secret_like_line", "a.rs", "KEY=<REDACTED>", "critical");
        let other = finding("secret_like_line", "b.rs", "KEY=<REDACTED>", "high");
        let result = result_with(vec![listed.clone(), other.clone()]);

        let mut index = BTreeMap::new();
        index.insert(fingerprint_of(&listed), "reviewed fixture".to_string());

        let screened = screen(&result, Path::new(".codepack-allow"), &index);

        assert_eq!(screened.findings.len(), 1);
        assert_eq!(screened.findings[0].file, "b.rs");
        assert_eq!(screened.suppressed.len(), 1);
        assert_eq!(screened.suppressed[0].file, "a.rs");
        assert_eq!(screened.suppressed[0].reason, "reviewed fixture");
        assert_eq!(screened.suppressed[0].severity, "critical");
    }

    #[test]
    fn the_fingerprint_ignores_the_line_number() {
        // Two findings differing only by line share a fingerprint: adding an import
        // above a finding must not silently invalidate a reviewed entry.
        let mut first = finding("rule", "a.rs", "KEY=<REDACTED>", "high");
        let mut second = first.clone();
        first.line = Some(3);
        second.line = Some(41);
        assert_eq!(fingerprint_of(&first), fingerprint_of(&second));
    }

    #[test]
    fn an_empty_allowlist_suppresses_nothing() {
        let result = result_with(vec![finding("rule", "a.rs", "m", "high")]);
        let screened = screen(&result, Path::new(".codepack-allow"), &BTreeMap::new());
        assert_eq!(screened.findings.len(), 1);
        assert!(screened.suppressed.is_empty());
    }

    #[test]
    fn unfiltered_keeps_everything_and_names_no_allowlist() {
        let result = result_with(vec![finding("rule", "a.rs", "m", "high")]);
        let screened = Screened::unfiltered(&result);
        assert_eq!(screened.findings.len(), 1);
        assert!(screened.suppressed.is_empty());
        assert!(screened.allowlist_path.is_none());
    }

    #[test]
    fn a_malformed_allowlist_is_an_error_rather_than_being_ignored() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(codepack_core::ALLOWLIST_FILE_NAME),
            "[[allow]]\nfingerprint = \"zzzz\"\nreason = \"r\"\n",
        )
        .unwrap();
        assert!(load(dir.path()).is_err());
    }

    #[test]
    fn no_allowlist_file_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load(dir.path()).unwrap().is_none());
    }
}
