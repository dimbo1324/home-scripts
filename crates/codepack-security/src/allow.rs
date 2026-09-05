//! Applying `.codepack-allow` to a scan result.
//!
//! `codepack-core::allowlist` owns the file format and the fingerprint recipe. This
//! module owns the one thing that needs a [`Finding`] to express: splitting a result
//! into what a reviewer has accepted and what is still outstanding.
//!
//! ## Why it lives here rather than in a front end
//!
//! It began in `codepack-cli`, which meant `scan` and `verify` honoured the file while
//! the export pipeline and the ~30 reports did not (Q26). A team that had reviewed a
//! finding still found it staring back out of the bundle they shipped — two answers to
//! one question, from one product. The rule is the same rule everywhere, so it belongs
//! beside the findings it filters, one layer below both front ends and the engine.
//!
//! **A suppressed finding is counted, never silently dropped.** A scanner that quietly
//! hides things is worse than a noisy one, because a reader cannot tell "nothing was
//! found" from "something was found and hidden from you". Every caller is handed the
//! suppressed list and the path of the file that did it, and is expected to say so.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use codepack_core::allowlist::{self, Allowlist, AllowlistError};
use serde::Serialize;

use crate::scan::{Finding, ScanResult};

/// A finding that was listed in `.codepack-allow`, kept so it can be reported.
#[derive(Debug, Clone, Serialize)]
pub struct SuppressedFinding {
    pub fingerprint: String,
    /// The justification the file itself gives. Echoed back so a reader can judge
    /// whether the acceptance still holds without opening the file.
    pub reason: String,
    pub rule: String,
    pub file: String,
    pub severity: String,
}

/// A scan result after the allowlist has been applied.
pub struct Screened {
    /// Findings that were **not** listed. These drive every report and every exit code.
    pub findings: Vec<Finding>,
    pub suppressed: Vec<SuppressedFinding>,
    /// Where the allowlist was read from, when one was used at all.
    pub allowlist_path: Option<PathBuf>,
}

impl Screened {
    /// Every finding, unfiltered — used when no allowlist exists, which is the common
    /// case and must not pay for the feature.
    pub fn unfiltered(result: &ScanResult) -> Self {
        Self {
            findings: result.findings.clone(),
            suppressed: Vec::new(),
            allowlist_path: None,
        }
    }

    /// Whether anything was actually suppressed. Callers use it to decide whether they
    /// owe the reader a sentence about it.
    pub fn has_suppressions(&self) -> bool {
        !self.suppressed.is_empty()
    }

    /// The result rebuilt from the surviving findings, with the summary counts
    /// recomputed so they describe what is actually in it.
    ///
    /// Recomputing rather than subtracting: the summary counts findings by kind, and a
    /// subtraction would need the suppressed list to carry the kind too, which is one
    /// more thing that can silently disagree with the findings themselves.
    pub fn to_result(&self) -> ScanResult {
        crate::scan::result_from_findings(self.findings.clone())
    }
}

/// The fingerprint for one finding.
///
/// `Finding::message` is already redacted before it ever reaches a caller (invariant
/// I3), so hashing it introduces no exposure that writing the finding to
/// `06_security_scan.json` does not already accept.
pub fn fingerprint_of(finding: &Finding) -> String {
    allowlist::fingerprint(&finding.rule, &finding.file, &finding.message)
}

/// Splits `result`'s findings into those that survive and those the allowlist accepts.
pub fn screen(
    result: &ScanResult,
    allowlist_path: &Path,
    index: &BTreeMap<String, String>,
) -> Screened {
    let mut findings = Vec::new();
    let mut suppressed = Vec::new();

    for finding in &result.findings {
        let print = fingerprint_of(finding);
        match index.get(&print) {
            Some(reason) => suppressed.push(SuppressedFinding {
                fingerprint: print,
                reason: reason.clone(),
                rule: finding.rule.clone(),
                file: finding.file.clone(),
                severity: finding.severity.clone(),
            }),
            None => findings.push(finding.clone()),
        }
    }

    Screened {
        findings,
        suppressed,
        allowlist_path: Some(allowlist_path.to_path_buf()),
    }
}

/// Reads `.codepack-allow` from `project_root` and applies it.
///
/// A missing file is not an error and leaves the result untouched. A malformed one *is*
/// an error: silently ignoring it would leave a reviewer believing findings are accepted
/// when they are still reported, or believing the file is honoured when a syntax error
/// means it is not.
pub fn screen_project(
    project_root: &Path,
    result: &ScanResult,
) -> Result<Screened, AllowlistError> {
    match Allowlist::load(project_root)? {
        Some((path, allowlist)) => Ok(screen(result, &path, &allowlist.index())),
        None => Ok(Screened::unfiltered(result)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{FindingKind, ScanSummary};

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
        let result = result_with(vec![listed.clone(), other]);

        let mut index = BTreeMap::new();
        index.insert(fingerprint_of(&listed), "reviewed fixture".to_string());

        let screened = screen(&result, Path::new(".codepack-allow"), &index);

        assert_eq!(screened.findings.len(), 1);
        assert_eq!(screened.findings[0].file, "b.rs");
        assert_eq!(screened.suppressed.len(), 1);
        assert_eq!(screened.suppressed[0].file, "a.rs");
        assert_eq!(screened.suppressed[0].reason, "reviewed fixture");
        assert!(screened.has_suppressions());
    }

    #[test]
    fn an_empty_allowlist_suppresses_nothing() {
        let result = result_with(vec![finding("rule", "a.rs", "m", "high")]);
        let screened = screen(&result, Path::new(".codepack-allow"), &BTreeMap::new());
        assert_eq!(screened.findings.len(), 1);
        assert!(!screened.has_suppressions());
    }

    #[test]
    fn unfiltered_keeps_everything_and_names_no_allowlist() {
        let result = result_with(vec![finding("rule", "a.rs", "m", "high")]);
        let screened = Screened::unfiltered(&result);
        assert_eq!(screened.findings.len(), 1);
        assert!(screened.allowlist_path.is_none());
    }

    /// The summary has to describe the list it sits above, or a report contradicts
    /// itself in its own header.
    #[test]
    fn the_rebuilt_summary_counts_only_what_survived() {
        let mut sensitive = finding("sensitive_filename", ".env", "m", "critical");
        sensitive.kind = FindingKind::SensitiveFile;
        let secret = finding("secret_like_line", "a.rs", "KEY=<REDACTED>", "high");
        let mut risky = finding("eval", "b.rs", "m", "medium");
        risky.kind = FindingKind::RiskyCode;

        let result = ScanResult {
            // Deliberately wrong going in: the point is that it is recomputed, not copied.
            summary: ScanSummary {
                sensitive_files: 99,
                potential_secrets: 99,
                risky_code: 99,
                total_findings: 99,
            },
            findings: vec![sensitive, secret.clone(), risky],
        };

        let mut index = BTreeMap::new();
        index.insert(fingerprint_of(&secret), "accepted".to_string());
        let screened = screen(&result, Path::new(".codepack-allow"), &index);
        let rebuilt = screened.to_result();

        assert_eq!(rebuilt.findings.len(), 2);
        assert_eq!(rebuilt.summary.sensitive_files, 1);
        assert_eq!(rebuilt.summary.potential_secrets, 0);
        assert_eq!(rebuilt.summary.risky_code, 1);
        assert_eq!(rebuilt.summary.total_findings, 2);
    }

    /// The line number is excluded from the fingerprint on purpose: adding an import
    /// above a finding must not silently invalidate a reviewed entry.
    #[test]
    fn the_fingerprint_ignores_the_line_number() {
        let mut first = finding("rule", "a.rs", "KEY=<REDACTED>", "high");
        let mut second = first.clone();
        first.line = Some(3);
        second.line = Some(41);
        assert_eq!(fingerprint_of(&first), fingerprint_of(&second));
    }

    #[test]
    fn a_project_without_an_allowlist_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let result = result_with(vec![finding("rule", "a.rs", "m", "high")]);
        let screened = screen_project(dir.path(), &result).unwrap();
        assert_eq!(screened.findings.len(), 1);
        assert!(screened.allowlist_path.is_none());
    }

    #[test]
    fn a_project_allowlist_is_read_and_applied() {
        let dir = tempfile::tempdir().unwrap();
        let listed = finding("secret_like_line", "a.rs", "KEY=<REDACTED>", "critical");
        std::fs::write(
            dir.path().join(codepack_core::ALLOWLIST_FILE_NAME),
            format!(
                "[[allow]]\nfingerprint = \"{}\"\nreason = \"a test fixture\"\n",
                fingerprint_of(&listed)
            ),
        )
        .unwrap();

        let screened = screen_project(dir.path(), &result_with(vec![listed])).unwrap();
        assert!(screened.findings.is_empty());
        assert_eq!(screened.suppressed.len(), 1);
        assert!(screened.allowlist_path.is_some());
    }

    /// Ignoring a broken file would leave a reviewer believing findings are accepted
    /// when they are still reported.
    #[test]
    fn a_malformed_allowlist_is_an_error_rather_than_being_ignored() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(codepack_core::ALLOWLIST_FILE_NAME),
            "[[allow]]\nfingerprint = \"zzzz\"\nreason = \"r\"\n",
        )
        .unwrap();
        assert!(screen_project(dir.path(), &result_with(Vec::new())).is_err());
    }
}
