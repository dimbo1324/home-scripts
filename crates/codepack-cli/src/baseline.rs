//! A recorded set of findings that are not news.
//!
//! ## Why this is not `.codepack-allow`
//!
//! The allowlist answers "we looked at this and accepted it", and every entry has to say
//! why — an unreviewable suppression list is indistinguishable from having switched the
//! scanner off. That requirement is what makes it useless for the other question a team
//! has on day one: *there are four hundred findings in this repository, and we want the
//! build to fail on the four hundred and first.*
//!
//! A baseline answers that one. It is generated, not written by hand; it carries no
//! reasons because nobody has reviewed its contents; and it is meant to shrink. Keeping
//! the two files apart keeps the allowlist honest — nobody is tempted to bulk-dump four
//! hundred entries with `reason = "existing"` into the file that is supposed to mean
//! somebody read them.
//!
//! Fingerprints are the same recipe the allowlist uses (`codepack-core::allowlist`), so
//! a finding that moves down a file stays recognised and an entry can be promoted from
//! the baseline into the allowlist by copying one string.

use std::collections::BTreeMap;
use std::path::Path;

use codepack_security::ScanResult;
use serde::{Deserialize, Serialize};

use crate::error::{CliError, Result};

/// Bumped if the recipe or the file's shape changes. Present from the first release, so
/// a later change can be detected rather than guessed at.
const SCHEMA_VERSION: u32 = 1;

/// What every entry's suppression reason reads as.
///
/// Fixed text, and deliberately not reassuring: a baseline entry means "this was here
/// before we started counting", which is not the same as "this is fine".
const BASELINE_REASON: &str = "present when the baseline was recorded (not reviewed)";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BaselineFile {
    pub schema_version: u32,
    /// When it was taken, so a reader can tell a baseline from last year from one taken
    /// this morning.
    pub generated_at: String,
    /// The project it was taken from, for the same reason.
    pub project: String,
    /// Sorted, so the file is stable across runs and reviewable as a diff.
    pub fingerprints: Vec<String>,
}

/// Reads a baseline, returning the index [`crate::allow::screen`] expects.
pub(crate) fn load(path: &Path) -> Result<BTreeMap<String, String>> {
    let text = std::fs::read_to_string(path).map_err(|source| CliError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let parsed: BaselineFile = serde_json::from_str(&text).map_err(|error| {
        CliError::message(format!(
            "{} is not a baseline this build can read: {error}",
            path.display()
        ))
    })?;
    if parsed.schema_version > SCHEMA_VERSION {
        return Err(CliError::message(format!(
            "{} was written by a newer codepack (schema {} against this build's {}); \
             re-record it rather than risking a wrong answer",
            path.display(),
            parsed.schema_version,
            SCHEMA_VERSION
        )));
    }
    Ok(parsed
        .fingerprints
        .into_iter()
        .map(|fingerprint| (fingerprint, BASELINE_REASON.to_string()))
        .collect())
}

/// Records `result`'s findings as the new baseline, returning how many were written.
///
/// Called with the findings that survived the allowlist: what the allowlist already
/// accepts does not need recording twice, and leaving it out keeps the baseline
/// shrinking as entries are promoted.
pub(crate) fn write(path: &Path, project: &Path, result: &ScanResult) -> Result<usize> {
    let mut fingerprints: Vec<String> = result
        .findings
        .iter()
        .map(crate::allow::fingerprint_of)
        .collect();
    fingerprints.sort();
    fingerprints.dedup();

    let file = BaselineFile {
        schema_version: SCHEMA_VERSION,
        generated_at: codepack_core::time::now_human_utc(),
        project: project.display().to_string(),
        fingerprints,
    };
    let body = serde_json::to_string_pretty(&file)
        .map_err(|error| CliError::message(format!("cannot render the baseline: {error}")))?;
    std::fs::write(path, body + "\n").map_err(|source| CliError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(file.fingerprints.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use codepack_security::{Finding, FindingKind, ScanSummary};

    fn finding(rule: &str, file: &str) -> Finding {
        Finding {
            kind: FindingKind::PotentialSecret,
            severity: "high".to_string(),
            confidence: "high".to_string(),
            file: file.to_string(),
            line: Some(1),
            rule: rule.to_string(),
            message: "KEY=<REDACTED>".to_string(),
        }
    }

    fn result_with(findings: Vec<Finding>) -> ScanResult {
        ScanResult {
            summary: ScanSummary::default(),
            findings,
        }
    }

    #[test]
    fn what_is_recorded_is_what_is_later_held_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");
        let old = finding("secret_like_line", "a.rs");
        let result = result_with(vec![old.clone()]);

        assert_eq!(write(&path, dir.path(), &result).unwrap(), 1);

        let index = load(&path).unwrap();
        assert!(index.contains_key(&crate::allow::fingerprint_of(&old)));
        // The reason is fixed and deliberately unreassuring: nobody reviewed this.
        assert!(index.values().all(|reason| reason.contains("not reviewed")));
    }

    #[test]
    fn a_finding_that_arrived_later_is_not_in_the_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");
        let old = finding("secret_like_line", "a.rs");
        write(&path, dir.path(), &result_with(vec![old.clone()])).unwrap();

        let index = load(&path).unwrap();
        let fresh = finding("secret_like_line", "b.rs");
        assert!(!index.contains_key(&crate::allow::fingerprint_of(&fresh)));
    }

    #[test]
    fn the_file_is_stable_and_deduplicated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");
        // The same finding twice, and a second one out of order.
        let repeated = finding("rule", "a.rs");
        let other = finding("rule", "b.rs");
        let count = write(
            &path,
            dir.path(),
            &result_with(vec![other, repeated.clone(), repeated]),
        )
        .unwrap();
        assert_eq!(count, 2, "duplicates collapse");

        let body = std::fs::read_to_string(&path).unwrap();
        let parsed: BaselineFile = serde_json::from_str(&body).unwrap();
        let mut sorted = parsed.fingerprints.clone();
        sorted.sort();
        assert_eq!(parsed.fingerprints, sorted, "written sorted, so diffs read");
        assert_eq!(parsed.schema_version, SCHEMA_VERSION);
        assert!(!parsed.generated_at.is_empty());
    }

    #[test]
    fn an_empty_result_writes_an_empty_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");
        assert_eq!(
            write(&path, dir.path(), &result_with(Vec::new())).unwrap(),
            0
        );
        assert!(load(&path).unwrap().is_empty());
    }

    #[test]
    fn a_missing_baseline_is_an_error_that_names_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let error = load(&dir.path().join("absent.json"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("absent.json"), "{error}");
    }

    #[test]
    fn a_file_that_is_not_a_baseline_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");
        std::fs::write(&path, "{ not json").unwrap();
        assert!(load(&path).is_err());
    }

    /// A newer file may mean a different fingerprint recipe, and answering from it would
    /// hold back findings that are not the ones it recorded.
    #[test]
    fn a_baseline_from_a_newer_build_is_refused_rather_than_guessed_at() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");
        std::fs::write(
            &path,
            format!(
                r#"{{"schema_version": {}, "generated_at": "now", "project": "p", "fingerprints": []}}"#,
                SCHEMA_VERSION + 1
            ),
        )
        .unwrap();

        let error = load(&path).unwrap_err().to_string();
        assert!(error.contains("newer codepack"), "{error}");
    }

    #[test]
    fn a_baseline_from_this_build_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");
        write(
            &path,
            dir.path(),
            &result_with(vec![finding("rule", "a.rs")]),
        )
        .unwrap();
        assert_eq!(load(&path).unwrap().len(), 1);
    }
}
