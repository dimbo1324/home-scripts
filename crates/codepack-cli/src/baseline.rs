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
