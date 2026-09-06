//! `.codepack-allow` — findings a team has reviewed and accepted, so they stop being
//! re-reported on every run.
//!
//! ## Why this exists
//!
//! A scanner that reports the same false positive every single run trains its readers to
//! skim past findings. That habit is how a real secret gets waved through. Suppressing a
//! *reviewed* finding is therefore not a convenience — it is what keeps the remaining
//! findings worth reading.
//!
//! ## Why a finding is identified by a fingerprint, and what is in one
//!
//! The fingerprint is derived from the rule that fired, the file it fired on, and the
//! finding's **already-redacted** message. Every one of those three is a value the
//! product is willing to write into `06_security_scan.json`, a log and the history
//! database, so writing it into a hash is not a new exposure. The secret itself is never
//! an input — invariant I3 holds here the same way it holds everywhere else.
//!
//! **The line number is deliberately not an input.** Including it would invalidate every
//! entry in this file the moment someone adds an import above the finding, which turns a
//! reviewed-and-accepted list into constant churn, and churn is what makes people
//! disable the check. The cost is real and worth stating: two identical secret-shaped
//! strings in the same file under the same rule share one fingerprint, so accepting one
//! accepts both.
//!
//! A cryptographic hash is used rather than a cheap one because a collision here does not
//! produce a wrong number on a screen — it silently withholds a real secret finding, the
//! exact failure this product exists to prevent.
//!
//! ## Scope boundary
//!
//! This module only *describes* the file and computes fingerprints. Who applies it, and
//! where, is documented beside the code that does — see `codepack_security::allow`.
//!
//! The paragraph that used to stand here said the file was honoured only by
//! `codepack-cli`'s `scan` and `verify` and deliberately not inside `codepack-security`
//! or the pipeline. That stopped being true when the boundary moved, and nothing brought
//! it along (audit No. 25). A description of scope does not belong in the module that
//! defines a format: it is the part most likely to change, and the part a reader most
//! needs to be able to trust — "does `.codepack-allow` hide a finding in the bundle I am
//! about to send?" is a security question with a real answer.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The file name looked for in the project root.
pub const ALLOWLIST_FILE_NAME: &str = ".codepack-allow";

/// Domain separator, so a fingerprint recipe change cannot silently keep matching
/// entries written under the old one.
const FINGERPRINT_RECIPE: &str = "codepack-allow-v1";

/// How many hex characters of the digest a fingerprint keeps. 16 hex characters is 64
/// bits: short enough to paste into a TOML file by hand, far more than enough that an
/// accidental collision between two findings in one project is not a practical concern.
const FINGERPRINT_HEX_LEN: usize = 16;

/// Identifies one finding stably across runs, without containing the secret.
///
/// Inputs are the rule id, the file path as the finding reports it, and the finding's
/// already-redacted message. See the module docs for why the line number is excluded.
pub fn fingerprint(rule: &str, file: &str, redacted_message: &str) -> String {
    let mut hasher = Sha256::new();
    // NUL separators: without them, ("ab", "c") and ("a", "bc") would hash identically.
    hasher.update(FINGERPRINT_RECIPE.as_bytes());
    hasher.update([0]);
    hasher.update(rule.as_bytes());
    hasher.update([0]);
    hasher.update(file.as_bytes());
    hasher.update([0]);
    hasher.update(redacted_message.as_bytes());

    let digest = hasher.finalize();
    let mut hex = String::with_capacity(FINGERPRINT_HEX_LEN);
    for byte in digest.iter() {
        if hex.len() >= FINGERPRINT_HEX_LEN {
            break;
        }
        // `write!` into the existing buffer rather than `push_str(&format!(...))`, which
        // allocates a `String` per byte — eight of them per fingerprint, and a fingerprint
        // is computed for every finding, twice over in `verify` (audit No. 35). The same
        // shape `codepack_security::cache::cache_key` already uses.
        //
        // Two hex digits per byte; `FINGERPRINT_HEX_LEN` is even, so this lands exactly.
        // Writing into a `String` cannot fail.
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Why a `.codepack-allow` could not be used.
///
/// Mirrors `config::project::ProjectConfigError`: the diagnosis — which file, where, and
/// what is wrong — is produced once here, and each front end renders it in its own idiom.
#[derive(Debug)]
pub enum AllowlistError {
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    Syntax {
        path: PathBuf,
        /// `" at byte N"`, or empty when the parser could not locate the problem.
        span: String,
        message: String,
    },
    /// An entry carried a fingerprint that cannot have come from [`fingerprint`].
    /// Reported rather than ignored: a typo in a fingerprint means the entry silently
    /// never matches, so the reviewer believes a finding is accepted when it is not.
    MalformedFingerprint { path: PathBuf, value: String },
}

impl std::fmt::Display for AllowlistError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(formatter, "cannot read {}: {source}", path.display())
            }
            Self::Syntax {
                path,
                span,
                message,
            } => write!(
                formatter,
                "{} is not valid{span}: {message}",
                path.display()
            ),
            Self::MalformedFingerprint { path, value } => write!(
                formatter,
                "{} contains a fingerprint that could not have been produced by codepack: \
                 `{value}` (expected {FINGERPRINT_HEX_LEN} lowercase hex characters)",
                path.display()
            ),
        }
    }
}

impl std::error::Error for AllowlistError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::Syntax { .. } | Self::MalformedFingerprint { .. } => None,
        }
    }
}

/// One reviewed finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowEntry {
    /// From `codepack scan --json`, which reports it next to each finding precisely so
    /// nobody has to derive it by hand.
    pub fingerprint: String,
    /// Required, not optional. An allowlist whose entries do not say *why* becomes
    /// unreviewable within a month, and an unreviewable suppression list is
    /// indistinguishable from having switched the scanner off.
    pub reason: String,
}

/// The parsed `.codepack-allow`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allowlist {
    /// Present so a future recipe change can be detected rather than guessed at.
    /// Optional: a file written today without it is still valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<u32>,
    #[serde(default, rename = "allow")]
    pub entries: Vec<AllowEntry>,
}

impl Allowlist {
    /// Reads `.codepack-allow` from `project_root`. A missing file yields `None`, which
    /// is the normal case and never an error.
    pub fn load(
        project_root: &Path,
    ) -> std::result::Result<Option<(PathBuf, Self)>, AllowlistError> {
        let path = project_root.join(ALLOWLIST_FILE_NAME);
        if !path.is_file() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(&path).map_err(|source| AllowlistError::Read {
            path: path.clone(),
            source,
        })?;
        let parsed: Self = toml::from_str(&text).map_err(|error| {
            let span = match error.span() {
                Some(range) => format!(" at byte {}", range.start),
                None => String::new(),
            };
            AllowlistError::Syntax {
                path: path.clone(),
                span,
                message: error.message().to_string(),
            }
        })?;

        for entry in &parsed.entries {
            if !is_well_formed_fingerprint(&entry.fingerprint) {
                return Err(AllowlistError::MalformedFingerprint {
                    path: path.clone(),
                    value: entry.fingerprint.clone(),
                });
            }
        }

        Ok(Some((path, parsed)))
    }

    /// Builds the lookup used while filtering findings: fingerprint to the reason it was
    /// accepted. A `BTreeMap` rather than a `HashMap` so any report that lists what was
    /// suppressed comes out in a stable order.
    pub fn index(&self) -> BTreeMap<String, String> {
        self.entries
            .iter()
            .map(|entry| (entry.fingerprint.clone(), entry.reason.clone()))
            .collect()
    }
}

fn is_well_formed_fingerprint(value: &str) -> bool {
    value.len() == FINGERPRINT_HEX_LEN
        && value.chars().all(|character| {
            character.is_ascii_digit() || character.is_ascii_lowercase() && character <= 'f'
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_across_calls() {
        let first = fingerprint("secret_like_line", "src\\main.rs", "API_KEY=<REDACTED>");
        let second = fingerprint("secret_like_line", "src\\main.rs", "API_KEY=<REDACTED>");
        assert_eq!(first, second);
        assert_eq!(first.len(), FINGERPRINT_HEX_LEN);
        assert!(is_well_formed_fingerprint(&first));
    }

    #[test]
    fn each_input_changes_the_fingerprint() {
        let base = fingerprint("rule", "file", "message");
        assert_ne!(base, fingerprint("other", "file", "message"));
        assert_ne!(base, fingerprint("rule", "other", "message"));
        assert_ne!(base, fingerprint("rule", "file", "other"));
    }

    #[test]
    fn field_boundaries_cannot_be_shifted_between_inputs() {
        // Without the NUL separators these two would hash the same bytes.
        assert_ne!(fingerprint("ab", "c", "d"), fingerprint("a", "bc", "d"));
    }

    #[test]
    fn missing_file_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Allowlist::load(dir.path()).unwrap().is_none());
    }

    #[test]
    fn reads_entries_and_indexes_them() {
        let dir = tempfile::tempdir().unwrap();
        let print = fingerprint("secret_like_line", "tests\\fixture.rs", "TOKEN=<REDACTED>");
        std::fs::write(
            dir.path().join(ALLOWLIST_FILE_NAME),
            format!(
                "schema_version = 1\n\n[[allow]]\nfingerprint = \"{print}\"\n\
                 reason = \"test fixture, not a live credential\"\n"
            ),
        )
        .unwrap();

        let (path, allowlist) = Allowlist::load(dir.path()).unwrap().unwrap();
        assert!(path.ends_with(ALLOWLIST_FILE_NAME));
        assert_eq!(allowlist.schema_version, Some(1));
        assert_eq!(allowlist.entries.len(), 1);

        let index = allowlist.index();
        assert_eq!(
            index.get(&print).map(String::as_str),
            Some("test fixture, not a live credential")
        );
    }

    #[test]
    fn an_unknown_key_is_an_error_naming_it() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(ALLOWLIST_FILE_NAME),
            "[[allow]]\nfingerprint = \"0123456789abcdef\"\nreason = \"r\"\nresaon = \"typo\"\n",
        )
        .unwrap();

        let error = Allowlist::load(dir.path()).unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("resaon"), "unhelpful message: {rendered}");
    }

    #[test]
    fn a_missing_reason_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(ALLOWLIST_FILE_NAME),
            "[[allow]]\nfingerprint = \"0123456789abcdef\"\n",
        )
        .unwrap();
        assert!(Allowlist::load(dir.path()).is_err());
    }

    #[test]
    fn a_typoed_fingerprint_is_rejected_rather_than_never_matching() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(ALLOWLIST_FILE_NAME),
            "[[allow]]\nfingerprint = \"NOT-A-FINGERPRINT\"\nreason = \"r\"\n",
        )
        .unwrap();

        let error = Allowlist::load(dir.path()).unwrap_err();
        assert!(matches!(error, AllowlistError::MalformedFingerprint { .. }));
        assert!(error.to_string().contains("NOT-A-FINGERPRINT"));
    }

    #[test]
    fn uppercase_hex_is_rejected_so_one_finding_has_exactly_one_spelling() {
        assert!(!is_well_formed_fingerprint("0123456789ABCDEF"));
        assert!(is_well_formed_fingerprint("0123456789abcdef"));
    }
}
