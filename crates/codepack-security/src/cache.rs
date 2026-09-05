//! Reusing the result of scanning a file whose bytes have not changed.
//!
//! ## What is cacheable and what is not
//!
//! A finding is either derived from a file's **contents** — the keyword cascade,
//! provider signatures, entropy, risky-code shapes — or from its **name**, which is the
//! `sensitive_filename` rule alone. Only the first kind is cached. Two files with
//! identical bytes and different names genuinely have different findings, and a cache
//! keyed on content that also served the name-derived one would report `.env`'s
//! severity for a copy called `notes.txt`.
//!
//! ## What the key has to cover
//!
//! The bytes, and everything about *this build* that decides what those bytes mean. A
//! cache keyed on content alone is a trap: improve a detector, and every file already in
//! the cache keeps answering with the old, weaker verdict — the improvement ships and
//! silently does nothing. [`cache_key`] therefore mixes in [`DETECTOR_RECIPE`], which
//! **must be bumped whenever detection changes**, the crate version, and the scan
//! options that change a verdict.
//!
//! ## Who owns the storage
//!
//! Not this crate. `codepack-security` sits beside `codepack-storage` rather than above
//! it, and reaching sideways for a database would break the layering. The scan is handed
//! a [`FileScanCache`] and neither knows nor cares what is behind it; the engine, which
//! legitimately depends on both, supplies one backed by SQLite.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::scan::FindingKind;

/// Bump when any detector's behaviour changes — a new rule, a changed threshold, a
/// different message. Forgetting to is how a cache serves yesterday's verdict forever.
const DETECTOR_RECIPE: &str = "codepack-security content detectors v1";

/// One content-derived finding, without the file it was found in.
///
/// The path is deliberately absent: it is what makes an otherwise identical file
/// different, so storing it would make the entry unusable for the next copy of the same
/// bytes. The caller puts the path back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedFinding {
    pub kind: FindingKind,
    pub severity: String,
    pub confidence: String,
    pub line: usize,
    pub rule: String,
    /// Already redacted when it was first produced (invariant I3), and stored that way:
    /// nothing here ever holds a secret value.
    pub message: String,
}

/// Somewhere previously scanned content can be looked up and recorded.
///
/// `Sync` because the scan is parallel. Implementations are expected to make `store`
/// cheap — the scan calls it once per newly scanned file, from a worker thread, so an
/// implementation that writes to a database on every call serialises the whole pass.
/// Buffering and flushing afterwards is the intended shape.
pub trait FileScanCache: Sync {
    /// The findings recorded for this key, if any.
    fn lookup(&self, key: &str) -> Option<Vec<CachedFinding>>;

    /// Record the findings for a key that was not there. An empty slice is a real
    /// answer — "these bytes contain nothing" — and is worth storing.
    fn store(&self, key: &str, findings: &[CachedFinding]);
}

/// The key for one file's content under the current build and options.
///
/// Hex-encoded SHA-256 over the recipe, the crate version, the option bits and the raw
/// bytes, NUL-separated so no two different inputs can be concatenated into the same
/// string.
pub fn cache_key(raw: &[u8], strict_token_checksums: bool) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DETECTOR_RECIPE.as_bytes());
    hasher.update([0]);
    hasher.update(env!("CARGO_PKG_VERSION").as_bytes());
    hasher.update([0]);
    hasher.update([u8::from(strict_token_checksums)]);
    hasher.update([0]);
    hasher.update(raw);

    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest.iter() {
        use std::fmt::Write as _;
        // Writing into a String cannot fail.
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// The stored form of one file's entry.
///
/// The encoding lives here, beside the type, so a store never has to know the shape of
/// what it is keeping — and so a format change has exactly one place to happen.
pub fn encode(findings: &[CachedFinding]) -> Option<String> {
    serde_json::to_string(findings).ok()
}

/// The inverse of [`encode`].
///
/// `None` for anything that no longer parses: such a row was written by a different
/// build, and the worst it can cost is one file being scanned again.
pub fn decode(stored: &str) -> Option<Vec<CachedFinding>> {
    serde_json::from_str(stored).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(line: usize, rule: &str) -> CachedFinding {
        CachedFinding {
            kind: FindingKind::PotentialSecret,
            severity: "high".to_string(),
            confidence: "high".to_string(),
            line,
            rule: rule.to_string(),
            message: "KEY=<REDACTED>".to_string(),
        }
    }

    #[test]
    fn the_same_bytes_under_the_same_options_key_the_same() {
        assert_eq!(cache_key(b"hello", false), cache_key(b"hello", false));
    }

    #[test]
    fn different_bytes_key_differently() {
        assert_ne!(cache_key(b"hello", false), cache_key(b"hellp", false));
    }

    /// The trap this key exists to avoid, in miniature: an option that changes a verdict
    /// must change the key, or a run with it on would be served a verdict computed with
    /// it off.
    #[test]
    fn an_option_that_changes_a_verdict_changes_the_key() {
        assert_ne!(cache_key(b"hello", false), cache_key(b"hello", true));
    }

    #[test]
    fn a_key_is_hex_and_fixed_width() {
        let key = cache_key(b"anything", false);
        assert_eq!(key.len(), 64, "sha-256 in hex");
        assert!(key.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn empty_content_still_has_a_key() {
        // A file with nothing in it is the most cacheable case there is.
        assert_eq!(cache_key(b"", false).len(), 64);
    }

    #[test]
    fn encoding_round_trips() {
        let findings = vec![finding(3, "secret_like_line"), finding(9, "github-token")];
        let stored = encode(&findings).expect("serialisable");
        assert_eq!(decode(&stored).as_deref(), Some(findings.as_slice()));
    }

    #[test]
    fn an_empty_entry_round_trips_too() {
        // "These bytes contain nothing" is the answer worth most, being the common one.
        let stored = encode(&[]).expect("serialisable");
        assert_eq!(decode(&stored), Some(Vec::new()));
    }

    #[test]
    fn a_row_from_another_build_is_ignored_rather_than_fatal() {
        assert!(decode("not json at all").is_none());
        assert!(decode(r#"[{"kind":"unheard_of_kind"}]"#).is_none());
    }
}
