//! A fingerprint of what the detectors are, so a cache cannot outlive them.
//!
//! ## The problem this solves
//!
//! [`crate::cache::cache_key`] has to change whenever detection changes, or a file
//! already in the cache keeps answering with the old, weaker verdict — the improvement
//! ships and silently does nothing. That used to rest on two things that do not work: a
//! hand-bumped string constant, and `CARGO_PKG_VERSION`, which in this workspace is
//! `2.0.0-dev` and does not move between builds. In practice a detector change had to be
//! remembered by a person, every time.
//!
//! Invariant I9 protects the detector's *thresholds*; nothing protected the fact that new
//! rules were applied at all. That is the worst kind of regression for this product,
//! because it is invisible: the corpus test passes, the golden test passes, and real
//! scans keep answering from yesterday's cache (audit No. 19).
//!
//! ## Why it hashes `Debug` renderings
//!
//! Because the alternative is a hand-written serializer per table, which is the same
//! failure again one level down: add a field to `TokenPattern` or a variant to
//! `CharClass`, forget to add it to the serializer, and the fingerprint stops noticing.
//! `Debug` is derived, so it covers every field and every variant by construction, and it
//! changes exactly when the data does.
//!
//! The cost is that a change in how the standard library formats `Debug` would invalidate
//! every cached entry once. That is the harmless direction: a cache thrown away too often
//! costs a rescan, a cache kept too long costs a missed secret.
//!
//! ## What it cannot see
//!
//! Behaviour that lives in code rather than data: the body of a `RiskyCodeRule::matches`
//! function, or a change in how the cascade weighs its evidence.
//! [`crate::cache::DETECTOR_RECIPE`] stays for exactly that — a manual bump for a change a
//! fingerprint genuinely cannot observe — and now covers only that.

use std::sync::LazyLock;

use sha2::{Digest, Sha256};

/// Hex SHA-256 over every detector table, computed once per process.
pub(crate) static DETECTOR_FINGERPRINT: LazyLock<String> = LazyLock::new(compute);

fn compute() -> String {
    let mut hasher = Sha256::new();

    // A NUL after each field: it cannot occur in any `Debug` rendering here, so two
    // different tables cannot concatenate into the same digest.
    let mut field = |bytes: &[u8]| {
        hasher.update(bytes);
        hasher.update([0]);
    };

    field(b"keyword-roots");
    field(format!("{:?}", crate::patterns::keyword_scan::every_root()).as_bytes());

    field(b"provider-patterns");
    field(format!("{:?}", *crate::patterns::provider::PROVIDER_PATTERNS).as_bytes());

    field(b"risky-code");
    // Field by field rather than by `Debug` on the whole rule: `RiskyCodeRule::matches`
    // is a function pointer, and its `Debug` is an address — it moves between processes,
    // which would make the fingerprint unstable and throw the cache away on every run.
    // Its *body* is therefore among the changes only `DETECTOR_RECIPE` can announce.
    for rule in crate::patterns::risky_code::RISKY_CODE_PATTERNS {
        field(rule.severity.as_bytes());
        field(rule.rule_id.as_bytes());
        // Part of the reported message, so a reworded rule is a different verdict as far
        // as a cached message is concerned.
        field(rule.explanation.as_bytes());
    }

    field(b"entropy-thresholds");
    field(format!("{:?}", crate::patterns::entropy::thresholds()).as_bytes());

    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest.iter() {
        use std::fmt::Write as _;
        // Writing into a String cannot fail.
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fingerprint is what the cache key is built from, so it must be identical in
    /// every process of the same build — a value that moved between runs would throw the
    /// whole cache away on each one.
    #[test]
    fn the_fingerprint_is_stable_within_a_build() {
        assert_eq!(compute(), compute());
        assert_eq!(*DETECTOR_FINGERPRINT, compute());
    }

    #[test]
    fn the_fingerprint_is_a_full_sha256_in_hex() {
        assert_eq!(DETECTOR_FINGERPRINT.len(), 64);
        assert!(DETECTOR_FINGERPRINT.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    /// The tables it reads are non-empty and their renderings really do carry rule
    /// identities — otherwise the digest above would be a constant dressed up as a
    /// fingerprint.
    #[test]
    fn every_table_actually_contributes_something() {
        let roots = format!("{:?}", crate::patterns::keyword_scan::every_root());
        let providers = format!("{:?}", *crate::patterns::provider::PROVIDER_PATTERNS);
        let risky = crate::patterns::risky_code::RISKY_CODE_PATTERNS
            .iter()
            .map(|rule| rule.rule_id)
            .collect::<Vec<_>>()
            .join(",");
        let entropy = format!("{:?}", crate::patterns::entropy::thresholds());

        assert!(roots.contains("SECRET"), "{roots}");
        assert!(providers.contains("rule_id"), "{providers}");
        assert!(!risky.is_empty(), "{risky}");
        // A threshold change is what invariant I9 is about; it must reach the digest.
        assert!(entropy.contains("4.0"), "{entropy}");
    }

    /// A changed table must produce a different digest. Demonstrated on the same hashing
    /// shape rather than by mutating the real tables, which are `const`.
    #[test]
    fn a_different_table_hashes_differently() {
        let of = |tables: &[&str]| {
            let mut hasher = Sha256::new();
            for table in tables {
                hasher.update(table.as_bytes());
                hasher.update([0]);
            }
            format!("{:x}", hasher.finalize())
        };

        assert_ne!(
            of(&["roots", "providers"]),
            of(&["roots", "providers-with-one-more-rule"])
        );
        // And the NUL separator does its job: two fields cannot be re-split into the
        // same digest by moving the boundary between them.
        assert_ne!(of(&["ab", "c"]), of(&["a", "bc"]));
    }
}
