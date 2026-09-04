//! Export safety modes, secret redaction, and the heuristic secret detector.
//!
//! Stage S3 scope boundary (binding, see `docs/__arch__/ROADMAP.md` and
//! `.ai/project/12-domain-rules.md`): this crate depends only on `codepack-core`. It
//! takes a caller-supplied file list — it never walks the filesystem in production
//! code (that is `codepack-scanner`'s job; combining the two crates is S9's). It never
//! touches SQLite, the clipboard, or any text-dump call site. It never performs
//! network access or network validation of a secret (invariant I1, permanent):
//! every detector here is a pure, local, in-memory pattern match.

pub mod allow;
pub mod classify;
mod constants;
pub mod error;
pub mod patterns;
pub mod policy;
pub mod pseudonym;
pub mod redact;
pub mod scan;

use pseudonym::{Labels, Placeholders};

/// Redaction for one run, and the only way to reach the pseudonym mode.
///
/// A value rather than a set of free functions because labelled mode has to remember
/// which secrets it has already seen, and that memory belongs to one export: two
/// bundles produced by the same process must not share a numbering, or the second one
/// would silently disclose that a value also appeared in the first.
///
/// [`Redactor::plain`] behaves exactly like the free functions it wraps, byte for byte.
/// That equivalence is what lets the feature default to off with no artifact moving —
/// and it is pinned by a test rather than assumed.
#[derive(Debug)]
pub struct Redactor {
    labels: Option<Labels>,
}

impl Redactor {
    /// One indistinguishable placeholder for everything — what every release before
    /// this one did, and still the default.
    pub fn plain() -> Self {
        Self { labels: None }
    }

    /// Stable per-secret labels (`<REDACTED:s1>`), numbered in the order the run meets
    /// them.
    pub fn labelled() -> Self {
        Self {
            labels: Some(Labels::default()),
        }
    }

    /// Built straight from `Config::redaction_labels`, so a caller never has to branch.
    pub fn new(labelled: bool) -> Self {
        if labelled {
            Self::labelled()
        } else {
            Self::plain()
        }
    }

    pub(crate) fn placeholders(&self) -> Placeholders<'_> {
        match &self.labels {
            Some(labels) => Placeholders::labelled(labels),
            None => Placeholders::plain(),
        }
    }

    /// Content redaction: rewrites file text before it is exported or copied.
    pub fn redact_secrets(&self, text: &str) -> String {
        redact::redact_text_with(text, self.placeholders())
    }

    /// The stronger scan-report redaction, for a single line.
    pub fn redacted_line(&self, line: &str) -> String {
        patterns::keyword::redacted_line_with(line, self.placeholders())
    }

    /// Whether this redactor labels. Reported in artifact headers so a reader knows
    /// what `<REDACTED:s1>` means without having to infer it.
    pub fn is_labelled(&self) -> bool {
        self.labels.is_some()
    }

    /// How many distinct secrets have been labelled so far. `0` in plain mode, which
    /// does not count: an unlabelled run genuinely does not know.
    pub fn distinct_secrets(&self) -> usize {
        self.labels.as_ref().map_or(0, Labels::distinct)
    }
}

impl Default for Redactor {
    fn default() -> Self {
        Self::plain()
    }
}

pub use constants::{
    BALANCED_MODE_EXCLUDED_SUFFIXES, HIGH_RISK_FILENAMES, SAFE_EXPORT_MODES,
    SAFE_MODE_EXCLUDED_SUFFIXES, SENSITIVE_FILENAMES, SENSITIVE_SUFFIXES,
};
pub use error::{Result, SecurityError};
pub use policy::{
    SafetyDecision, SecurityOptions, classify_sensitive_file, is_env_example, normalise_mode,
    should_skip_file_for_safety,
};
pub use pseudonym::REDACTION_PLACEHOLDER_PREFIXES;
pub use redact::redact_secrets;
pub use scan::{
    Finding, FindingKind, ScanOptions, ScanResult, ScanSummary, result_from_findings, scan_project,
    scan_project_with_options,
};

#[cfg(test)]
mod redactor_tests {
    use super::*;

    /// Lines chosen to reach every redaction shape at once: a keyword assignment, a
    /// bare provider signature, an HTTP auth header, a URL password, and a line that
    /// holds no secret at all.
    const SAMPLES: &[&str] = &[
        "API_KEY = \"abc123def456\"",
        "aws = AKIAIOSFODNN7EXAMPLE",
        "curl -H 'Authorization: Basic dXNlcjpwYXNzd29yZA=='",
        "db.connect('postgres://admin:s3cr3tpassword@host/db')",
        "let total = items.len();",
        "SECRET: \"dXNlcjpwYXNzd29yZA==\"",
    ];

    #[test]
    fn plain_mode_is_byte_for_byte_what_the_free_functions_produce() {
        // This equivalence is the reason the feature can default to off without moving
        // a single golden reference. Asserted, not assumed.
        let redactor = Redactor::plain();
        for sample in SAMPLES {
            assert_eq!(redactor.redact_secrets(sample), redact_secrets(sample));
            assert_eq!(
                redactor.redacted_line(sample),
                patterns::keyword::redacted_line(sample)
            );
        }
    }

    #[test]
    fn the_same_secret_in_two_files_carries_the_same_label() {
        // The feature itself: an assistant reading the bundle can see that these two
        // services talk to the same database, without being told the password.
        let redactor = Redactor::labelled();
        let first = redactor.redact_secrets("API_KEY=hunter2correct\n");
        let second = redactor.redact_secrets("password: \"hunter2correct\"\n");

        assert!(first.contains("<REDACTED:s1>"), "{first}");
        assert!(second.contains("<REDACTED:s1>"), "{second}");
        assert_eq!(redactor.distinct_secrets(), 1);
    }

    #[test]
    fn two_different_secrets_never_share_a_label() {
        let redactor = Redactor::labelled();
        let text = redactor.redact_secrets("API_KEY=first-value\ntoken = second-value\n");

        assert!(text.contains("<REDACTED:s1>"), "{text}");
        assert!(text.contains("<REDACTED:s2>"), "{text}");
        assert_eq!(redactor.distinct_secrets(), 2);
    }

    #[test]
    fn a_labelled_run_never_writes_the_value_it_labelled() {
        // Invariant I3 does not weaken because the placeholder got a suffix.
        let redactor = Redactor::labelled();
        for sample in SAMPLES {
            let out = redactor.redact_secrets(sample);
            for secret in [
                "abc123def456",
                "AKIAIOSFODNN7EXAMPLE",
                "dXNlcjpwYXNzd29yZA",
                "s3cr3tpassword",
            ] {
                assert!(
                    !out.contains(secret),
                    "{secret} survived labelled redaction: {out}"
                );
            }
        }
    }

    #[test]
    fn every_placeholder_a_labelled_run_emits_is_one_a_consumer_can_recognise() {
        // `verify` strips these before deciding whether anything credential-shaped is
        // left. A shape missing from the list would read as a leftover secret.
        let redactor = Redactor::labelled();
        for sample in SAMPLES {
            let out = redactor.redact_secrets(sample);
            for fragment in out.split("<REDACTED").skip(1) {
                let placeholder = format!("<REDACTED{fragment}");
                assert!(
                    REDACTION_PLACEHOLDER_PREFIXES
                        .iter()
                        .any(|prefix| placeholder.starts_with(prefix)),
                    "unrecognised placeholder in {out}"
                );
            }
        }
    }
}
