//! Shannon entropy detection (BLUEPRINT §E.2, 🎯 new capability — legacy has no
//! entropy analysis at all). Catches random-looking secrets that carry **no** keyword
//! context, which the keyword cascade structurally cannot see.
//!
//! `H(s) = -Σ p_i·log2(p_i)` bits/char over a candidate token's character-frequency
//! distribution. Thresholds from BLUEPRINT §E.2: base64-like (`H ≥ 4.0`, length `≥ 20`),
//! hex-like (`H ≥ 3.0`, length `≥ 32`).
//!
//! **Alphabet gate is structural, not a separate check.** Candidate tokens are produced
//! by splitting the line on any character outside `[A-Za-z0-9+/=_-]`; every resulting
//! token is therefore 100%-alphabet-conformant by construction — there is no partial-
//! conformance threshold to invent (BLUEPRINT gives none).
//!
//! **This is the single highest false-positive-risk detector in the crate** — base64
//! blobs, hashes, UUIDs, and minified code are all naturally high-entropy. Two
//! safeguards keep it conservative, both authored (not given verbatim by BLUEPRINT,
//! which states only the two thresholds above):
//!
//! - a bare qualifying token (no adjacent context) is capped at `low` confidence — an
//!   additive heuristic, never discarded outright;
//! - a token immediately preceded (ignoring whitespace) by `=`/`:` or a secret-shaped
//!   assignment ([`crate::patterns::keyword::has_secret_assignment`]) is boosted one
//!   confidence bucket; a token that clears its threshold by a wide margin starts at
//!   `medium` instead of `low` before that boost is applied, so `medium → high` is
//!   reachable, but **only** with context — without context the ceiling stays `medium`.

use std::collections::HashMap;

use crate::patterns::keyword::has_secret_assignment;

/// Every entropy threshold, for [`crate::fingerprint`]. Listed here so a new one has
/// to be added in the same file it is declared in, where the omission is visible.
pub(crate) fn thresholds() -> [f64; 8] {
    [
        BASE64_MIN_LENGTH as f64,
        BASE64_MIN_ENTROPY,
        BASE64_STRONG_LENGTH as f64,
        BASE64_STRONG_ENTROPY,
        HEX_MIN_LENGTH as f64,
        HEX_MIN_ENTROPY,
        HEX_STRONG_LENGTH as f64,
        HEX_STRONG_ENTROPY,
    ]
}

const BASE64_MIN_LENGTH: usize = 20;
const BASE64_MIN_ENTROPY: f64 = 4.0;
const BASE64_STRONG_LENGTH: usize = 40;
const BASE64_STRONG_ENTROPY: f64 = 4.8;

const HEX_MIN_LENGTH: usize = 32;
const HEX_MIN_ENTROPY: f64 = 3.0;
const HEX_STRONG_LENGTH: usize = 48;
const HEX_STRONG_ENTROPY: f64 = 3.6;

fn is_candidate_alphabet_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-')
}

fn shannon_entropy(token: &str) -> f64 {
    let len = token.chars().count();
    if len == 0 {
        return 0.0;
    }
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in token.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    counts.values().fold(0.0, |acc, &count| {
        let p = count as f64 / len as f64;
        acc - p * p.log2()
    })
}

/// A run of [`is_candidate_alphabet_char`] characters with its byte offsets in the
/// original line, so callers can look at what precedes it for context.
struct Token<'a> {
    start: usize,
    end: usize,
    text: &'a str,
}

fn tokenize(line: &str) -> Vec<Token<'_>> {
    let mut tokens = Vec::new();
    let mut start: Option<usize> = None;
    for (idx, c) in line.char_indices() {
        if is_candidate_alphabet_char(c) {
            if start.is_none() {
                start = Some(idx);
            }
        } else if let Some(s) = start.take() {
            tokens.push(Token {
                start: s,
                end: idx,
                text: &line[s..idx],
            });
        }
    }
    if let Some(s) = start {
        tokens.push(Token {
            start: s,
            end: line.len(),
            text: &line[s..],
        });
    }
    tokens
}

fn base_bucket(entropy: f64, len: usize) -> Option<&'static str> {
    let base64_hit = len >= BASE64_MIN_LENGTH && entropy >= BASE64_MIN_ENTROPY;
    let hex_hit = len >= HEX_MIN_LENGTH && entropy >= HEX_MIN_ENTROPY;
    if !base64_hit && !hex_hit {
        return None;
    }
    let strong = (len >= BASE64_STRONG_LENGTH && entropy >= BASE64_STRONG_ENTROPY)
        || (len >= HEX_STRONG_LENGTH && entropy >= HEX_STRONG_ENTROPY);
    Some(if strong { "medium" } else { "low" })
}

fn boost(bucket: &'static str) -> &'static str {
    match bucket {
        "low" => "medium",
        "medium" => "high",
        other => other,
    }
}

fn has_context(line: &str, token_start: usize) -> bool {
    let prefix = &line[..token_start];
    let trimmed = prefix.trim_end();
    if trimmed.ends_with('=') || trimmed.ends_with(':') {
        return true;
    }
    has_secret_assignment(prefix)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntropyMatch {
    pub confidence: &'static str,
    pub start: usize,
    pub end: usize,
}

/// Runs unconditionally over every candidate line — never gated by the
/// `aho-corasick` prefilter, since an entropy-only secret carries no literal the
/// prefilter's fixed alphabet could anchor on (documented in `patterns::prefilter`).
pub fn entropy_findings(line: &str) -> Vec<EntropyMatch> {
    tokenize(line)
        .into_iter()
        .filter_map(|token| {
            let entropy = shannon_entropy(token.text);
            let bucket = base_bucket(entropy, token.text.chars().count())?;
            let confidence = if has_context(line, token.start) {
                boost(bucket)
            } else {
                bucket
            };
            Some(EntropyMatch {
                confidence,
                start: token.start,
                end: token.end,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_entropy_repeated_string_is_not_flagged() {
        let line = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(entropy_findings(line).is_empty());
    }

    #[test]
    fn plain_english_prose_is_not_flagged() {
        let line = "the quick brown fox jumps over the lazy dog repeatedly today";
        assert!(entropy_findings(line).is_empty());
    }

    #[test]
    fn bare_high_entropy_base64_blob_caps_at_low() {
        // Length 30 clears the base64 "hit" floor (len >= 20, H >= 4.0) but stays
        // below the "strong" floor (len >= 40), so a bare (no-context) token here must
        // cap at `low`, not escalate to `medium`/`high` on entropy alone.
        let line = "aZ9kQ2wLp7xR4tY8mN1cJ6hF3sD0eU";
        let findings = entropy_findings(line);
        assert!(!findings.is_empty());
        assert!(findings.iter().all(|m| m.confidence == "low"));
    }

    #[test]
    fn context_boosts_confidence_by_one_bucket() {
        let line = "api_key = \"zQ8mK2pXvL9wR4tY7bN1cJ6hF3sD0aE5gU8iO2kM4nP7qW1xZ9\"";
        let findings = entropy_findings(line);
        assert!(!findings.is_empty());
        assert!(
            findings
                .iter()
                .any(|m| m.confidence == "medium" || m.confidence == "high")
        );
    }

    #[test]
    fn hex_like_long_token_is_flagged() {
        let line = "checksum: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4";
        let findings = entropy_findings(line);
        assert!(!findings.is_empty());
    }

    #[test]
    fn short_token_below_length_floor_is_not_flagged() {
        let line = "id = ab12cd34";
        assert!(entropy_findings(line).is_empty());
    }

    #[test]
    fn shannon_entropy_of_single_repeated_char_is_zero() {
        assert_eq!(shannon_entropy("aaaaaaaa"), 0.0);
    }

    #[test]
    fn shannon_entropy_of_empty_string_is_zero() {
        assert_eq!(shannon_entropy(""), 0.0);
    }
}
