//! Keyword-based secret detection, ported from legacy `reports/insights/security.py`
//! (`_secret_confidence`, `redacted_line`) plus the shared `constants.py` patterns.
//!
//! The keyword roots themselves, and the matching of the `key = value` shapes built on
//! them, live in [`crate::patterns::keyword_scan`]; this module is the cascade and the
//! redaction policy layered over them. [`crate::redact::redact_secrets`] shares the same
//! span finders rather than restating the shapes.

use crate::patterns::keyword_scan::{
    self, ASSIGNMENT_ROOTS, REDACT_ROOTS, SCAN_ROOTS, contains_root, find_keyword_assignments,
};
use crate::pseudonym::Placeholders;

/// Every keyword/value span on the line — legacy's first `SECRET_PATTERNS` entry —
/// followed by every `BEARER <token>` span, the second entry.
///
/// Content redaction replaces exactly these ranges, in this order.
pub(crate) fn find_secret_spans(line: &str) -> Vec<(usize, usize)> {
    let mut spans = find_keyword_assignments(line, REDACT_ROOTS);
    spans.extend(keyword_scan::find_bearer_tokens(line));
    spans
}

/// True when the line carries a keyword with a value, or a bearer token — legacy's
/// `SECRET_PATTERNS` as a yes/no question. Yields `high` confidence.
fn has_secret_with_value(line: &str) -> bool {
    !find_secret_spans(line).is_empty()
}

/// Legacy `SECRET_KEY_PATTERN`: a bare keyword mention, no value shape required. A line
/// matching this — outside a comment — yields `low` confidence.
pub(crate) fn mentions_scan_keyword(line: &str) -> bool {
    contains_root(line, &SCAN_ROOTS)
}

/// Legacy `_ASSIGNMENT_SECRET_RE`: a secret-shaped key immediately followed by `:`/`=`,
/// with no requirement on the value itself — deliberately looser than
/// [`has_secret_with_value`], yielding `medium` confidence.
pub(crate) fn has_secret_assignment(line: &str) -> bool {
    keyword_scan::has_assignment_operator_after_root(line, &ASSIGNMENT_ROOTS)
}

/// Legacy `_PRIVATE_KEY_RE`: a PEM private-key header. The single `critical`-tier
/// keyword rule.
///
/// The shape lives in `patterns::token_scan` and is shared with the `pem-private-key`
/// provider signature — one description, two rule identities, rather than the same
/// pattern written twice.
fn is_private_key_header(line: &str) -> bool {
    crate::patterns::provider::is_pem_private_key(line)
}

/// Legacy `_SCANNER_CODE_HINTS`, respelled to this crate's own Rust identifiers. Any
/// line containing one of these substrings is exempted from every detector (keyword,
/// provider, entropy) — this is what keeps the scanner from flagging its own source.
pub(crate) const SELF_PROTECTION_HINTS: &[&str] = &[
    // Legacy's own identifier names, kept verbatim: this crate's source is not the only
    // thing that trips the scanner -- any project that vendored or referenced the
    // original Python scanner mentions these too, and legacy exempted them by name.
    "SECRET_PATTERNS",
    "SECRET_KEY_PATTERN",
    "redact_secrets",
    "REDACT_KEYWORDS",
    "SCAN_KEYWORDS",
    "ASSIGNMENT_SECRET_RE",
    "PRIVATE_KEY_RE",
    "PROVIDER_PATTERNS",
    // This crate's current identifiers, which replaced several of the names above when
    // the regexes became data. Without these, the scanner flags its own source.
    "REDACT_ROOTS",
    "SCAN_ONLY_ROOTS",
    "ASSIGNMENT_ONLY_ROOTS",
    "find_keyword_assignments",
    "find_secret_spans",
];

/// `true` when `line` mentions one of this crate's own pattern identifiers and must
/// therefore be exempted from every detector, not only the keyword cascade.
pub fn is_self_protected(line: &str) -> bool {
    SELF_PROTECTION_HINTS.iter().any(|hint| line.contains(hint))
}

/// The five-level confidence cascade, ported from legacy `_secret_confidence`. Order is
/// load-bearing: self-protection first, then `critical` → `high` → `medium` → `low`,
/// first match wins. Returns `None` when nothing qualifies.
pub fn secret_confidence(line: &str) -> Option<&'static str> {
    if is_self_protected(line) {
        return None;
    }
    if is_private_key_header(line) {
        return Some("critical");
    }
    if has_secret_with_value(line) {
        return Some("high");
    }
    if has_secret_assignment(line) {
        return Some("medium");
    }
    let trimmed = line.trim_start();
    if mentions_scan_keyword(line)
        && !(trimmed.starts_with('#') || trimmed.starts_with("//") || trimmed.starts_with('*'))
    {
        return Some("low");
    }
    None
}

/// Legacy `redacted_line`: a second, stronger redaction pass specific to scan reports.
/// First applies [`crate::redact::redact_secrets`] (the content-level pass), then — if
/// the result still mentions a scan keyword — collapses the rest of the line using the
/// same split-on-first-`=`-or-`:` logic. Every [`crate::scan::Finding`] message must go
/// through this function (invariant I3): the raw matched substring never reaches the
/// output, only the key name survives.
pub fn redacted_line(line: &str) -> String {
    redacted_line_with(line, Placeholders::plain())
}

/// [`redacted_line`] with an explicit placeholder policy — the form the pseudonym
/// feature calls.
pub(crate) fn redacted_line_with(line: &str, placeholders: Placeholders<'_>) -> String {
    let redacted = crate::redact::redact_line_with(line, placeholders);
    if mentions_scan_keyword(&redacted) {
        return redact_value_after_separator(
            &redacted,
            KeySpacing::Trim,
            // No separator on the line means there is no key name worth keeping, so the
            // whole line collapses rather than leaking an unidentifiable fragment. Never
            // labelled: the "secret" here is a whole line of source, so a label would
            // claim two lines are the same credential when all they share is their text.
            crate::pseudonym::line_placeholder,
            placeholders,
        );
    }
    redacted.trim().to_string()
}

/// Length at which an unbroken alphanumeric run stops being plausible as a word a
/// person typed. Real key names break at `_`, `-`, `.` and spaces, so their runs are
/// short; encoded values do not break at all.
///
/// Set to 12 rather than something larger because the run only has to be long enough to
/// carry a secret: base64 of an 11-byte password is 16 characters, and the first version
/// of this fix used a 16-character threshold that a 15-character run walked straight
/// through. The cost of being wrong in this direction is a masked word in a message; the
/// cost of being wrong in the other direction is a leaked credential.
const ENCODED_RUN_MIN_LEN: usize = 12;

/// Masks anything in the retained key-name text that could itself be a secret.
///
/// **Q16 (owner decision 2026-07-25).** Legacy splits on the first `=`/`:` and keeps
/// everything before it, which assumes the separator belongs to a `key=value` pair. When
/// the separator sits *inside* the secret — base64 padding, an `Authorization: Basic …`
/// header — the "key name" is the secret itself, and it travelled into the finding
/// message, the JSON, the SARIF, the database row and the log. That breaches invariant
/// I3, which is absolute.
///
/// This masks rather than rejects, because rejecting the whole line throws away the
/// identifier the message exists to carry. A run of at least [`ENCODED_RUN_MIN_LEN`]
/// alphanumeric characters that is **not purely alphabetic** is replaced; anything else
/// is kept verbatim. Purely alphabetic is the right exemption: `Authorization`,
/// `postgres` and `SECRET` survive, while base64, hex digests and random tokens — none
/// of which are all-letters at that length — do not.
///
/// The rule deliberately over-masks rather than under-masks. `oauth2ClientSecret` is a
/// legitimate identifier that carries a digit and will be masked; the result is a less
/// informative message, never an exposed credential.
/// Whether the retained key name keeps the whitespace it had in the original text.
///
/// The two redaction paths genuinely differ here and both behaviors are pinned by
/// tests, so the difference is a parameter rather than a silent divergence between two
/// copies of the same logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeySpacing {
    /// Keep the text exactly as it appeared. Content redaction matches a span that
    /// already starts at the keyword, and legacy preserved any space sitting before the
    /// separator — `API_KEY = x` yields `API_KEY =<REDACTED>`, stray space included.
    /// Golden references contain that spelling, so it is parity, not sloppiness.
    Preserve,
    /// Trim first. Scan-report messages redact a whole source line, so the key name
    /// would otherwise carry the line's indentation into the finding.
    Trim,
}

/// Splits `text` at its first `=` (else its first `:`), keeps the left side as the key
/// name, and replaces everything after the separator with `<REDACTED>`.
///
/// This is the single implementation of legacy's split-on-first-separator redaction
/// shape. It backs both redaction paths — exported file content
/// ([`crate::redact::redact_secrets`]) and scan-report finding messages
/// ([`redacted_line`]) — which previously carried separate, subtly divergent copies.
/// That mattered: when Q16 fixed the leak on the message path, the content path kept
/// the bug, and content redaction is the more dangerous of the two because its output
/// is handed to whoever receives the bundle.
///
/// `fallback` is called when the text holds neither separator, so the caller can
/// distinguish "a matched value with no key" from "a whole line collapsed". A closure
/// rather than a string because one of those two cases wants a per-secret label and the
/// other does not, and only the caller knows which it is.
///
/// `placeholders` decides how a removed value is spelled — one fixed marker, or a
/// stable per-secret label (see [`crate::pseudonym`]).
pub(crate) fn redact_value_after_separator(
    text: &str,
    spacing: KeySpacing,
    fallback: impl FnOnce() -> String,
    placeholders: Placeholders<'_>,
) -> String {
    // `=` is probed before `:` so that `key=value:with:colons` keeps `key`, matching
    // legacy's ordering.
    for (separator, joiner) in [('=', "="), (':', ": ")] {
        let Some(position) = text.find(separator) else {
            continue;
        };
        let raw_key = &text[..position];
        let key = match spacing {
            KeySpacing::Preserve => raw_key,
            KeySpacing::Trim => raw_key.trim(),
        };
        // The value is everything after the separator — the thing being removed, and
        // therefore the thing a label has to be keyed on.
        let value = &text[position + separator.len_utf8()..];
        return format!(
            "{}{joiner}{}",
            sanitize_key_prefix(key, placeholders),
            placeholders.value(value)
        );
    }
    fallback()
}

/// Masks a suspicious run inside the retained key name.
///
/// A masked run is a secret that happened to sit before the separator, so it is labelled
/// like any other: two lines whose "key name" is the same encoded value are recognisably
/// about the same thing.
pub(crate) fn sanitize_key_prefix(prefix: &str, placeholders: Placeholders<'_>) -> String {
    let mut out = String::with_capacity(prefix.len());
    let mut run = String::new();

    let flush = |run: &mut String, out: &mut String| {
        if run.len() >= ENCODED_RUN_MIN_LEN && !run.chars().all(|c| c.is_ascii_alphabetic()) {
            out.push_str(&placeholders.value(run));
        } else {
            out.push_str(run);
        }
        run.clear();
    };

    for ch in prefix.chars() {
        if ch.is_ascii_alphanumeric() || ch == '+' || ch == '/' {
            run.push(ch);
        } else {
            flush(&mut run, &mut out);
            out.push(ch);
        }
    }
    flush(&mut run, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fallback every test that does not exercise it can share.
    fn fallback() -> String {
        "fallback".to_string()
    }

    #[test]
    fn a_secret_containing_an_equals_sign_does_not_survive_as_the_key_name() {
        // Q16. The split-on-first-`=` rule treats everything before it as a key name.
        // When the `=` is base64 padding inside the secret, the "key name" *is* the
        // secret, so it travelled into the finding message and from there into the
        // JSON, the SARIF, the database row and the log — a direct I3 breach.
        let line = "curl -H 'Authorization: Basic dXNlcjpwYXNzd29yZA==' # token";
        let message = redacted_line(line);
        assert!(
            !message.contains("dXNlcjpwYXNzd29yZA"),
            "the secret leaked into the message: {message}"
        );
    }

    #[test]
    fn a_short_encoded_secret_is_masked_too_not_just_a_long_one() {
        // The first version of this fix used a 16-character threshold, which base64 of
        // an 11-byte password (16 chars) cleared and a 15-character run walked straight
        // through. `aHVudGVyMnBhc3M=` decodes to `hunter2pass`.
        let message = redacted_line("curl -H 'Authorization: Basic aHVudGVyMnBhc3M=' # token");
        assert!(
            !message.contains("aHVudGVyMnBhc3M"),
            "short encoded secret leaked: {message}"
        );
    }

    #[test]
    fn a_hex_digest_is_masked_although_it_has_no_uppercase() {
        // An earlier rule required upper case, lower case *and* digits together, which
        // let lowercase hex digests through.
        let message = redacted_line("hash = d41d8cd98f00b204e9800998ecf8427e # token");
        assert!(
            !message.contains("d41d8cd98f00b204"),
            "hex digest leaked: {message}"
        );
    }

    #[test]
    fn an_ordinary_key_name_survives_verbatim() {
        // The masking must not eat the identifier the message exists to carry; these two
        // shapes are what the golden references contain.
        assert_eq!(
            redacted_line("      - JWT_SECRET=fixture-placeholder-value"),
            "- JWT_SECRET=<REDACTED>"
        );
        assert_eq!(
            redacted_line(r#"SECRET_TOKEN = "placeholder-token-for-fixture-only""#),
            "SECRET_TOKEN=<REDACTED>"
        );
    }

    #[test]
    fn sanitizer_keeps_words_and_masks_encoded_runs() {
        assert_eq!(
            sanitize_key_prefix("- JWT_SECRET", Placeholders::plain()),
            "- JWT_SECRET"
        );
        assert_eq!(
            sanitize_key_prefix("Authorization", Placeholders::plain()),
            "Authorization"
        );
        assert_eq!(
            sanitize_key_prefix("Basic aHVudGVyMnBhc3M", Placeholders::plain()),
            "Basic <REDACTED>"
        );
        // Documented over-masking: a legitimate identifier carrying a digit is masked
        // rather than risked. Information loss, never exposure.
        assert_eq!(
            sanitize_key_prefix("oauth2ClientSecret", Placeholders::plain()),
            "<REDACTED>"
        );
    }

    #[test]
    fn separator_redaction_splits_on_equals_before_colon() {
        // `=` wins so that a value containing colons still yields the real key name.
        assert_eq!(
            redact_value_after_separator(
                "key=host:5432",
                KeySpacing::Trim,
                fallback,
                Placeholders::plain()
            ),
            "key=<REDACTED>"
        );
        assert_eq!(
            redact_value_after_separator(
                "key: value",
                KeySpacing::Trim,
                fallback,
                Placeholders::plain()
            ),
            "key: <REDACTED>"
        );
    }

    #[test]
    fn separator_redaction_returns_the_fallback_when_no_separator_exists() {
        assert_eq!(
            redact_value_after_separator(
                "BEARER abcdef",
                KeySpacing::Preserve,
                || "<REDACTED_SECRET>".to_string(),
                Placeholders::plain()
            ),
            "<REDACTED_SECRET>"
        );
    }

    #[test]
    fn the_two_spacing_modes_differ_exactly_as_their_call_sites_require() {
        // Preserve is what content redaction needs: legacy kept the space before the
        // separator and the golden references contain that spelling. Trim is what a
        // scan message needs, since it redacts a whole indented source line. Pinning
        // both here is what stops the two paths drifting apart again.
        assert_eq!(
            redact_value_after_separator(
                "  API_KEY = x",
                KeySpacing::Preserve,
                fallback,
                Placeholders::plain()
            ),
            "  API_KEY =<REDACTED>"
        );
        assert_eq!(
            redact_value_after_separator(
                "  API_KEY = x",
                KeySpacing::Trim,
                fallback,
                Placeholders::plain()
            ),
            "API_KEY=<REDACTED>"
        );
    }

    #[test]
    fn separator_redaction_masks_an_encoded_key_name_in_both_modes() {
        // The sanitizer runs on the retained prefix regardless of spacing mode, so
        // neither redaction path can leak a secret that happens to precede a separator.
        for spacing in [KeySpacing::Preserve, KeySpacing::Trim] {
            let out = redact_value_after_separator(
                "Basic dXNlcjpwYXNzd29yZA==",
                spacing,
                || "<REDACTED_SECRET>".to_string(),
                Placeholders::plain(),
            );
            assert!(
                !out.contains("dXNlcjpwYXNzd29yZA"),
                "secret survived in {spacing:?} mode: {out}"
            );
        }
    }

    #[test]
    fn self_protection_exempts_own_pattern_names() {
        assert!(is_self_protected("// see SECRET_PATTERNS for details"));
        assert_eq!(
            secret_confidence("// see SECRET_PATTERNS for details"),
            None
        );
        assert_eq!(
            secret_confidence("this line calls redact_secrets(line)"),
            None
        );
    }

    #[test]
    fn critical_confidence_for_pem_header() {
        assert_eq!(
            secret_confidence("-----BEGIN RSA PRIVATE KEY-----"),
            Some("critical")
        );
    }

    #[test]
    fn high_confidence_for_secret_pattern_match() {
        assert_eq!(
            secret_confidence(r#"API_KEY = "abcdef123456""#),
            Some("high")
        );
        assert_eq!(
            secret_confidence("Authorization: BEARER abcdefghijklmnopqrstuvwxyz"),
            Some("high")
        );
    }

    #[test]
    fn medium_confidence_for_assignment_without_value_shape() {
        // ASSIGNMENT_SECRET_RE fires on the key/operator alone. SECRET_PATTERNS'
        // unquoted alternative `[^\s'"\n]+` only needs one whitespace-delimited run of
        // characters after the operator to match — so a line with an actual (even
        // single-word) value after the colon already escalates to `high` (verified in
        // `high_confidence_for_secret_pattern_match` below). `medium` is reachable only
        // when the operator has no value at all following it on the line.
        assert_eq!(secret_confidence("token: "), Some("medium"));
    }

    #[test]
    fn high_confidence_when_any_word_follows_the_operator() {
        // Contrast with `medium_confidence_for_assignment_without_value_shape` above:
        // once *any* non-whitespace run follows the operator, SECRET_PATTERNS' unquoted
        // alternative already matches it, escalating straight to `high` — matching
        // legacy's backreference original, whose empty-capture group closes trivially
        // on an unquoted single word.
        assert_eq!(
            secret_confidence("token: this is not a single quoted value"),
            Some("high")
        );
    }

    #[test]
    fn low_confidence_for_bare_keyword_outside_comment() {
        assert_eq!(
            secret_confidence("we discussed the access_key rotation policy today"),
            Some("low")
        );
    }

    #[test]
    fn low_confidence_suppressed_inside_comment() {
        assert_eq!(secret_confidence("# token rotation policy"), None);
        assert_eq!(secret_confidence("// token rotation policy"), None);
        assert_eq!(secret_confidence("* token rotation policy"), None);
    }

    #[test]
    fn no_confidence_for_unrelated_line() {
        assert_eq!(secret_confidence("let counter = 0;"), None);
    }

    #[test]
    fn redacted_line_collapses_remaining_keyword_mentions() {
        // First pass (redact_secrets) yields "API_KEY =<REDACTED>" (space before `=`
        // preserved from the matched span); the keyword `API_KEY` is still present, so
        // the second, stronger pass collapses it again into a clean "key=<REDACTED>".
        assert_eq!(
            redacted_line(r#"API_KEY = "abcdef123456""#),
            "API_KEY=<REDACTED>"
        );
    }

    #[test]
    fn redacted_line_never_contains_original_secret_value() {
        let redacted = redacted_line(r#"SECRET="super-sensitive-value-123""#);
        assert!(!redacted.contains("super-sensitive-value-123"));
    }

    #[test]
    fn redacted_line_trims_and_passes_through_clean_lines() {
        assert_eq!(redacted_line("   let x = 1;   "), "let x = 1;");
    }
}
