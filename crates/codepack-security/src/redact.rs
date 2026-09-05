//! Content-level secret redaction, ported from legacy `utils/text_utils.py::redact_secrets`.
//!
//! ## The backreference-rewrite deviation
//!
//! Legacy's regex is:
//!
//! ```text
//! (?i)\b(API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASS|PRIVATE[_-]?KEY)\b\s*[:=]\s*(['"]?)[^\s'"\n]+(\2)
//! ```
//!
//! Group 2 captures an optional opening quote, and group 3 (`\2`, a **backreference**)
//! requires the closing character to match whatever the opening quote was (or, if there
//! was no opening quote, requires an empty closing match). Rust's `regex` crate is a
//! linear-time automaton engine and has no backreference support by design.
//!
//! This is rewritten ([`crate::patterns::keyword::SECRET_PATTERNS`], first entry) as an
//! alternation of three shapes — double-quoted, single-quoted, unquoted — each still
//! forbidding embedded whitespace exactly like legacy's `[^\s'"\n]+`:
//!
//! ```text
//! (?i)\b(API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASS|PRIVATE[_-]?KEY)\b\s*[:=]\s*(?:"[^\s"\n]+"|'[^\s'\n]+'|[^\s'"\n]+)
//! ```
//!
//! **Span equivalence, not bit-for-bit identity — by construction, not by luck.** On
//! well-formed input (matching open/close quotes, or no quotes at all — the only shapes
//! that occur in practice) this produces the identical match span as the backreference
//! original; see `redact_span_matches_legacy_backreference_semantics` below.
//!
//! On the mismatched-quote edge case `KEY: "value'`, both implementations happen to
//! agree by *not* matching: the backreference original requires the closing character
//! to equal the opening `"`, which never appears again, so it fails; this rewrite's
//! double-quoted alternative also requires a closing `"` that is absent, its
//! single-quoted alternative requires an opening `'` that is not the next character,
//! and its unquoted alternative cannot start on a `"` at all (excluded by
//! `[^\s'"\n]`). See `mismatched_quote_style_does_not_falsely_close_early` below — this
//! is verified by test, not assumed.
//!
//! ## Finding 1, 2026-07-27 audit: this pass used to redact less than the scanner found
//!
//! Until this fix, content redaction consulted only `keyword_scan::REDACT_ROOTS` — legacy's
//! original, narrow keyword list — while the *scanner* had grown provider signatures
//! and a wider keyword set (`SCAN_ONLY_ROOTS`) in S3. The result: a line the scanner
//! itself reported as `critical` (a bare `AWS_ACCESS_KEY_ID=...`, or any
//! `DATABASE_URL=`/`JWT_SECRET=`/`ACCESS_KEY=`/`CLIENT_SECRET=` assignment) reached
//! `03_text_dump.txt` — the file built specifically to hand a project to an AI
//! assistant — completely unredacted. The product already knew the line was secret and
//! wrote it out anyway.
//!
//! [`find_redaction_spans`] is content redaction's own, wider span set: the full scan
//! keyword vocabulary, HTTP auth tokens (`Bearer`/`Basic`/`Digest`), URL-embedded
//! passwords, and every provider/Telegram signature the scanner already recognises.
//! Entropy is the one deliberate exclusion — see that function's doc comment for why.
//!
//! Owner decision 2026-07-27 (`docs/__arch__/open-questions.md`): this widening is
//! intentional and diverges from legacy, which redacted keyword-only. Golden parity is
//! unaffected — `03_text_dump.txt` is checked for presence only, never byte-compared
//! (decision 2026-07-25).

use crate::patterns::keyword::{KeySpacing, redact_value_after_separator};
use crate::patterns::keyword_scan::{
    contains_root, find_bearer_tokens, find_keyword_assignments, scan_roots, skip_spaces,
};
use crate::patterns::{credentials, prefilter, provider};
use crate::pseudonym::Placeholders;

/// Every span content redaction must replace on one line.
///
/// Order does not matter to the caller — [`redact_line_spans`] sorts and deduplicates
/// overlaps — but the set itself is the fix for Finding 1: keyword assignments use
/// [`scan_roots`] (the scanner's full vocabulary), not the narrower `keyword_scan::REDACT_ROOTS`
/// legacy shipped, and provider/Telegram/HTTP-auth/URL-credential spans are included at
/// all, which legacy never had to consider because none of those detectors existed yet.
///
/// **Entropy is deliberately excluded**, the only detector left out. It is this crate's
/// highest false-positive-risk detector by its own module doc — base64 assets, hashes,
/// UUIDs and minified code all clear its thresholds — and that risk is acceptable for a
/// *scan finding*, where a human reviews a short list before acting on it. It is not
/// acceptable for *silently rewriting exported file content* nobody asked to have
/// edited: an entropy false positive in a scan report is a line to double-check, the
/// same false positive in content redaction is unannounced data corruption in a file
/// the project's owner may never open, and it would be triggered by files entropy was
/// never asked to police (arbitrary text, other people's source).
fn find_redaction_spans(line: &str) -> Vec<(usize, usize)> {
    let mut spans = find_keyword_assignments(line, &scan_roots());
    spans.extend(find_compound_keyword_assignments(line));
    spans.extend(find_bearer_tokens(line));
    spans.extend(credentials::find_http_auth_tokens(line));
    spans.extend(credentials::find_url_credentials(line));
    // Gated exactly like `scan::collect_secret_hits`'s own provider check: the prefilter
    // is a fixed literal set the provider signatures are anchored on, so a line with no
    // hit cannot contain a provider match.
    if prefilter::has_hit(line) {
        spans.extend(
            provider::find_provider_matches(line)
                .into_iter()
                .map(|found| (found.start, found.end)),
        );
    }
    // Never gated by the prefilter — same reason as the scanner: Telegram's shape has
    // no distinctive literal prefix to anchor on.
    spans.extend(
        provider::find_telegram_matches(line)
            .into_iter()
            .map(|found| (found.start, found.end)),
    );
    spans
}

/// Assignments whose key *carries* a keyword root in one of its `_`/`-` segments, rather
/// than being one.
///
/// ## Why redaction is allowed to be wider than detection here
///
/// The shared matcher requires a root to stand as a whole word: `TOKEN=x` matches,
/// `NPM_TOKEN=x` does not. That boundary reproduces legacy's `\b(…)\b` exactly and is
/// deliberate — widening the *detector* would change what the scanner reports and move
/// the golden references, which is an owner's decision rather than a repair.
///
/// Redaction is the other half of the asymmetry this crate already states: over-masking
/// costs a masked word, under-masking leaks a credential. A sweep across a produced
/// bundle found `NPM_TOKEN=…` surviving into `03_text_dump.txt` — the artifact most
/// likely to be handed to somebody else — because of that boundary. So this pass runs
/// **only** for redaction: `find_redaction_spans` calls it, and nothing in the detection
/// path does.
///
/// Segment-wise rather than substring, so `TOKENIZER=…` is left alone while
/// `NPM_TOKEN=…` and `AWS_SECRET_ACCESS_KEY=…` are masked.
fn find_compound_keyword_assignments(line: &str) -> Vec<(usize, usize)> {
    let roots = scan_roots();
    let bytes = line.as_bytes();
    let mut spans = Vec::new();
    let mut index = 0usize;

    while index < bytes.len() {
        let byte = bytes[index];
        if !(byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-') {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len()
            && (bytes[index].is_ascii_alphanumeric()
                || bytes[index] == b'_'
                || bytes[index] == b'-')
        {
            index += 1;
        }
        let name = &line[start..index];

        // A bare root is the shared matcher's job; this pass exists for the compounded
        // names it declines, so anything it already covers is skipped.
        let compounded = name.contains(['_', '-']);
        if !compounded
            || !name
                .split(['_', '-'])
                .any(|segment| !segment.is_empty() && contains_root(segment, &roots))
        {
            continue;
        }

        // The operator must follow the name immediately. `NAME = value`, with spacing,
        // is already collapsed by the line-level pass in `keyword::redacted_line_with`,
        // and matching it here would only change that pass's spacing. What leaks is the
        // tight `NAME=value` shell-assignment shape, and that is what this covers.
        if index >= bytes.len() || (bytes[index] != b'=' && bytes[index] != b':') {
            continue;
        }
        let value_start = skip_spaces(bytes, index + 1);
        if value_start >= bytes.len() {
            continue;
        }
        // The value runs to the next whitespace: an environment assignment in a command,
        // a line in a `.env`, a YAML scalar. Quotes are part of it and are handled by the
        // shared `replace_match`.
        let mut value_end = value_start;
        while value_end < bytes.len() && !bytes[value_end].is_ascii_whitespace() {
            value_end += 1;
        }
        if value_end > value_start {
            spans.push((start, value_end));
            index = value_end;
        }
    }

    spans
}

/// Rewrites one matched span: `KEY: value` / `KEY=value` keeps the key name, everything
/// else (`BEARER`/`Basic`/`Digest <token>`, a URL password, a provider or Telegram
/// signature) has no key to name and falls through to the fixed placeholder.
///
/// Shares [`redact_value_after_separator`] with the scan-report path (Q16). Keeping two
/// copies is what let the content path — the more dangerous of the two, since its output
/// is handed to whoever receives the bundle — retain the leak after the message path was
/// fixed: `SECRET: "dXNlcjpwYXNzd29yZA=="` used to yield
/// `SECRET: "dXNlcjpwYXNzd29yZA=<REDACTED>`, which decodes to a real credential. The
/// same guard is why a base64 `Basic` token containing its own `=` padding cannot leak
/// either: [`redact_value_after_separator`] treats that `=` exactly as it would a real
/// assignment operator and masks the run in front of it via `sanitize_key_prefix`,
/// which is the correct, conservative outcome even though it produces a slightly
/// unlovely doubled placeholder rather than a single clean one.
fn replace_match(matched: &str, placeholders: Placeholders<'_>) -> String {
    redact_value_after_separator(
        matched,
        // The match span starts at the keyword itself, and legacy preserved any space
        // before the separator; golden references contain that spelling.
        KeySpacing::Preserve,
        // A span with no key of its own — a bare token, a provider signature, a URL
        // password — has nothing to name, so the whole span is the secret and the whole
        // span is what a label is keyed on.
        || placeholders.bare(matched),
        placeholders,
    )
}

/// Replaces every span [`find_redaction_spans`] finds with a redacted placeholder.
/// Applied to file content before it is included in an export or copied to the
/// clipboard — see `docs/__arch__/BLUEPRINT.md` §A.4.2.
///
/// Works line by line because the shapes themselves are line-scoped: the original
/// patterns excluded `\n` from every value character class, so a value could never span
/// a newline. Scanning per line also keeps the span offsets simple and bounds the work
/// on a very large file.
pub fn redact_secrets(text: &str) -> String {
    redact_text_with(text, Placeholders::plain())
}

/// [`redact_secrets`] with an explicit placeholder policy — the form
/// [`crate::Redactor`] calls.
pub(crate) fn redact_text_with(text: &str, placeholders: Placeholders<'_>) -> String {
    // `split_inclusive` keeps each line's terminator attached, so joining the results
    // reproduces the original line endings exactly — including a missing final newline,
    // and including `\r\n`, whose `\r` is simply part of the line's tail.
    text.split_inclusive('\n')
        .map(|line| redact_line_spans(line, placeholders))
        .collect()
}

/// One line, for the scan-report path that works line by line.
pub(crate) fn redact_line_with(line: &str, placeholders: Placeholders<'_>) -> String {
    redact_text_with(line, placeholders)
}

/// Replaces every secret span on one line, left to right.
fn redact_line_spans(line: &str, placeholders: Placeholders<'_>) -> String {
    let spans = find_redaction_spans(line);
    if spans.is_empty() {
        return line.to_string();
    }

    // Several detectors can claim overlapping or nested spans on the same line now
    // (a keyword assignment's value can itself contain a URL-credential span, for
    // instance), so all spans are sorted and applied in one pass and a later span
    // starting inside an already-applied one is skipped rather than corrupting the
    // output — the outer, earlier-starting span already covers it.
    let mut ordered = spans;
    ordered.sort_unstable();

    let mut out = String::with_capacity(line.len());
    let mut cursor = 0usize;
    for (start, end) in ordered {
        if start < cursor {
            continue;
        }
        out.push_str(&line[cursor..start]);
        out.push_str(&replace_match(&line[start..end], placeholders));
        cursor = end;
    }
    out.push_str(&line[cursor..]);
    out
}

/// Redaction for a shell command line, which is stronger than [`redact_secrets`] in one
/// specific way.
///
/// ## Why a command needs more than the general rule
///
/// The keyword matcher requires a root to stand as a whole word: `TOKEN=x` matches,
/// `NPM_TOKEN=x` does not. That boundary is deliberate and documented — it reproduces
/// legacy's `\b(…)\b` exactly, and widening it would change what the *scanner* reports,
/// move the golden references, and is an owner's decision rather than a repair.
///
/// A shell command is the one place where that boundary is clearly wrong, because the
/// shape is unambiguous: a command may be prefixed by environment assignments, and those
/// names are conventionally compounded — `NPM_TOKEN=…`, `GH_TOKEN=…`,
/// `AWS_SECRET_ACCESS_KEY=…`. `package.json`'s `scripts` are full of exactly this, they
/// are never excluded by safe mode, and they are copied into the artifact meant to be
/// pasted into a language model.
///
/// So this masks the value of a *leading* assignment whose name carries a keyword root in
/// any `_`/`-` separated segment, and then applies the ordinary redaction to the rest. It
/// is narrower than the general rule rather than a second copy of it: it only looks at
/// assignments at the head of a command, where a bare word followed by `=` cannot be
/// anything else.
pub fn redact_shell_command(command: &str) -> String {
    let mut out = String::with_capacity(command.len());
    let mut rest = command;

    // Leading `NAME=VALUE` runs, in order, stopping at the first token that is not one.
    loop {
        let leading_spaces = rest.len() - rest.trim_start().len();
        let trimmed = rest.trim_start();
        let Some((name, after)) = split_leading_assignment(trimmed) else {
            break;
        };
        let (value, tail) = match after.find(char::is_whitespace) {
            Some(at) => (&after[..at], &after[at..]),
            None => (after, ""),
        };
        out.push_str(&rest[..leading_spaces]);
        out.push_str(name);
        out.push('=');
        if name_carries_keyword_root(name) {
            out.push_str("<REDACTED>");
        } else {
            out.push_str(value);
        }
        rest = tail;
    }

    out.push_str(&redact_secrets(rest));
    out
}

/// Splits `NAME=` off the front of a command, if that is what it starts with.
///
/// A name is a shell-legal variable name: letters, digits and underscore, not starting
/// with a digit. Anything else — a path, a flag, a quoted string — is not an assignment
/// and stops the scan.
fn split_leading_assignment(text: &str) -> Option<(&str, &str)> {
    let at = text.find('=')?;
    let name = &text[..at];
    if name.is_empty() || name.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return None;
    }
    Some((name, &text[at + 1..]))
}

/// True when any `_`/`-` separated segment of `name` is one of the scan keyword roots.
///
/// Segment-wise rather than substring: `TOKENIZER` must not match, while `NPM_TOKEN` and
/// `AWS_SECRET_ACCESS_KEY` must.
fn name_carries_keyword_root(name: &str) -> bool {
    let roots = scan_roots();
    name.split(['_', '-'])
        .any(|segment| !segment.is_empty() && contains_root(segment, &roots))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_containing_an_equals_sign_does_not_survive_into_exported_content() {
        // This pass rewrites exported file content and the clipboard, so a survivor here
        // is handed to whoever receives the bundle. `dXNlcjpwYXNzd29yZA==` decodes to
        // `user:password`.
        let redacted = redact_secrets(r#"SECRET: "dXNlcjpwYXNzd29yZA==""#);
        assert!(
            !redacted.contains("dXNlcjpwYXNzd29yZA"),
            "secret leaked into exported content: {redacted}"
        );
    }

    #[test]
    fn redacts_double_quoted_value() {
        assert_eq!(
            redact_secrets(r#"API_KEY: "abc123""#),
            "API_KEY: <REDACTED>"
        );
    }

    #[test]
    fn redacts_single_quoted_value() {
        assert_eq!(redact_secrets("API_KEY='abc123'"), "API_KEY=<REDACTED>");
    }

    #[test]
    fn redacts_unquoted_value() {
        assert_eq!(redact_secrets("API_KEY=abc123"), "API_KEY=<REDACTED>");
    }

    #[test]
    fn redact_span_matches_legacy_backreference_semantics() {
        // Well-formed matching-quote cases: span-equivalent to the Python backreference
        // original by construction (documented in the module doc comment above). Uses
        // "SECRET" (an actual `REDACT_KEYWORDS` member) rather than plain "KEY", which
        // is not itself a keyword root and would never match either implementation.
        assert_eq!(redact_secrets(r#"SECRET: "value""#), "SECRET: <REDACTED>");
        assert_eq!(redact_secrets("SECRET='value'"), "SECRET=<REDACTED>");
        assert_eq!(redact_secrets("SECRET=value"), "SECRET=<REDACTED>");
    }

    #[test]
    fn mismatched_quote_style_does_not_falsely_close_early() {
        // SECRET: "value' — neither the backreference original nor this rewrite
        // produces a match here (see module doc comment for the full trace); the value
        // is not safely identifiable as fully quoted, so it is left untouched by both.
        let input = r#"SECRET: "value'"#;
        assert_eq!(redact_secrets(input), input);
    }

    #[test]
    fn redacts_bearer_token() {
        // The BEARER pattern's own match span is just "BEARER <token>" — it never
        // includes the "Authorization:" prefix that precedes it on the line, so
        // `replace_match` finds neither `=` nor `:` inside the matched text itself and
        // falls through to the bare `<REDACTED_SECRET>` placeholder (legacy's `repl`
        // does the same: `match.group(0)` is only the BEARER span).
        assert_eq!(
            redact_secrets("Authorization: BEARER abcdefghijklmnopqrstuvwxyz"),
            "Authorization: <REDACTED_SECRET>"
        );
    }

    #[test]
    fn bearer_token_below_length_threshold_is_not_redacted() {
        assert_eq!(
            redact_secrets("Authorization: BEARER short"),
            "Authorization: BEARER short"
        );
    }

    #[test]
    fn non_secret_text_is_untouched() {
        let text = "the quick brown fox jumps over the lazy dog";
        assert_eq!(redact_secrets(text), text);
    }

    #[test]
    fn password_keyword_redacted() {
        assert_eq!(redact_secrets("PASSWORD: hunter2"), "PASSWORD: <REDACTED>");
    }

    #[test]
    fn private_key_keyword_redacted() {
        assert_eq!(
            redact_secrets("PRIVATE_KEY=abcdef0123456789"),
            "PRIVATE_KEY=<REDACTED>"
        );
    }

    #[test]
    fn no_placeholder_leaks_original_value() {
        let redacted = redact_secrets(r#"SECRET="super-sensitive-value-123""#);
        assert!(!redacted.contains("super-sensitive-value-123"));
    }

    // --- Finding 1 (2026-07-27 audit): content redaction now matches what the scanner
    // finds, not just legacy's narrower keyword list. ---

    #[test]
    fn scan_only_keywords_are_now_redacted_in_exported_content() {
        // Before this fix these four reached the scanner (as `medium`/`low` findings)
        // but never `redact_secrets` at all — the exact gap the audit's `SCAN_ONLY_ROOTS`
        // comment ("scanned for but never redacted") named directly.
        assert_eq!(
            redact_secrets("DATABASE_URL=postgres://user:pass@host:5432/db"),
            "DATABASE_URL=<REDACTED>"
        );
        assert_eq!(
            redact_secrets("JWT_SECRET=abcdef0123456789"),
            "JWT_SECRET=<REDACTED>"
        );
        assert_eq!(
            redact_secrets("ACCESS_KEY=abcdef0123456789"),
            "ACCESS_KEY=<REDACTED>"
        );
        assert_eq!(
            redact_secrets("CLIENT_SECRET=abcdef0123456789"),
            "CLIENT_SECRET=<REDACTED>"
        );
    }

    #[test]
    fn a_bare_provider_signature_is_redacted_from_exported_content_even_with_no_keyword() {
        // The audit's own repro: AWS_ACCESS_KEY_ID= has no REDACT_ROOTS-bounded keyword
        // at all ("ACCESS_KEY" is glued to the identifier by underscores on both sides),
        // so only the provider signature can catch it. Before this fix it reached
        // 03_text_dump.txt verbatim despite the scanner reporting it `critical`.
        let redacted = redact_secrets("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE");
        assert!(!redacted.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn a_url_password_is_redacted_from_exported_content_with_no_keyword_at_all() {
        // Finding 2's structural detector, wired into content redaction too: no
        // REDACT_ROOTS/scan_roots keyword appears anywhere on this line.
        let redacted = redact_secrets(
            "db.connect('postgres://admin:hunter2fakepass@host/db?sslmode=require')",
        );
        assert!(!redacted.contains("hunter2fakepass"));
        assert!(
            redacted.contains("admin"),
            "the username is not a secret and should survive"
        );
    }

    #[test]
    fn basic_auth_is_redacted_from_exported_content() {
        let redacted =
            redact_secrets("headers = {'Authorization': 'Basic ZmFrZXVzZXI6ZmFrZXBhc3N3b3Jk'}");
        assert!(!redacted.contains("ZmFrZXVzZXI6ZmFrZXBhc3N3b3Jk"));
    }

    #[test]
    fn the_audits_own_four_line_reproduction_leaves_no_secret_in_exported_content() {
        // The exact fixture from AUDIT-2026-07-27.md, finding 1, reproduced verbatim.
        let source = "db.connect('postgres://admin:hunter2fakepass@host/db?sslmode=require')\n\
                       AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n\
                       headers = {'Authorization': 'Basic ZmFrZXVzZXI6ZmFrZXBhc3N3b3Jk'}\n\
                       api_key = \"sk-projFAKEfghijklmnopqrstuvwxyz1234567890ABCD\"\n";
        let redacted = redact_secrets(source);
        for secret in [
            "hunter2fakepass",
            "AKIAIOSFODNN7EXAMPLE",
            "ZmFrZXVzZXI6ZmFrZXBhc3N3b3Jk",
            "sk-projFAKEfghijklmnopqrstuvwxyz1234567890ABCD",
        ] {
            assert!(
                !redacted.contains(secret),
                "{secret} leaked into: {redacted}"
            );
        }
    }
}
