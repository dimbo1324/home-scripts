//! Keyword-root matching for the secret cascade, done with string operations.
//!
//! ## Roots as data, not as regex source
//!
//! The keyword sets used to live as fragments of regex source spliced into larger
//! patterns:
//!
//! ```text
//! const REDACT_KEYWORDS: &str = "API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASS|PRIVATE[_-]?KEY";
//! const SCAN_KEYWORDS:   &str = "API[_-]?KEY|SECRET|…|ACCESS[_-]?KEY|CLIENT[_-]?SECRET";
//! ```
//!
//! `SCAN_KEYWORDS` was meant to be `REDACT_KEYWORDS` plus four more roots, but Rust
//! cannot concatenate `const &str` at compile time, so the shared prefix was retyped by
//! hand and a test asserted `SCAN_KEYWORDS.starts_with(REDACT_KEYWORDS)` to catch the
//! two drifting apart. A test guarding a copy-paste is a sign the data is modelled
//! wrongly: the relationship is *containment*, and expressing it as such makes the
//! guard unnecessary.
//!
//! Here a root is its list of words — `API[_-]?KEY` becomes `["API", "KEY"]` — and the
//! separator rule is applied by the matcher instead of being spelled into each pattern.
//! The three sets are then defined by composition, so the containment is structural and
//! cannot rot.
use std::sync::LazyLock;

/// One keyword root: the words it is written with, in order.
///
/// A root matches when its words appear consecutively, joined by nothing, `_` or `-`
/// — the `[_-]?` the regexes spelled between every pair. Matching is case-insensitive.
type KeywordRoot = &'static [&'static str];

/// Roots that content redaction acts on. Legacy `_REDACT_KEYWORDS`.
pub(crate) const REDACT_ROOTS: &[KeywordRoot] = &[
    &["API", "KEY"],
    &["SECRET"],
    &["TOKEN"],
    &["PASSWORD"],
    &["PASS"],
    &["PRIVATE", "KEY"],
];

/// Roots that are scanned for but never themselves redacted, beyond [`REDACT_ROOTS`].
const SCAN_ONLY_ROOTS: &[KeywordRoot] = &[
    &["DATABASE", "URL"],
    &["JWT", "SECRET"],
    &["ACCESS", "KEY"],
    &["CLIENT", "SECRET"],
];

/// Roots the `medium`-confidence assignment rule recognises, beyond [`REDACT_ROOTS`].
///
/// Legacy's `_ASSIGNMENT_SECRET_RE` listed `database_url` and `jwt_secret` but **not**
/// `access_key` or `client_secret`, so this is deliberately narrower than
/// [`scan_roots`]. That asymmetry is legacy's, reproduced rather than tidied: widening
/// it would raise the confidence of lines the original left alone.
const ASSIGNMENT_ONLY_ROOTS: &[KeywordRoot] = &[&["DATABASE", "URL"], &["JWT", "SECRET"]];

/// Every root the scanner looks for. Legacy `_SCAN_KEYWORDS`.
///
/// Built once. These are read on the hottest path there is — once per line of every file
/// scanned and every file redacted — and they used to be rebuilt into a fresh `Vec` at
/// each of those calls: two or three heap allocations per line, millions of them on a
/// large project, and allocator pressure from every rayon thread at once (audit No. 16).
/// The same `LazyLock` shape `PROVIDER_PATTERNS` and `AUTOMATON` already use in this
/// module's neighbour.
pub(crate) static SCAN_ROOTS: LazyLock<Vec<KeywordRoot>> = LazyLock::new(|| {
    REDACT_ROOTS
        .iter()
        .chain(SCAN_ONLY_ROOTS)
        .copied()
        .collect()
});

/// Every root the `medium`-confidence assignment rule looks for.
pub(crate) static ASSIGNMENT_ROOTS: LazyLock<Vec<KeywordRoot>> = LazyLock::new(|| {
    REDACT_ROOTS
        .iter()
        .chain(ASSIGNMENT_ONLY_ROOTS)
        .copied()
        .collect()
});

/// Every keyword root the crate knows, for [`crate::fingerprint`].
///
/// The union rather than either set: the fingerprint's job is to notice *any* change to
/// what the detectors look for, so it must see the assignment-only roots too.
pub(crate) fn every_root() -> Vec<KeywordRoot> {
    let mut roots: Vec<KeywordRoot> = SCAN_ROOTS.clone();
    roots.extend(ASSIGNMENT_ROOTS.iter().copied());
    roots
}

/// A word character, matching the `\w` the `\b` assertions were defined against.
fn is_word_char(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

/// The separators a root's words may be joined by — `[_-]?` in the originals.
fn is_root_separator(byte: u8) -> bool {
    byte == b'_' || byte == b'-'
}

/// Matches `root` at `start`, returning the offset just past it.
///
/// Between two words the separator is optional and at most one character, exactly as
/// `[_-]?` specifies — `API_KEY`, `API-KEY` and `APIKEY` all match, `API__KEY` does not.
fn match_root_at(line: &str, start: usize, root: KeywordRoot) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut cursor = start;

    for (index, word) in root.iter().enumerate() {
        if index > 0 && cursor < bytes.len() && is_root_separator(bytes[cursor]) {
            cursor += 1;
        }
        let end = cursor.checked_add(word.len())?;
        let candidate = bytes.get(cursor..end)?;
        if !candidate.eq_ignore_ascii_case(word.as_bytes()) {
            return None;
        }
        cursor = end;
    }

    Some(cursor)
}

/// True when `line[start..end]` is bounded by `\b` on both sides.
///
/// `\b` asserts a transition, so each edge holds when exactly one side is a word
/// character. Every root begins and ends with a letter, so in practice this means "not
/// glued to a longer identifier" — `MY_API_KEY` is deliberately *not* a match, matching
/// the original `\b(…)\b`.
///
/// `pub(crate)`: shared with [`crate::patterns::credentials`], which needs the exact
/// same boundary rule for `BASIC`/`DIGEST` — a second, drifted copy of a security
/// boundary check is the precise failure class Finding 1 (2026-07-27 audit) came from.
pub(crate) fn is_word_bounded(line: &str, start: usize, end: usize) -> bool {
    let before_is_word = line[..start].chars().next_back().is_some_and(is_word_char);
    let after_is_word = line[end..].chars().next().is_some_and(is_word_char);
    !before_is_word && !after_is_word
}

/// Finds the leftmost word-bounded occurrence of any root, returning its byte range.
///
/// When several roots match at the same position the longest wins, which is what a
/// regex alternation does not guarantee but what callers need: `JWT_SECRET` must be
/// reported as itself rather than as the `SECRET` inside it.
pub(crate) fn find_root(line: &str, roots: &[KeywordRoot]) -> Option<(usize, usize)> {
    (0..=line.len())
        .filter(|start| line.is_char_boundary(*start))
        .find_map(|start| {
            roots
                .iter()
                .filter_map(|root| match_root_at(line, start, root))
                .filter(|end| is_word_bounded(line, start, *end))
                .max()
                .map(|end| (start, end))
        })
}

/// True when `line` mentions any of `roots` as a whole word.
pub(crate) fn contains_root(line: &str, roots: &[KeywordRoot]) -> bool {
    find_root(line, roots).is_some()
}

/// Horizontal whitespace, the `\s*` around an assignment operator.
///
/// `pub(crate)`: shared with [`crate::patterns::credentials`] — see [`is_word_bounded`].
pub(crate) fn skip_spaces(bytes: &[u8], from: usize) -> usize {
    let mut index = from;
    while index < bytes.len() && (bytes[index] == b' ' || bytes[index] == b'\t') {
        index += 1;
    }
    index
}

/// Matches `\s*[:=]` after a root, returning the offset just past the operator.
fn match_assignment_operator(bytes: &[u8], from: usize) -> Option<usize> {
    let operator = skip_spaces(bytes, from);
    match bytes.get(operator) {
        Some(b':' | b'=') => Some(operator + 1),
        _ => None,
    }
}

/// Matches the value shape `(?:"[^\s"\n]+"|'[^\s'\n]+'|[^\s'"\n]+)`, returning the
/// offset just past it.
///
/// The three alternatives are tried in the original's order — double-quoted, then
/// single-quoted, then unquoted — and, crucially, the unquoted alternative excludes both
/// quote characters. That is what makes a mismatched pair such as `KEY: "value'` match
/// nothing at all: the double-quoted form finds no closing `"`, the single-quoted form
/// needs an opening `'` that is not there, and the unquoted form cannot begin on a `"`.
/// Legacy's backreference original behaved the same way; see [`crate::redact`]'s module
/// doc for the full trace.
fn match_value(bytes: &[u8], from: usize) -> Option<usize> {
    let start = skip_spaces(bytes, from);
    let first = *bytes.get(start)?;

    // A quoted value: at least one non-whitespace character, then the same quote.
    if first == b'"' || first == b'\'' {
        let mut index = start + 1;
        while index < bytes.len() {
            let byte = bytes[index];
            if byte == first {
                // `+` in the original: the value must not be empty.
                return (index > start + 1).then_some(index + 1);
            }
            if byte.is_ascii_whitespace() {
                break;
            }
            index += 1;
        }
        return None;
    }

    // Unquoted: a run of characters that are neither whitespace nor either quote.
    let mut index = start;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() || byte == b'"' || byte == b'\'' {
            break;
        }
        index += 1;
    }
    (index > start).then_some(index)
}

/// Finds every `<root>\s*[:=]\s*<value>` span in `line`, left to right and
/// non-overlapping — legacy's first `SECRET_PATTERNS` entry.
///
/// The returned ranges are what content redaction replaces, so their exact extent is a
/// compatibility surface: golden references contain the resulting text.
pub(crate) fn find_keyword_assignments(line: &str, roots: &[KeywordRoot]) -> Vec<(usize, usize)> {
    let bytes = line.as_bytes();
    let mut spans = Vec::new();
    let mut cursor = 0usize;

    while cursor < line.len() {
        let Some((start, root_end)) =
            find_root(&line[cursor..], roots).map(|(start, end)| (cursor + start, cursor + end))
        else {
            break;
        };

        let matched_end = match_assignment_operator(bytes, root_end)
            .and_then(|after_operator| match_value(bytes, after_operator));

        match matched_end {
            Some(end) => {
                spans.push((start, end));
                cursor = end;
            }
            // This root had no value after it; resume scanning past the root itself so a
            // later mention on the same line is still considered.
            None => cursor = root_end.max(start + 1),
        }
    }

    spans
}

/// True when a root on the line is followed by `\s*[:=]`, with no requirement on what
/// comes after — legacy's `_ASSIGNMENT_SECRET_RE`.
pub(crate) fn has_assignment_operator_after_root(line: &str, roots: &[KeywordRoot]) -> bool {
    let bytes = line.as_bytes();
    let mut cursor = 0usize;

    while cursor < line.len() {
        let Some((start, root_end)) =
            find_root(&line[cursor..], roots).map(|(start, end)| (cursor + start, cursor + end))
        else {
            return false;
        };
        if match_assignment_operator(bytes, root_end).is_some() {
            return true;
        }
        cursor = root_end.max(start + 1);
    }

    false
}

/// The literal a bearer-token mention starts with.
const BEARER: &str = "BEARER";

/// Minimum token length for a `BEARER` mention to count, from the original's `{16,}`.
/// Short words after `Bearer` are prose, not credentials.
///
/// `pub(crate)`: [`crate::patterns::credentials::find_http_auth_tokens`] reuses this
/// exact threshold for `Basic`/`Digest`, rather than defining its own copy that could
/// silently drift from this one.
pub(crate) const BEARER_MIN_TOKEN_LEN: usize = 16;

/// A character permitted inside a bearer token: `[A-Za-z0-9._\-+/=]`.
///
/// `pub(crate)`: shared with [`crate::patterns::credentials`] — see
/// [`BEARER_MIN_TOKEN_LEN`]. `Basic`/`Digest` tokens use the same alphabet.
pub(crate) fn is_bearer_token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+' | b'/' | b'=')
}

/// Finds every `BEARER <token>` span — legacy's second `SECRET_PATTERNS` entry,
/// `(?i)\b(BEARER)\s+[A-Za-z0-9._\-+/=]{16,}`.
pub(crate) fn find_bearer_tokens(line: &str) -> Vec<(usize, usize)> {
    let bytes = line.as_bytes();
    let mut spans = Vec::new();
    let mut cursor = 0usize;

    while cursor < line.len() {
        let Some(offset) = line[cursor..].to_ascii_uppercase().find(BEARER) else {
            break;
        };
        let start = cursor + offset;
        let after_keyword = start + BEARER.len();

        if !is_word_bounded(line, start, after_keyword) {
            cursor = start + 1;
            continue;
        }

        // `\s+`: at least one space, unlike the assignment operator's `\s*`.
        let token_start = skip_spaces(bytes, after_keyword);
        if token_start == after_keyword {
            cursor = after_keyword;
            continue;
        }

        let mut token_end = token_start;
        while token_end < bytes.len() && is_bearer_token_char(bytes[token_end]) {
            token_end += 1;
        }

        if token_end - token_start >= BEARER_MIN_TOKEN_LEN {
            spans.push((start, token_end));
            cursor = token_end;
        } else {
            cursor = after_keyword;
        }
    }

    spans
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_root_matches_every_separator_spelling() {
        for spelling in ["API_KEY", "API-KEY", "APIKEY", "api_key", "Api-Key"] {
            assert!(
                contains_root(spelling, REDACT_ROOTS),
                "should have matched {spelling}"
            );
        }
    }

    #[test]
    fn a_doubled_separator_is_not_a_match() {
        // `[_-]?` allows at most one separator character.
        assert!(!contains_root("API__KEY", REDACT_ROOTS));
        assert!(!contains_root("API-_KEY", REDACT_ROOTS));
    }

    #[test]
    fn a_root_glued_to_a_longer_identifier_is_not_a_match() {
        assert!(!contains_root("MY_API_KEYS", REDACT_ROOTS));
        assert!(!contains_root("XTOKENX", REDACT_ROOTS));
        // But separated by non-word characters it is.
        assert!(contains_root("the TOKEN value", REDACT_ROOTS));
        assert!(contains_root("(SECRET)", REDACT_ROOTS));
    }

    #[test]
    fn the_longest_root_wins_at_a_shared_position() {
        // `JWT_SECRET` must not be reported as the bare `SECRET` inside it.
        let roots = &*SCAN_ROOTS;
        let (start, end) = find_root("JWT_SECRET=x", roots).expect("root found");
        assert_eq!(&"JWT_SECRET=x"[start..end], "JWT_SECRET");
    }

    #[test]
    fn scan_roots_contain_every_redact_root_by_construction() {
        // This replaces a test that asserted one regex-source string started with
        // another; containment is now structural rather than copy-pasted.
        let scan = &*SCAN_ROOTS;
        for root in REDACT_ROOTS {
            assert!(scan.contains(root), "scan set is missing {root:?}");
        }
        assert_eq!(scan.len(), REDACT_ROOTS.len() + SCAN_ONLY_ROOTS.len());
    }

    #[test]
    fn assignment_roots_are_narrower_than_scan_roots_exactly_as_legacy_had_them() {
        let assignment = &*ASSIGNMENT_ROOTS;
        // Legacy's assignment pattern listed database_url and jwt_secret but not
        // access_key or client_secret.
        assert!(assignment.contains(&(&["DATABASE", "URL"] as KeywordRoot)));
        assert!(assignment.contains(&(&["JWT", "SECRET"] as KeywordRoot)));
        assert!(!assignment.contains(&(&["ACCESS", "KEY"] as KeywordRoot)));
        assert!(!assignment.contains(&(&["CLIENT", "SECRET"] as KeywordRoot)));
    }

    #[test]
    fn finds_the_leftmost_root() {
        let roots = &*SCAN_ROOTS;
        let line = "pass then token";
        let (start, end) = find_root(line, roots).expect("root found");
        assert_eq!(&line[start..end], "pass");
    }

    #[test]
    fn non_ascii_neighbours_are_word_characters_so_they_suppress_the_boundary() {
        assert!(!contains_root("ключTOKEN", REDACT_ROOTS));
        assert!(contains_root("ключ TOKEN", REDACT_ROOTS));
    }

    #[test]
    fn empty_input_and_empty_root_set_are_handled() {
        assert!(!contains_root("", REDACT_ROOTS));
        assert!(!contains_root("anything", &[]));
    }

    /// The corpus both span differential tests run over.
    ///
    /// Deliberately includes the awkward shapes: mismatched quotes, empty quoted
    /// values, a value containing an `=`, several mentions on one line, and a keyword
    /// with no value at all.
    fn assignment_corpus() -> Vec<String> {
        [
            r#"API_KEY: "abc123""#,
            "API_KEY='abc123'",
            "API_KEY=abc123",
            "API_KEY = abc123",
            r#"SECRET: "value'"#,
            r#"SECRET: """#,
            "SECRET: ''",
            r#"SECRET: "dXNlcjpwYXNzd29yZA==""#,
            "token: ",
            "token:",
            "token: value",
            "API_KEY=one SECRET=two",
            "PASSWORD: hunter2",
            "PRIVATE_KEY=abcdef0123456789",
            "no keywords at all here",
            "compass = 5",
            "MY_API_KEY=notbounded",
            "",
            "DATABASE_URL=postgres://admin@host/db",
            "  API_KEY = spaced",
            "api_key:value",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    }

    #[test]
    fn keyword_assignment_spans_match_the_regex_engine() {
        // These spans are what content redaction replaces, so their exact extent is a
        // compatibility surface: golden references contain the resulting text.
        let source = r#"(?i)\b(API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASS|PRIVATE[_-]?KEY)\b[ \t]*[:=][ \t]*(?:"[^\s"\n]+"|'[^\s'\n]+'|[^\s'"\n]+)"#;
        let regex = regex::Regex::new(source).expect("reference pattern must compile");

        for line in assignment_corpus() {
            let ours = find_keyword_assignments(&line, REDACT_ROOTS);
            let theirs: Vec<(usize, usize)> = regex
                .find_iter(&line)
                .map(|found| (found.start(), found.end()))
                .collect();
            assert_eq!(ours, theirs, "assignment spans disagreed on {line:?}");
        }
    }

    #[test]
    fn bearer_token_spans_match_the_regex_engine() {
        let regex = regex::Regex::new(r"(?i)\b(BEARER)[ \t]+[A-Za-z0-9._\-+/=]{16,}")
            .expect("reference pattern must compile");

        let corpus = [
            "Authorization: BEARER abcdefghijklmnopqrstuvwxyz",
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
            "Authorization: BEARER short",
            "Authorization: BEARER",
            "Authorization: BEARERabcdefghijklmnopq",
            "xBEARER abcdefghijklmnopqrstuvwxyz",
            "bearer 0123456789abcdef",
            "bearer 0123456789abcde",
            "no bearer here",
            "",
        ];

        for line in corpus {
            let ours = find_bearer_tokens(line);
            let theirs: Vec<(usize, usize)> = regex
                .find_iter(line)
                .map(|found| (found.start(), found.end()))
                .collect();
            assert_eq!(ours, theirs, "bearer spans disagreed on {line:?}");
        }
    }

    /// Differential check against the regex alternations these roots replaced.
    #[test]
    fn matches_the_regex_engine_on_keyword_mentions() {
        let redact_source = r"(?i)\b(API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASS|PRIVATE[_-]?KEY)\b";
        let scan_source = r"(?i)\b(API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASS|PRIVATE[_-]?KEY|DATABASE[_-]?URL|JWT[_-]?SECRET|ACCESS[_-]?KEY|CLIENT[_-]?SECRET)\b";

        let corpus = [
            "API_KEY=1",
            "API-KEY: 2",
            "APIKEY=3",
            "API__KEY=4",
            "MY_API_KEY=5",
            "api_keys=6",
            "SECRET",
            "secret_value",
            "the token is here",
            "PASSWORD:",
            "pass",
            "compass",
            "PRIVATE_KEY",
            "DATABASE_URL=postgres://x",
            "JWT_SECRET=abc",
            "ACCESS_KEY=abc",
            "CLIENT_SECRET=abc",
            "unrelated line of code",
            "",
            "ключ TOKEN",
            "ключTOKEN",
        ];

        let scan = &*SCAN_ROOTS;
        for (source, roots) in [(redact_source, REDACT_ROOTS), (scan_source, &scan[..])] {
            let regex = regex::Regex::new(source).expect("reference pattern must compile");
            for line in corpus {
                assert_eq!(
                    contains_root(line, roots),
                    regex.is_match(line),
                    "pattern {source} disagreed on {line:?}"
                );
            }
        }
    }
}
