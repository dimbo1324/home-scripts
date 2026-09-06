//! A small token matcher built from plain string operations, replacing the regexes that
//! described provider secret formats.
//!
//! ## Why not a regex
//!
//! Every vendor token signature has the same shape: a literal prefix, then a run of
//! characters drawn from a fixed alphabet, with a length constraint. Written as a regex
//! that shape disappears into pattern syntax — `AKIA[0-9A-Z]{16}` — and each of the ten
//! rules had to repeat the same `Regex::new(..).expect("hand-written pattern literal is
//! a valid regex, proven by test coverage")` incantation, because a regex is built from
//! a string at run time and can therefore fail to compile in a way the type system
//! cannot see. Nineteen copies of that same `expect` string were the visible symptom.
//!
//! Describing the shape as data instead makes the failure mode disappear: a
//! [`TokenPattern`] is a `const` value, so a malformed rule is a compile error rather
//! than a runtime panic guarded by a comment. It also runs without a regex engine, and
//! the rules read as what they are — "this prefix, then 16 of these characters".
//!
//! Equivalence with the regexes this replaced is verified, not assumed: see
//! `tests::matches_the_regex_engine_across_a_generated_corpus`, which checks every rule
//! against the original pattern over generated positive and negative inputs.
//!
//! ## What it deliberately cannot express
//!
//! Alternation, capture groups and repetition of groups are all absent. Rules that need
//! alternation (`gh[pous]_…` vs `github_pat_…`) are expressed as two patterns sharing a
//! rule id, which is clearer than one pattern with a branch. Nothing here needs more,
//! and keeping the vocabulary small is what makes the matcher auditable — this is
//! security-critical code whose behavior a reader must be able to confirm by eye.

use std::borrow::Cow;

/// The character alphabets vendor token formats draw from.
///
/// Named rather than inlined as ranges so a rule reads as a description of the format
/// ("uppercase and digits") instead of a character-class expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CharClass {
    /// `[0-9]`.
    Digit,
    /// `[0-9A-Z]` — AWS access key IDs are uppercase only.
    UpperAlnum,
    /// `[0-9A-Za-z]`.
    Alnum,
    /// `[0-9A-Za-z_-]` — the URL-safe base64 alphabet, used by most modern token
    /// formats and by JWT segments.
    AlnumUrlSafe,
    /// `[0-9A-Za-z_]` — underscore but **no dash**. GitHub's fine-grained tokens use
    /// this narrower alphabet; using [`Self::AlnumUrlSafe`] here instead made a run of
    /// dashes match a token shape that GitHub never issues. Caught by
    /// `tests::matches_the_regex_engine_across_a_generated_corpus`.
    AlnumUnderscore,
    /// `[0-9A-Za-z-]` — Slack's alphabet: dashes but no underscores.
    AlnumDash,
    /// `[A-Za-z0-9/+=]` — standard base64 including padding, for AWS secret values.
    Base64Standard,
    /// `[A-Z ]` — the words between `BEGIN` and `PRIVATE KEY` in a PEM header.
    UpperOrSpace,
    /// `[_.-]` — the separator styles a field name may use between words.
    NameSeparator,
    /// `['"]` — an optional quote around a configuration value.
    Quote,
    /// `[ \t]` — horizontal whitespace around an assignment operator.
    Space,
    /// `[:=]` — an assignment operator.
    Assignment,
}

impl CharClass {
    /// Whether `character` belongs to this class. ASCII-only by construction: every
    /// vendor format these classes describe is ASCII, so a non-ASCII character always
    /// terminates a run.
    const fn contains(self, character: u8) -> bool {
        match self {
            Self::Digit => character.is_ascii_digit(),
            Self::UpperAlnum => character.is_ascii_digit() || character.is_ascii_uppercase(),
            Self::Alnum => character.is_ascii_alphanumeric(),
            Self::AlnumUrlSafe => {
                character.is_ascii_alphanumeric() || character == b'_' || character == b'-'
            }
            Self::AlnumUnderscore => character.is_ascii_alphanumeric() || character == b'_',
            Self::AlnumDash => character.is_ascii_alphanumeric() || character == b'-',
            Self::Base64Standard => {
                character.is_ascii_alphanumeric()
                    || character == b'/'
                    || character == b'+'
                    || character == b'='
            }
            Self::UpperOrSpace => character.is_ascii_uppercase() || character == b' ',
            Self::NameSeparator => matches!(character, b'_' | b'.' | b'-'),
            Self::Quote => matches!(character, b'\'' | b'"'),
            Self::Space => matches!(character, b' ' | b'\t'),
            Self::Assignment => matches!(character, b':' | b'='),
        }
    }
}

/// No practical upper bound on a run length; the input line is always shorter.
const UNBOUNDED: usize = usize::MAX;

/// One element of a token format, matched in sequence.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Segment {
    /// Exact text. Compared case-sensitively unless the owning pattern says otherwise.
    Literal(&'static str),
    /// A run of `class` characters whose length lies in `min..=max`.
    Run {
        class: CharClass,
        min: usize,
        max: usize,
    },
}

impl Segment {
    /// A run of exactly `len` characters — `{n}` in regex terms.
    const fn exactly(class: CharClass, len: usize) -> Self {
        Self::Run {
            class,
            min: len,
            max: len,
        }
    }

    /// A run of `min` or more characters — `{n,}`.
    const fn at_least(class: CharClass, min: usize) -> Self {
        Self::Run {
            class,
            min,
            max: UNBOUNDED,
        }
    }

    /// Zero or one character — `?`.
    const fn optional(class: CharClass) -> Self {
        Self::Run {
            class,
            min: 0,
            max: 1,
        }
    }

    /// Zero or more characters — `*`.
    const fn any_number(class: CharClass) -> Self {
        Self::Run {
            class,
            min: 0,
            max: UNBOUNDED,
        }
    }
}

/// A whole token format: a sequence of segments, plus which segment carries the secret.
///
/// `segments` is a [`Cow`] so that the fixed formats below can be `const` values with
/// borrowed slices, while the vendors whose shapes differ only by prefix can build
/// theirs at startup without either leaking memory or repeating eleven near-identical
/// constants.
#[derive(Debug)]
pub(crate) struct TokenPattern {
    pub(crate) segments: Cow<'static, [Segment]>,
    /// Compare [`Segment::Literal`] text case-insensitively. Vendor prefixes are
    /// case-sensitive (`AKIA`, `eyJ`); configuration field names are not.
    pub(crate) case_insensitive: bool,
    /// Index into `segments` of the run holding the secret itself, when the pattern has
    /// to match surrounding context to be precise enough.
    ///
    /// `None` means the whole match is the secret, which is the case for every
    /// prefix-anchored vendor format. This is what the reported span covers, and the
    /// span is what gets masked before a message is built — reporting the whole match
    /// for a context-anchored rule would blank the very field name that tells the reader
    /// which key was found.
    pub(crate) value_segment: Option<usize>,
}

/// Where a pattern matched, and which part of it is the secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TokenMatch {
    /// Byte range of the secret — the whole match, or just the value segment.
    pub(crate) value_start: usize,
    pub(crate) value_end: usize,
}

/// Matches `segments[index..]` against `text` starting at `start`.
///
/// Runs are greedy and backtrack: a run takes the longest length its class and bounds
/// allow, then gives characters back one at a time until the rest of the pattern fits.
/// That is what lets `-----BEGIN [A-Z ]*PRIVATE KEY-----` work, where the greedy run
/// would otherwise swallow the literal that has to follow it.
///
/// Returns the end offset of the full match, and records the value segment's range in
/// `value_span` when it is matched.
fn match_from(
    text: &[u8],
    start: usize,
    segments: &[Segment],
    index: usize,
    case_insensitive: bool,
    value_segment: Option<usize>,
    value_span: &mut Option<(usize, usize)>,
) -> Option<usize> {
    let Some(segment) = segments.get(index) else {
        return Some(start);
    };

    match *segment {
        Segment::Literal(literal) => {
            let end = start.checked_add(literal.len())?;
            let candidate = text.get(start..end)?;
            let matches = if case_insensitive {
                candidate.eq_ignore_ascii_case(literal.as_bytes())
            } else {
                candidate == literal.as_bytes()
            };
            if !matches {
                return None;
            }
            match_from(
                text,
                end,
                segments,
                index + 1,
                case_insensitive,
                value_segment,
                value_span,
            )
        }
        Segment::Run { class, min, max } => {
            // Longest run this class allows from `start`, capped by `max`.
            let mut longest = start;
            while longest < text.len() && longest - start < max && class.contains(text[longest]) {
                longest += 1;
            }
            if longest - start < min {
                return None;
            }

            // Give characters back until the remaining segments fit.
            let mut length = longest - start;
            loop {
                let end = start + length;
                if let Some(total_end) = match_from(
                    text,
                    end,
                    segments,
                    index + 1,
                    case_insensitive,
                    value_segment,
                    value_span,
                ) {
                    if value_segment == Some(index) {
                        *value_span = Some((start, end));
                    }
                    return Some(total_end);
                }
                if length == min {
                    return None;
                }
                length -= 1;
            }
        }
    }
}

/// Finds every non-overlapping match of `pattern` in `line`, left to right.
///
/// Scanning restarts after the end of each match, which is how a regex engine's
/// `find_iter` behaves and what keeps one long secret from producing several findings.
pub(crate) fn find_matches(line: &str, pattern: &TokenPattern) -> Vec<TokenMatch> {
    let text = line.as_bytes();
    let mut matches = Vec::new();
    let mut cursor = 0usize;

    while cursor <= text.len() {
        let mut value_span = None;
        let matched_end = match_from(
            text,
            cursor,
            &pattern.segments,
            0,
            pattern.case_insensitive,
            pattern.value_segment,
            &mut value_span,
        );

        let Some(match_end) = matched_end else {
            cursor += 1;
            continue;
        };

        let (value_start, value_end) = match (pattern.value_segment, value_span) {
            // A context-anchored rule reports only its value segment.
            (Some(_), Some(span)) => span,
            // Either the whole match is the secret, or the value segment was optional
            // and absent; reporting the whole match is the safe fallback, since an
            // unreported span would be left unmasked.
            _ => (cursor, match_end),
        };
        matches.push(TokenMatch {
            value_start,
            value_end,
        });

        // A zero-width match would loop forever; advance at least one byte.
        cursor = match_end.max(cursor + 1);
    }

    matches
}

/// Convenience wrapper for rules that only need a yes/no answer.
pub(crate) fn is_match(line: &str, pattern: &TokenPattern) -> bool {
    !find_matches(line, pattern).is_empty()
}

// --- The vendor token formats -------------------------------------------------------
//
// Each is the direct transcription of the regex it replaces; the regex is quoted above
// each so the two can be compared by eye, and the differential test below proves they
// agree in practice.

/// `AKIA[0-9A-Z]{16}`
pub(crate) const AWS_ACCESS_KEY_ID: TokenPattern = TokenPattern {
    segments: Cow::Borrowed(&[
        Segment::Literal("AKIA"),
        Segment::exactly(CharClass::UpperAlnum, 16),
    ]),
    case_insensitive: false,
    value_segment: None,
};

/// `(?i)(?:aws[_.\-]?)?secret[_.\-]?access[_.\-]?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40,})`
///
/// The value has no distinguishing prefix — it is 40 characters of base64, a shape
/// shared by hashes, build identifiers and minified tokens — so the rule is anchored on
/// AWS's own field name instead, in the spellings the SDKs and CLI actually use.
///
/// `aws` is optional only because `secretAccessKey` is itself an AWS SDK field name
/// rather than a generic phrase. The value run is unbounded above so that a longer value
/// is covered completely; reporting only its first 40 characters would leave the tail
/// unmasked in the finding message.
///
/// Legacy note: the original wrote the optional `aws` prefix as a non-capturing group.
/// Here it is two segments, an optional literal being expressible only as a separate
/// pattern, so this rule is registered twice — once with the prefix, once without.
pub(crate) const AWS_SECRET_WITH_PREFIX: TokenPattern = TokenPattern {
    segments: Cow::Borrowed(&[
        Segment::Literal("aws"),
        Segment::optional(CharClass::NameSeparator),
        Segment::Literal("secret"),
        Segment::optional(CharClass::NameSeparator),
        Segment::Literal("access"),
        Segment::optional(CharClass::NameSeparator),
        Segment::Literal("key"),
        Segment::optional(CharClass::Quote),
        Segment::any_number(CharClass::Space),
        Segment::exactly(CharClass::Assignment, 1),
        Segment::any_number(CharClass::Space),
        Segment::optional(CharClass::Quote),
        Segment::at_least(CharClass::Base64Standard, 40),
    ]),
    case_insensitive: true,
    value_segment: Some(12),
};

/// [`AWS_SECRET_WITH_PREFIX`] without the optional `aws` word.
pub(crate) const AWS_SECRET_BARE: TokenPattern = TokenPattern {
    segments: Cow::Borrowed(&[
        Segment::Literal("secret"),
        Segment::optional(CharClass::NameSeparator),
        Segment::Literal("access"),
        Segment::optional(CharClass::NameSeparator),
        Segment::Literal("key"),
        Segment::optional(CharClass::Quote),
        Segment::any_number(CharClass::Space),
        Segment::exactly(CharClass::Assignment, 1),
        Segment::any_number(CharClass::Space),
        Segment::optional(CharClass::Quote),
        Segment::at_least(CharClass::Base64Standard, 40),
    ]),
    case_insensitive: true,
    value_segment: Some(10),
};

/// `gh[pous]_[A-Za-z0-9]{36}` — the classic personal/OAuth/user/server token shapes.
///
/// The four prefixes are listed separately rather than as a character alternation; at
/// four entries that is shorter than a class would be and needs no new vocabulary.
pub(crate) const GITHUB_TOKEN_PREFIXES: [&str; 4] = ["ghp_", "gho_", "ghu_", "ghs_"];

/// `github_pat_[A-Za-z0-9_]{82}` — the fine-grained token shape.
pub(crate) const GITHUB_FINE_GRAINED_TOKEN: TokenPattern = TokenPattern {
    segments: Cow::Borrowed(&[
        Segment::Literal("github_pat_"),
        // `[A-Za-z0-9_]`: alphanumerics and underscore, deliberately no dash.
        Segment::exactly(CharClass::AlnumUnderscore, 82),
    ]),
    case_insensitive: false,
    value_segment: None,
};

/// `AIza[0-9A-Za-z\-_]{35}`
pub(crate) const GOOGLE_API_KEY: TokenPattern = TokenPattern {
    segments: Cow::Borrowed(&[
        Segment::Literal("AIza"),
        Segment::exactly(CharClass::AlnumUrlSafe, 35),
    ]),
    case_insensitive: false,
    value_segment: None,
};

/// `xox[baprs]-[0-9A-Za-z-]{10,72}`
pub(crate) const SLACK_TOKEN_PREFIXES: [&str; 5] = ["xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"];

/// `(sk|rk)_live_[0-9A-Za-z]{24,}`
pub(crate) const STRIPE_KEY_PREFIXES: [&str; 2] = ["sk_live_", "rk_live_"];

/// `sk-ant-[A-Za-z0-9_-]{20,}`
pub(crate) const ANTHROPIC_API_KEY: TokenPattern = TokenPattern {
    segments: Cow::Borrowed(&[
        Segment::Literal("sk-ant-"),
        Segment::at_least(CharClass::AlnumUrlSafe, 20),
    ]),
    case_insensitive: false,
    value_segment: None,
};

/// `sk-[A-Za-z0-9]{20,}` — checked only after the Anthropic rule, which shares the
/// `sk-` prefix.
pub(crate) const OPENAI_API_KEY: TokenPattern = TokenPattern {
    segments: Cow::Borrowed(&[
        Segment::Literal("sk-"),
        Segment::at_least(CharClass::Alnum, 20),
    ]),
    case_insensitive: false,
    value_segment: None,
};

/// `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` — a JWT's three base64url
/// segments. `eyJ` is the base64 encoding of `{"`, so it is how every JWT header starts.
pub(crate) const JWT: TokenPattern = TokenPattern {
    segments: Cow::Borrowed(&[
        Segment::Literal("eyJ"),
        Segment::at_least(CharClass::AlnumUrlSafe, 1),
        Segment::Literal("."),
        Segment::at_least(CharClass::AlnumUrlSafe, 1),
        Segment::Literal("."),
        Segment::at_least(CharClass::AlnumUrlSafe, 1),
    ]),
    case_insensitive: false,
    value_segment: None,
};

/// `-----BEGIN [A-Z ]*PRIVATE KEY-----`
///
/// The `[A-Z ]*` run is why the matcher backtracks: greedily it swallows
/// `RSA PRIVATE KEY`, which is all uppercase and spaces, and the trailing literal then
/// has nothing left to match against.
pub(crate) const PEM_PRIVATE_KEY: TokenPattern = TokenPattern {
    segments: Cow::Borrowed(&[
        Segment::Literal("-----BEGIN "),
        Segment::any_number(CharClass::UpperOrSpace),
        Segment::Literal("PRIVATE KEY-----"),
    ]),
    case_insensitive: false,
    value_segment: None,
};

/// `\d{8,10}:[A-Za-z0-9_-]{35}`
pub(crate) const TELEGRAM_BOT_TOKEN: TokenPattern = TokenPattern {
    segments: Cow::Borrowed(&[
        Segment::Run {
            class: CharClass::Digit,
            min: 8,
            max: 10,
        },
        Segment::Literal(":"),
        Segment::exactly(CharClass::AlnumUrlSafe, 35),
    ]),
    case_insensitive: false,
    value_segment: None,
};

/// Builds a `<prefix><run>` pattern for the vendor formats that differ only in their
/// literal prefix — GitHub's four classic token kinds, Slack's five, Stripe's two.
///
/// Owns its segments rather than borrowing, which is what the [`Cow`] on
/// [`TokenPattern::segments`] is for: eleven near-identical constants would otherwise
/// have to be written out by hand.
pub(crate) fn prefixed(
    prefix: &'static str,
    class: CharClass,
    min: usize,
    max: usize,
) -> TokenPattern {
    TokenPattern {
        segments: Cow::Owned(vec![
            Segment::Literal(prefix),
            Segment::Run { class, min, max },
        ]),
        case_insensitive: false,
        value_segment: None,
    }
}

#[cfg(test)]
mod tests;
