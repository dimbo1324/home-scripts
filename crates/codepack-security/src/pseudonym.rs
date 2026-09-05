//! Stable per-secret labels: telling two redacted values apart without revealing either.
//!
//! ## The problem this solves
//!
//! Redaction replaces every secret with the same placeholder, so a reader of the bundle
//! — very often a language model — sees `DATABASE_URL=<REDACTED>` in three files and
//! cannot tell whether that is one credential used three times or three different ones.
//! The structure is gone along with the values, and structure is exactly what somebody
//! reasoning about the code needs: "the worker and the API talk to the same database"
//! is a fact about the project, not about the password.
//!
//! With labels on, the first distinct secret becomes `<REDACTED:s1>`, the second
//! `<REDACTED:s2>`, and every later occurrence of the first is `<REDACTED:s1>` again.
//!
//! ## Why a counter and not a hash
//!
//! A hash of the value would be simpler — no shared state, stable across runs — and it
//! would be wrong. A truncated hash printed beside a secret is a *commitment* to it: a
//! reader who guesses `hunter2` can hash the guess and confirm it, which turns every
//! redacted low-entropy secret into a checkable dictionary attack. Invariant I3 says the
//! value never leaves the redactor, and a verifiable fingerprint of the value is a form
//! of leaving.
//!
//! A first-seen counter reveals only what the reader can already see: how many distinct
//! secrets there are and which occurrences coincide. That is the entire feature, with
//! nothing extra attached.
//!
//! The cost is that labels are per-run and order-dependent — `s1` in yesterday's bundle
//! is not necessarily `s1` in today's. They are a key to one document, not an identity
//! across documents; [`crate::scan::Finding`] fingerprints already fill that role, and
//! they are computed from the redacted message rather than the secret.
//!
//! ## Scope
//!
//! Off by default (`Config::redaction_labels`). With it off every placeholder is byte
//! for byte what it has always been, so no artifact moves and no `schema_version`
//! changes.

use std::collections::HashMap;
use std::sync::Mutex;

/// First-seen numbering of the distinct secrets in one run.
#[derive(Debug, Default)]
pub struct Labels {
    seen: Mutex<HashMap<String, usize>>,
}

impl Labels {
    /// The label for `secret`, assigning the next number the first time it is seen.
    ///
    /// Poisoning is handled by taking the inner value rather than propagating: a panic
    /// in another thread must not turn redaction — the thing standing between a secret
    /// and the output — into a panic of its own.
    fn label(&self, secret: &str) -> usize {
        let key = normalise(secret);
        let mut seen = self.seen.lock().unwrap_or_else(|error| error.into_inner());
        let next = seen.len() + 1;
        *seen.entry(key).or_insert(next)
    }

    /// How many distinct secrets have been labelled so far. Reported by
    /// [`crate::Redactor::distinct_secrets`] so an artifact header can say how many
    /// different credentials the labels stand for.
    pub fn distinct(&self) -> usize {
        self.seen
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len()
    }
}

/// Two spellings of the same secret get the same label.
///
/// Quotes and surrounding whitespace are syntax, not value: `KEY="abc"`, `KEY = abc` and
/// `KEY: 'abc'` all carry `abc`. A trailing comma or semicolon is punctuation from the
/// language, and is stripped for the same reason.
fn normalise(secret: &str) -> String {
    let trimmed = secret.trim().trim_end_matches([',', ';']).trim();
    let unquoted = match trimmed.chars().next() {
        Some(quote @ ('"' | '\'')) if trimmed.len() >= 2 && trimmed.ends_with(quote) => {
            &trimmed[1..trimmed.len() - 1]
        }
        _ => trimmed,
    };
    unquoted.to_string()
}

/// Which of the three replacement roles a placeholder plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaceholderKind {
    /// The value after a key: `API_KEY=<REDACTED>`.
    Value,
    /// A span with no key of its own — a bare token, a provider signature.
    Bare,
    /// A whole collapsed line, produced by `keyword::redacted_line_with`. Never
    /// labelled: the "secret" is a line of source, and a label would claim two lines are
    /// the same credential when all they share is their text.
    Line,
}

/// Spells one placeholder. **The only place a placeholder is written.**
///
/// Paired with [`parse_placeholder`] and pinned to it by a round-trip test, so what this
/// module produces and what it recognises cannot drift apart.
fn render(kind: PlaceholderKind, label: Option<usize>) -> String {
    match (kind, label) {
        (PlaceholderKind::Value, None) => "<REDACTED>".to_string(),
        (PlaceholderKind::Value, Some(n)) => format!("<REDACTED:s{n}>"),
        (PlaceholderKind::Bare, None) => "<REDACTED_SECRET>".to_string(),
        (PlaceholderKind::Bare, Some(n)) => format!("<REDACTED_SECRET:s{n}>"),
        // A labelled line form does not exist; asking for one is a caller's mistake, and
        // answering with the unlabelled spelling is the safe reading of it.
        (PlaceholderKind::Line, _) => "<REDACTED_SECRET_LINE>".to_string(),
    }
}

/// The placeholder `text` is, **exactly**, or `None`.
///
/// Exact rather than "starts with a known prefix and ends with `>`". That heuristic
/// accepted `<REDACTED>real-secret-value>` as an already-redacted value and returned it
/// verbatim — the one function that decides "this is already safe" failing towards
/// *skip*, in the component that is invariant I3's last line of defence. File content is
/// untrusted input to the redactor: it is data, not something the product wrote.
pub fn parse_placeholder(text: &str) -> Option<(PlaceholderKind, Option<usize>)> {
    let labelled = |body: &str| -> Option<usize> {
        // `sN`, N a run of digits and nothing else. `s1x`, `s`, `s01`-with-a-space and
        // an empty label all fail here rather than being waved through.
        let digits = body.strip_prefix('s')?;
        (!digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| digits.parse().ok())
            .flatten()
    };

    let inner = text.strip_prefix('<')?.strip_suffix('>')?;
    match inner {
        "REDACTED" => Some((PlaceholderKind::Value, None)),
        "REDACTED_SECRET" => Some((PlaceholderKind::Bare, None)),
        "REDACTED_SECRET_LINE" => Some((PlaceholderKind::Line, None)),
        _ => {
            // The bare prefix is tried first: `REDACTED_SECRET:s1` also starts with
            // `REDACTED`, but not with `REDACTED:`, so the two cannot be confused.
            if let Some(body) = inner.strip_prefix("REDACTED_SECRET:") {
                labelled(body).map(|n| (PlaceholderKind::Bare, Some(n)))
            } else if let Some(body) = inner.strip_prefix("REDACTED:") {
                labelled(body).map(|n| (PlaceholderKind::Value, Some(n)))
            } else {
                None
            }
        }
    }
}

/// Where this module's placeholders sit in `line`, as byte ranges.
///
/// Lives beside the renderer for the reason above: a consumer that scans for them with
/// its own idea of their shape is a second, unpinned definition. A run that merely
/// *starts* like a placeholder is not one, so a line genuinely discussing `<REDACTED:`
/// as text is still scanned.
pub fn placeholder_spans(line: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut from = 0usize;
    while let Some(offset) = line[from..].find('<') {
        let start = from + offset;
        // A placeholder cannot contain `>`, so the first one after `<` is the only
        // candidate end. Anything else is not a placeholder however it continues.
        match line[start..].find('>') {
            Some(close) => {
                let end = start + close + 1;
                if parse_placeholder(&line[start..end]).is_some() {
                    spans.push((start, end));
                    from = end;
                } else {
                    from = start + 1;
                }
            }
            None => break,
        }
    }
    spans
}

/// The placeholder `secret` already is, if it is one.
///
/// **Redacting a placeholder yields that same placeholder.** Without this, a second
/// redaction pass over already-redacted text treats `<REDACTED:s1>` as a fresh secret
/// and hands it `s2` — which is how one credential came out labelled `s1` in
/// `03_text_dump.txt` and `s2` in `06_security_scan.json`. Matching a value across a
/// bundle is the only thing labels are for, so that was the feature failing quietly.
///
/// Two passes are by design, not an accident to remove: `redacted_line_with` redacts
/// content and then collapses what is left of a keyword line, and the scan's message
/// builder masks bare provider and entropy spans afterwards. Making the substitution
/// idempotent fixes every one of them at once, including the next one somebody adds.
fn existing_placeholder(secret: &str) -> Option<String> {
    let candidate = normalise(secret);
    parse_placeholder(&candidate).map(|_| candidate)
}

/// The whole-line placeholder, for `keyword::redacted_line_with`'s collapse case.
///
/// A function rather than a literal at the call site: every placeholder in the product
/// is spelled by [`render`], so there is exactly one definition to keep in step with
/// [`parse_placeholder`].
pub(crate) fn line_placeholder() -> String {
    render(PlaceholderKind::Line, None)
}

/// How a redaction site spells its replacement.
///
/// Threaded through the redaction functions rather than read from a global: two exports
/// can run in the same process (the desktop app), and their labels must not share a
/// numbering.
#[derive(Debug, Clone, Copy)]
pub struct Placeholders<'a> {
    labels: Option<&'a Labels>,
}

impl<'a> Placeholders<'a> {
    /// Today's behaviour, unchanged: one indistinguishable placeholder.
    pub fn plain() -> Self {
        Self { labels: None }
    }

    pub fn labelled(labels: &'a Labels) -> Self {
        Self {
            labels: Some(labels),
        }
    }

    /// Replacement for a value that follows a key (`API_KEY=<here>`).
    pub fn value(&self, secret: &str) -> String {
        if let Some(existing) = existing_placeholder(secret) {
            return existing;
        }
        render(PlaceholderKind::Value, self.labels.map(|l| l.label(secret)))
    }

    /// Replacement for a span with no key of its own — a bare token, a provider
    /// signature, a password inside a URL.
    pub fn bare(&self, secret: &str) -> String {
        if let Some(existing) = existing_placeholder(secret) {
            return existing;
        }
        render(PlaceholderKind::Bare, self.labels.map(|l| l.label(secret)))
    }
}

/// Every placeholder shape redaction can produce, as literal prefixes.
///
/// A *prefix* list answers "does this line contain redaction at all", which is all the
/// text dump's counter needs. It is not a way to decide whether a given value **is** a
/// placeholder — that question is [`parse_placeholder`], and answering it by prefix is
/// what audit No. 7 found: `<REDACTED>real-secret-value>` passed. A round-trip test pins
/// this list to what [`render`] actually emits.
pub const REDACTION_PLACEHOLDER_PREFIXES: &[&str] = &[
    "<REDACTED_SECRET_LINE>",
    "<REDACTED_SECRET:",
    "<REDACTED_SECRET>",
    "<REDACTED:",
    "<REDACTED>",
];

#[cfg(test)]
mod tests {
    use super::*;

    // --- Recognition is exact, and pinned to production -------------------------------
    //
    // Audit No. 7: `existing_placeholder` matched a known prefix and a closing `>`, so
    // `<REDACTED>real-secret-value>` was accepted as "already redacted" and returned
    // verbatim. The one function that decides a value is already safe failed towards
    // skip, in the component invariant I3 rests on.

    /// Every shape `render` can produce is recognised by `parse_placeholder`, and comes
    /// back as the same kind and label. This is what keeps the writer and the reader
    /// from drifting apart.
    #[test]
    fn every_rendered_placeholder_parses_back_to_itself() {
        let kinds = [
            PlaceholderKind::Value,
            PlaceholderKind::Bare,
            PlaceholderKind::Line,
        ];
        for kind in kinds {
            for label in [None, Some(1), Some(7), Some(1234)] {
                let text = render(kind, label);
                let (parsed_kind, parsed_label) = parse_placeholder(&text)
                    .unwrap_or_else(|| panic!("{text} is produced but not recognised"));
                assert_eq!(parsed_kind, kind, "{text}");
                // The line form has no labelled spelling, so it renders unlabelled
                // whatever it is asked for — and must parse back that way too.
                let expected = if kind == PlaceholderKind::Line {
                    None
                } else {
                    label
                };
                assert_eq!(parsed_label, expected, "{text}");
            }
        }
    }

    /// The prefix list is a "does this line contain redaction" filter, not a recogniser.
    /// It still has to describe what is actually written, or the text dump's counter
    /// stops seeing a shape.
    #[test]
    fn the_prefix_list_covers_every_shape_that_is_produced() {
        for kind in [
            PlaceholderKind::Value,
            PlaceholderKind::Bare,
            PlaceholderKind::Line,
        ] {
            for label in [None, Some(3)] {
                let text = render(kind, label);
                assert!(
                    REDACTION_PLACEHOLDER_PREFIXES
                        .iter()
                        .any(|prefix| text.starts_with(prefix)),
                    "{text} is produced but no prefix matches it"
                );
            }
        }
    }

    /// The exact case the audit names: a secret wrapped to look like a placeholder must
    /// be redacted, not returned.
    #[test]
    fn a_secret_wrapped_to_look_like_a_placeholder_is_still_redacted() {
        let labels = Labels::default();
        let placeholders = Placeholders::labelled(&labels);

        for crafted in [
            "<REDACTED>real-secret-value>",
            "<REDACTED:s1>real-secret-value>",
            "<REDACTED_SECRET>AKIAIOSFODNN7EXAMPLE>",
            "<REDACTED:>",
            "<REDACTED:sx>",
            "<REDACTED:s1x>",
            "<REDACTED_SECRET_LINE:s1>",
            "<REDACTEDsomething>",
        ] {
            let answer = placeholders.value(crafted);
            assert_ne!(
                answer, crafted,
                "{crafted} was passed through as if it were already redacted"
            );
            assert!(
                parse_placeholder(&answer).is_some(),
                "{crafted} produced {answer}, which is not a placeholder"
            );
        }
    }

    /// The general form of the rule, over a spread of placeholder-shaped inputs rather
    /// than one example: whatever comes in, what comes out is **always exactly a
    /// placeholder**. That is the property worth stating, and it is strictly stronger
    /// than "the secret is not in the output" — a placeholder cannot carry anything,
    /// because its whole grammar is `<REDACTED>`, `<REDACTED:sN>` and their two bare
    /// siblings, with no room for a payload.
    ///
    /// A value that *is* already a placeholder comes back as itself, which is the
    /// idempotence the two-pass design needs.
    #[test]
    fn every_answer_is_exactly_a_placeholder_whatever_went_in() {
        let labels = Labels::default();
        let placeholders = Placeholders::labelled(&labels);

        let fragments = [
            "",
            "<",
            ">",
            "REDACTED",
            ":s1",
            "secret-value",
            " ",
            "_SECRET",
        ];
        for a in fragments {
            for b in fragments {
                for c in fragments {
                    let candidate = format!("<REDACTED{a}{b}{c}>");
                    for answer in [
                        placeholders.value(&candidate),
                        placeholders.bare(&candidate),
                    ] {
                        assert!(
                            parse_placeholder(&answer).is_some(),
                            "{candidate} produced {answer}, which is not a placeholder"
                        );
                        if parse_placeholder(&normalise(&candidate)).is_some() {
                            assert_eq!(answer, normalise(&candidate), "{candidate}");
                        }
                    }
                }
            }
        }
    }

    /// Spans are found by the same exact rule, so a crafted wrapper cannot make a
    /// consumer skip over the secret inside it.
    #[test]
    fn spans_cover_real_placeholders_and_not_crafted_ones() {
        let line = "a=<REDACTED:s1> b=<REDACTED>oops> c=<REDACTED_SECRET_LINE>";
        let spans = placeholder_spans(line);
        let found: Vec<&str> = spans.iter().map(|(s, e)| &line[*s..*e]).collect();
        assert_eq!(
            found,
            vec!["<REDACTED:s1>", "<REDACTED>", "<REDACTED_SECRET_LINE>"],
            "the crafted wrapper must not swallow `oops>`"
        );
    }

    #[test]
    fn an_unterminated_run_produces_no_span() {
        assert!(placeholder_spans("<REDACTED:s1 never closed").is_empty());
        assert!(placeholder_spans("prose about <REDACTED: markers").is_empty());
    }

    #[test]
    fn the_same_secret_gets_the_same_label_and_a_different_one_does_not() {
        let labels = Labels::default();
        let placeholders = Placeholders::labelled(&labels);

        assert_eq!(placeholders.value("hunter2"), "<REDACTED:s1>");
        assert_eq!(placeholders.value("other"), "<REDACTED:s2>");
        assert_eq!(placeholders.value("hunter2"), "<REDACTED:s1>");
        assert_eq!(labels.distinct(), 2);
    }

    #[test]
    fn quoting_and_spacing_do_not_create_a_second_identity() {
        let labels = Labels::default();
        let placeholders = Placeholders::labelled(&labels);

        assert_eq!(placeholders.value(" abc "), "<REDACTED:s1>");
        assert_eq!(placeholders.value("\"abc\""), "<REDACTED:s1>");
        assert_eq!(placeholders.value("'abc',"), "<REDACTED:s1>");
        assert_eq!(labels.distinct(), 1);
    }

    #[test]
    fn a_label_never_contains_any_part_of_the_secret() {
        // The whole point. A label is a position in a list, not a function of the value,
        // so it cannot be tested against a guess.
        let labels = Labels::default();
        let placeholders = Placeholders::labelled(&labels);

        let label = placeholders.value("wJalrXUtnFEMI/K7MDENG/bPxRfiCY");
        assert_eq!(label, "<REDACTED:s1>");
        assert!(!label.contains("wJal"));
        assert!(!label.contains("bPxRfiCY"));
    }

    #[test]
    fn the_plain_mode_spelling_is_exactly_what_it_always_was() {
        let placeholders = Placeholders::plain();
        assert_eq!(placeholders.value("anything"), "<REDACTED>");
        assert_eq!(placeholders.bare("anything"), "<REDACTED_SECRET>");
    }

    #[test]
    fn a_mismatched_quote_is_not_stripped() {
        // `"abc` is not a quoted `abc`; treating it as one would merge two different
        // values under one label.
        let labels = Labels::default();
        let placeholders = Placeholders::labelled(&labels);
        placeholders.value("\"abc");
        placeholders.value("abc");
        assert_eq!(labels.distinct(), 2);
    }

    #[test]
    fn two_runs_number_independently() {
        // A desktop process can run two exports; sharing a counter would leak the fact
        // that a value appeared in an earlier, unrelated bundle.
        let first = Labels::default();
        let second = Labels::default();
        assert_eq!(Placeholders::labelled(&first).value("a"), "<REDACTED:s1>");
        assert_eq!(Placeholders::labelled(&second).value("b"), "<REDACTED:s1>");
    }

    // --- Redacting a placeholder yields that same placeholder -------------------------
    //
    // Two redaction passes over one line are by design, so the substitution has to be
    // idempotent. It was not, and the failure was silent: the second pass treated
    // `<REDACTED:s1>` as a fresh secret and issued `s2`, so one credential came out
    // labelled differently in `03_text_dump.txt` and `06_security_scan.json` — which is
    // the only thing labels exist to prevent.

    #[test]
    fn a_labelled_placeholder_survives_a_second_pass_unchanged() {
        let labels = Labels::default();
        let placeholders = Placeholders::labelled(&labels);

        let first = placeholders.value("hunter2hunter2");
        assert_eq!(first, "<REDACTED:s1>");
        assert_eq!(
            placeholders.value(&first),
            first,
            "a second pass must not relabel"
        );
        assert_eq!(
            labels.distinct(),
            1,
            "the placeholder is not a second credential"
        );
    }

    #[test]
    fn the_bare_form_is_idempotent_too() {
        let labels = Labels::default();
        let placeholders = Placeholders::labelled(&labels);

        let first = placeholders.bare("AKIAIOSFODNN7EXAMPLE");
        assert_eq!(first, "<REDACTED_SECRET:s1>");
        assert_eq!(placeholders.bare(&first), first);
        assert_eq!(labels.distinct(), 1);
    }

    /// A placeholder produced by one form must not be renamed by the other. This is the
    /// exact crossing that broke: content redaction writes `<REDACTED:sN>` and the scan
    /// message builder then masks bare spans.
    #[test]
    fn the_two_forms_do_not_rename_each_other_s_placeholders() {
        let labels = Labels::default();
        let placeholders = Placeholders::labelled(&labels);

        let value_form = placeholders.value("first-credential");
        let bare_form = placeholders.bare("second-credential");

        assert_eq!(placeholders.bare(&value_form), value_form);
        assert_eq!(placeholders.value(&bare_form), bare_form);
        assert_eq!(labels.distinct(), 2, "still exactly two real credentials");
    }

    /// Quoting is syntax, so a placeholder wrapped in quotes is still a placeholder —
    /// the same rule `normalise` already applies to values.
    #[test]
    fn a_quoted_placeholder_is_recognised() {
        let labels = Labels::default();
        let placeholders = Placeholders::labelled(&labels);

        assert_eq!(placeholders.value("\"<REDACTED:s4>\""), "<REDACTED:s4>");
        assert_eq!(placeholders.value(" <REDACTED:s4> "), "<REDACTED:s4>");
        assert_eq!(labels.distinct(), 0);
    }

    /// Text that merely *starts* like a placeholder is not one, or a line of real prose
    /// discussing redaction would stop being scanned.
    #[test]
    fn an_unterminated_placeholder_is_not_treated_as_one() {
        let labels = Labels::default();
        let placeholders = Placeholders::labelled(&labels);

        let answer = placeholders.value("<REDACTED:s1 and then some actual secret");
        assert_eq!(
            answer, "<REDACTED:s1>",
            "it is redacted as a value, not passed through"
        );
        assert_eq!(labels.distinct(), 1);
    }

    /// Plain mode has always produced one indistinguishable placeholder, and still does.
    /// The idempotence rule must not change what an unlabelled run writes — the golden
    /// references are the proof, and this is the unit-level statement of the same thing.
    #[test]
    fn plain_mode_is_unchanged_by_the_idempotence_rule() {
        let placeholders = Placeholders::plain();

        assert_eq!(placeholders.value("hunter2"), "<REDACTED>");
        assert_eq!(
            placeholders.bare("AKIAIOSFODNN7EXAMPLE"),
            "<REDACTED_SECRET>"
        );
        // And re-reading its own output keeps the spelling it already had.
        assert_eq!(placeholders.value("<REDACTED>"), "<REDACTED>");
        assert_eq!(placeholders.bare("<REDACTED_SECRET>"), "<REDACTED_SECRET>");
    }
}
