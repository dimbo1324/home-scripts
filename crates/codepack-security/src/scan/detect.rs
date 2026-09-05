//! What one line, or one file name, means.
//!
//! Everything here is a pure decision over text already in memory: no file is opened, no
//! state is kept. The cascade that picks *which* detector's answer survives is
//! [`collect_secret_hits`], and its ordering is load-bearing — read its doc comment
//! before changing anything in this file.

use std::path::Path;

use crate::constants;
use crate::patterns::{checksum, credentials, entropy, keyword, prefilter, provider, risky_code};

fn file_name_lower(path: &Path) -> String {
    path.file_name()
        .map(|value| value.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

fn extension_lower(path: &Path) -> String {
    path.extension()
        .map(|value| value.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

/// Legacy `_collect_security_findings`'s sensitive-file check: `name ∈
/// SENSITIVE_FILENAMES OR suffix ∈ SENSITIVE_SUFFIXES OR name.startswith(".env")`,
/// `critical` when the name starts with `.env` or the suffix is one of
/// `{key,pem,p12,pfx}`, `high` otherwise.
pub(super) fn sensitive_file_severity(relative: &Path) -> Option<&'static str> {
    let name = file_name_lower(relative);
    let suffix = extension_lower(relative);
    let is_sensitive = constants::is_sensitive_filename(&name)
        || constants::is_sensitive_suffix(&suffix)
        || name.starts_with(".env");
    if !is_sensitive {
        return None;
    }
    let critical =
        name.starts_with(".env") || matches!(suffix.as_str(), "key" | "pem" | "p12" | "pfx");
    Some(if critical { "critical" } else { "high" })
}

pub(super) struct SecretHit {
    pub(super) rule: &'static str,
    pub(super) confidence: &'static str,
}

/// The confidence a provider match is reported at.
///
/// Normally the rule's own, unchanged. In strict mode a token whose vendor checksum
/// recomputes to something else is reported at `medium`: still a finding, still naming
/// the vendor, but no longer strong enough to trip a `--fail-on critical` gate. That is
/// the whole precision gain — a documentation sample such as
/// `ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` stops reading as a live credential.
///
/// A verdict of `Unknown` never weakens anything: it means this build cannot check that
/// vendor's format, which is not evidence about the token.
fn provider_confidence(
    line: &str,
    found: &provider::ProviderMatch,
    strict_checksums: bool,
) -> &'static str {
    if !strict_checksums {
        return found.confidence;
    }
    // `find_provider_matches` reports byte offsets into this same line, and the shapes
    // it matches are ASCII, so the slice is always on a character boundary.
    let token = &line[found.start..found.end];
    match checksum::verdict_for(found.rule_id, token) {
        checksum::ChecksumVerdict::Invalid => "medium",
        checksum::ChecksumVerdict::Valid | checksum::ChecksumVerdict::Unknown => found.confidence,
    }
}

/// Runs every secret detector over one line and applies the self-protection exemption
/// once, uniformly, across all of them (keyword, provider, entropy) — not only the
/// keyword cascade, which is the minimum legacy required.
///
/// **At most one hit per line**, because legacy's `_collect_security_findings` appends at
/// most one `SecretFinding` per line and a second finding on the identical file+line
/// breaks golden parity outright.
///
/// Which one survives is chosen by how much it tells the user, not by detector order:
///
/// 1. **A confident keyword hit wins**, meaning `critical` or `high`. These are the tiers
///    legacy itself treats as definitive (the `critical` tier is the PEM private-key
///    header), so reporting anything else there would be a parity divergence with no
///    gain — the line is already described as strongly as it can be.
/// 2. **Otherwise a provider signature wins.** `aws-access-key-id`/`critical` names the
///    provider and the real severity; a `medium`/`low` `secret_like_line` says only "this
///    line contains a secret-ish word". An earlier version of this function let *any*
///    keyword hit suppress provider hits, which silently demoted a confirmed AWS key to
///    `low` on any line containing the word `token` or `key` — i.e. on most real lines,
///    since people label their keys. The corpus test could not see that regression: it
///    measures detection as a boolean per line, so rule id and severity are invisible to
///    precision/recall/F1.
/// 3. **Otherwise the weak keyword hit wins over the structural credential rules and
///    entropy.** Entropy and the credential rules carry no provider identity, so they
///    add nothing to a line the keyword cascade already described — and legacy, which
///    has neither, reports exactly `secret_like_line` there.
/// 4. **Otherwise a structural credential match wins over entropy** (Finding 2,
///    2026-07-27 audit): a password's *position* inside a URL, or an HTTP
///    `Basic`/`Digest` auth token. Both are more specific and more precise than a
///    generic high-entropy guess, so they are checked first — but only reached once
///    every keyword-based rule above has passed, which is why a `Bearer` line never
///    reaches this step: it was already caught by rule 1's `has_secret_with_value`.
/// 5. **Entropy is the last resort**, which is where its whole recall contribution lives:
///    lines nothing above can see.
///
/// The redaction applied to the surviving hit's message is unaffected by this choice —
/// [`redacted_message`] masks every detected span regardless of which hit is reported.
/// `strict_checksums` lets a provider match whose vendor checksum fails to recompute be
/// reported as a weaker finding instead of a definitive one. It is a caller's opt-in,
/// never the default — see [`crate::patterns::checksum`] for why an unverified recipe is
/// not allowed to demote a real token on its own.
pub(super) fn collect_secret_hits(line: &str, strict_checksums: bool) -> Vec<SecretHit> {
    if keyword::is_self_protected(line) {
        return Vec::new();
    }

    let prefiltered = prefilter::has_hit(line);
    let keyword_hit = if prefiltered {
        keyword::secret_confidence(line)
    } else {
        None
    };

    // Rule 1: a keyword hit legacy would consider definitive.
    if let Some(confidence) = keyword_hit
        && matches!(confidence, "critical" | "high")
    {
        return vec![SecretHit {
            rule: "secret_like_line",
            confidence,
        }];
    }

    // Rule 2: a provider signature, which names what was found and how bad it is.
    if prefiltered && let Some(found) = provider::find_provider_matches(line).into_iter().next() {
        return vec![SecretHit {
            rule: found.rule_id,
            confidence: provider_confidence(line, &found, strict_checksums),
        }];
    }
    // Never gated by the prefilter — see patterns::prefilter's documented scope limits.
    if let Some(found) = provider::find_telegram_matches(line).into_iter().next() {
        return vec![SecretHit {
            rule: found.rule_id,
            confidence: found.confidence,
        }];
    }

    // Rule 3: the weaker keyword hit, which is what legacy would have reported.
    if let Some(confidence) = keyword_hit {
        return vec![SecretHit {
            rule: "secret_like_line",
            confidence,
        }];
    }

    // Rule 4: structural credential detectors that need no keyword context at all.
    // Not gated by the prefilter: neither "://" nor "Basic"/"Digest" is in its literal
    // set (adding them would help little — every line reaching this point already
    // cleared every prefilter-gated check above without matching), and both matchers
    // are cheap single-pass scans, the same order of cost as the keyword cascade
    // itself.
    if !credentials::find_url_credentials(line).is_empty() {
        return vec![SecretHit {
            rule: "url-credentials",
            confidence: "high",
        }];
    }
    if !credentials::find_http_auth_tokens(line).is_empty() {
        return vec![SecretHit {
            rule: "http-auth-credentials",
            confidence: "high",
        }];
    }

    // Rule 5: entropy, on lines nothing else recognised.
    entropy::entropy_findings(line)
        .into_iter()
        .next()
        .map(|found| SecretHit {
            rule: "high-entropy-token",
            confidence: found.confidence,
        })
        .into_iter()
        .collect()
}

/// Invariant I3 (`.ai/project/12-domain-rules.md`): a `Finding.message` must never
/// contain a raw secret value. [`keyword::redacted_line`] alone only redacts
/// keyword-shaped `key=value`/`key: value` spans — a bare provider signature or
/// entropy match with **no** adjacent keyword (for example a lone AWS key on its own
/// line) has no keyword span for it to act on and would otherwise pass through
/// untouched. This masks every provider/telegram/entropy match span with a fixed
/// placeholder, so a message is never built from text that still holds a known
/// secret-shaped span.
///
/// **Runs *after* [`keyword::redacted_line`], never before** (see
/// [`redacted_message`]). Running it first destroys information legacy's redaction
/// depends on: the entropy tokenizer's candidate alphabet includes `=`, so
/// `JWT_SECRET=<value>` is one single token, and masking that span wipes the key name
/// the finding exists to identify — leaving a useless `- <REDACTED>`. It equally erases
/// the keyword text `redacted_line` needs to recognise the line as secret-shaped at all.
fn mask_non_keyword_secret_spans<'a>(
    line: &'a str,
    redactor: Option<&crate::Redactor>,
) -> std::borrow::Cow<'a, str> {
    let mut spans: Vec<(usize, usize)> = Vec::new();
    if prefilter::has_hit(line) {
        for found in provider::find_provider_matches(line) {
            spans.push((found.start, found.end));
        }
    }
    for found in provider::find_telegram_matches(line) {
        spans.push((found.start, found.end));
    }
    for found in entropy::entropy_findings(line) {
        spans.push((found.start, found.end));
    }
    if spans.is_empty() {
        return std::borrow::Cow::Borrowed(line);
    }

    spans.sort_by_key(|&(start, _)| start);
    let mut out = String::with_capacity(line.len());
    let mut cursor = 0usize;
    for (start, end) in spans {
        if start < cursor {
            // Overlapping with an already-masked span (can happen if two detectors
            // claim intersecting ranges that are not simple containment — e.g. a
            // short fixed-length provider match and a longer entropy-tokenized span
            // sharing the same start but extending further). Extend the already-open
            // redaction to cover the further end instead of dropping this span: the
            // overlapping bytes are already excluded from `out` by the advanced
            // `cursor`, so widening it is sufficient to keep the rest masked too.
            cursor = cursor.max(end);
            continue;
        }
        out.push_str(&line[cursor..start]);
        // A labelling redactor spells this span `<REDACTED_SECRET:sN>` — the "bare"
        // shape, since a provider signature or entropy match has no key of its own.
        // Every other case keeps the literal this function has always written: a plain
        // `Redactor` must produce byte-identical output to no redactor at all, or the
        // default run moves.
        match redactor {
            Some(redactor) if redactor.is_labelled() => {
                out.push_str(&redactor.placeholders().bare(&line[start..end]));
            }
            _ => out.push_str("<REDACTED>"),
        }
        cursor = end;
    }
    out.push_str(&line[cursor..]);
    std::borrow::Cow::Owned(out)
}

/// Builds the single [`Finding::message`] shared by every hit on one line.
///
/// Two passes, in this order and no other:
///
/// 1. [`keyword::redacted_line`] on the **raw** line — legacy `redacted_line` verbatim.
///    Whenever the line is keyword-shaped this collapses it to `key=<REDACTED>` /
///    `key: <REDACTED>`, keeping the key name that identifies *which* secret was found
///    and dropping everything from the first `=`/`:` onward, value included.
/// 2. [`mask_non_keyword_secret_spans`] on the result — a residual safety net for what
///    step 1 legitimately leaves behind: the whole line when it holds no keyword at all
///    (a bare AWS key, a lone high-entropy blob), and the surviving key prefix, which on
///    a line such as `AKIA… token: x` would otherwise carry a provider token into the
///    message exactly as legacy does. This is a deliberate strengthening over legacy in
///    favour of invariant I3, and the only respect in which this message can differ from
///    legacy's.
pub(super) fn redacted_message(line: &str, redactor: Option<&crate::Redactor>) -> String {
    let legacy = match redactor {
        Some(redactor) => redactor.redacted_line(line),
        None => keyword::redacted_line(line),
    };
    mask_non_keyword_secret_spans(&legacy, redactor).into_owned()
}

pub(super) struct RiskyHit {
    pub(super) severity: &'static str,
    pub(super) rule: &'static str,
    pub(super) explanation: &'static str,
}

pub(super) fn collect_risky_hits(line: &str) -> Vec<RiskyHit> {
    risky_code::RISKY_CODE_PATTERNS
        .iter()
        .filter(|rule| rule.is_match(line))
        .map(|rule| RiskyHit {
            severity: rule.severity,
            rule: rule.rule_id,
            explanation: rule.explanation,
        })
        .collect()
}
