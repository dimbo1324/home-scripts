//! Provider-specific secret signatures (BLUEPRINT §B.1, 🎯 new capability — legacy has
//! only the PEM-header rule, reused here as `pem-private-key`). High-precision,
//! low-false-positive rules anchored to a known vendor token format. **No network
//! calls**: every rule is a pure, local shape match against text already in memory
//! (invariant I1 — this is exactly why AWS/GitHub/etc. keys are recognised by shape,
//! never validated against the provider's API).
//!
//! Four formats (AWS, Google, Slack, JWT) are given verbatim in `docs/__arch__/BLUEPRINT.md` §B.1; the
//! rest are authored from each provider's publicly documented token format, not ported
//! from legacy or verified against any live account.
//!
//! The shapes themselves live in [`crate::patterns::token_scan`] as data rather than
//! regexes — see that module for why, and for the differential tests proving the two
//! agree.

use std::sync::LazyLock;

use crate::patterns::token_scan::{self, CharClass, TokenPattern, prefixed};

/// A named secret signature: one token shape plus the identity and severity a match
/// reports.
#[derive(Debug)]
pub struct ProviderRule {
    pub rule_id: &'static str,
    pub confidence: &'static str,
    pub(crate) pattern: TokenPattern,
}

impl ProviderRule {
    /// One rule per prefix, for vendors whose shapes differ only in that prefix. Keeps
    /// each vendor's accepted spellings in exactly one list.
    fn per_prefix(
        rule_id: &'static str,
        confidence: &'static str,
        prefixes: &'static [&'static str],
        class: CharClass,
        min: usize,
        max: usize,
    ) -> impl Iterator<Item = Self> {
        prefixes.iter().map(move |prefix| Self {
            rule_id,
            confidence,
            pattern: prefixed(prefix, class, min, max),
        })
    }

    /// A rule wrapping one of the fixed formats declared in [`token_scan`].
    const fn new(rule_id: &'static str, confidence: &'static str, pattern: TokenPattern) -> Self {
        Self {
            rule_id,
            confidence,
            pattern,
        }
    }
}

/// Every provider signature, in priority order.
///
/// Order is load-bearing in two places. `anthropic-api-key` (`sk-ant-…`) is checked
/// strictly before `openai-api-key` (`sk-…`) so an Anthropic-shaped key is never
/// reclassified as OpenAI's; and the AWS secret rule's two registrations (with and
/// without the `aws` word) sit together so the longer, more specific spelling is tried
/// first. [`find_provider_matches`] drops any match overlapping an already-accepted one,
/// which is what makes the ordering decisive.
pub static PROVIDER_PATTERNS: LazyLock<Vec<ProviderRule>> = LazyLock::new(|| {
    let mut rules = vec![
        ProviderRule::new(
            "aws-access-key-id",
            "critical",
            token_scan::AWS_ACCESS_KEY_ID,
        ),
        // Two registrations of one rule: the field name may or may not carry the `aws`
        // word, and an optional literal is deliberately outside this matcher's grammar.
        ProviderRule::new(
            "aws-secret-access-key",
            "critical",
            token_scan::AWS_SECRET_WITH_PREFIX,
        ),
        ProviderRule::new(
            "aws-secret-access-key",
            "critical",
            token_scan::AWS_SECRET_BARE,
        ),
    ];

    // `gh[pous]_[A-Za-z0-9]{36}` — the classic personal/OAuth/user/server shapes.
    rules.extend(ProviderRule::per_prefix(
        "github-token",
        "critical",
        &token_scan::GITHUB_TOKEN_PREFIXES,
        CharClass::Alnum,
        36,
        36,
    ));
    rules.push(ProviderRule::new(
        "github-token",
        "critical",
        token_scan::GITHUB_FINE_GRAINED_TOKEN,
    ));
    rules.push(ProviderRule::new(
        "google-api-key",
        "critical",
        token_scan::GOOGLE_API_KEY,
    ));

    // `xox[baprs]-[0-9A-Za-z-]{10,72}`
    rules.extend(ProviderRule::per_prefix(
        "slack-token",
        "critical",
        &token_scan::SLACK_TOKEN_PREFIXES,
        CharClass::AlnumDash,
        10,
        72,
    ));

    // `(sk|rk)_live_[0-9A-Za-z]{24,}`
    rules.extend(ProviderRule::per_prefix(
        "stripe-key",
        "critical",
        &token_scan::STRIPE_KEY_PREFIXES,
        CharClass::Alnum,
        24,
        usize::MAX,
    ));

    rules.extend([
        // Strictly before `openai-api-key`: both start with `sk-`.
        ProviderRule::new(
            "anthropic-api-key",
            "critical",
            token_scan::ANTHROPIC_API_KEY,
        ),
        ProviderRule::new("openai-api-key", "high", token_scan::OPENAI_API_KEY),
        ProviderRule::new("jwt", "high", token_scan::JWT),
        ProviderRule::new("pem-private-key", "critical", token_scan::PEM_PRIVATE_KEY),
    ]);

    rules
});

/// `telegram-bot-token` is scanned separately from [`PROVIDER_PATTERNS`] — see
/// `patterns::prefilter`'s module doc for why: unlike every other provider signature it
/// has no distinctive literal prefix (`\d{8,10}:…` starts with plain digits), so the
/// `aho-corasick` prefilter cannot anchor on it and it must run unconditionally.
pub static TELEGRAM_BOT_TOKEN_RULE: LazyLock<ProviderRule> = LazyLock::new(|| ProviderRule {
    rule_id: "telegram-bot-token",
    confidence: "critical",
    pattern: token_scan::TELEGRAM_BOT_TOKEN,
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderMatch {
    pub rule_id: &'static str,
    pub confidence: &'static str,
    pub start: usize,
    pub end: usize,
}

fn ranges_overlap(a_start: usize, a_end: usize, b_start: usize, b_end: usize) -> bool {
    a_start < b_end && b_start < a_end
}

/// Collects matches of `rules` over `line`, dropping any whose span overlaps a match
/// already accepted from an earlier (higher-priority) rule.
fn collect_matches<'r>(
    line: &str,
    rules: impl Iterator<Item = &'r ProviderRule>,
) -> Vec<ProviderMatch> {
    let mut matches: Vec<ProviderMatch> = Vec::new();

    for rule in rules {
        for found in token_scan::find_matches(line, &rule.pattern) {
            let overlaps = matches.iter().any(|existing| {
                ranges_overlap(
                    existing.start,
                    existing.end,
                    found.value_start,
                    found.value_end,
                )
            });
            if overlaps {
                continue;
            }
            matches.push(ProviderMatch {
                rule_id: rule.rule_id,
                confidence: rule.confidence,
                start: found.value_start,
                end: found.value_end,
            });
        }
    }

    matches
}

/// Runs every rule in [`PROVIDER_PATTERNS`] over `line`, in priority order. A match
/// whose span overlaps an already-accepted match from a higher-priority rule is
/// dropped — this is what keeps `openai-api-key` from ever double-claiming a span
/// already claimed by `anthropic-api-key` (both start with `sk-`).
pub fn find_provider_matches(line: &str) -> Vec<ProviderMatch> {
    collect_matches(line, PROVIDER_PATTERNS.iter())
}

/// See [`TELEGRAM_BOT_TOKEN_RULE`] — always run, never gated by the prefilter.
pub fn find_telegram_matches(line: &str) -> Vec<ProviderMatch> {
    collect_matches(line, std::iter::once(&*TELEGRAM_BOT_TOKEN_RULE))
}

/// The PEM-header shape, shared with the keyword cascade's `critical` tier (same shape,
/// two rule identities).
pub(crate) fn is_pem_private_key(line: &str) -> bool {
    token_scan::is_match(line, &token_scan::PEM_PRIVATE_KEY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn rule_ids(line: &str) -> Vec<&'static str> {
        find_provider_matches(line)
            .into_iter()
            .map(|m| m.rule_id)
            .collect()
    }

    #[test]
    fn eleven_distinct_provider_rules_including_telegram() {
        // Ten signatures from BLUEPRINT §B.1 plus `aws-secret-access-key` (Q15).
        // Counted by distinct rule id, since several vendors need more than one shape
        // (GitHub's four classic prefixes plus its fine-grained one, Slack's five).
        let distinct: BTreeSet<&str> = PROVIDER_PATTERNS
            .iter()
            .map(|rule| rule.rule_id)
            .chain(std::iter::once(TELEGRAM_BOT_TOKEN_RULE.rule_id))
            .collect();
        assert_eq!(distinct.len(), 11, "rule ids: {distinct:?}");
    }

    #[test]
    fn every_rule_declaring_a_value_segment_has_one() {
        // `find_matches` falls back to the whole match when a declared value segment is
        // absent, so a mistyped index would silently widen the reported span instead of
        // failing loudly.
        for rule in PROVIDER_PATTERNS.iter() {
            if let Some(index) = rule.pattern.value_segment {
                assert!(
                    index < rule.pattern.segments.len(),
                    "{} declares value_segment {index} but has {} segments",
                    rule.rule_id,
                    rule.pattern.segments.len()
                );
            }
        }
    }

    #[test]
    fn a_longer_than_forty_character_value_is_covered_completely() {
        let value = "a".repeat(20) + &"B7c".repeat(8) + "de";
        assert!(value.len() > 40);
        let line = format!("aws_secret_access_key={value}");
        let found = find_provider_matches(&line);
        assert_eq!(&line[found[0].start..found[0].end], value);
    }

    #[test]
    fn aws_secret_access_key_matches_only_with_its_context() {
        let value = "a".repeat(20) + &"B7c".repeat(6) + "de";
        assert_eq!(value.len(), 40);

        for line in [
            format!("aws_secret_access_key = {value}"),
            format!("AWS_SECRET_ACCESS_KEY={value}"),
            format!("  secretAccessKey: \"{value}\","),
            format!("aws.secret.access.key={value}"),
        ] {
            assert_eq!(
                rule_ids(&line),
                vec!["aws-secret-access-key"],
                "context should have matched: {line}"
            );
        }

        // Bare, the value is just 40 base64 characters — a shape shared by hashes,
        // build identifiers and minified tokens. Matching it without context is what
        // would cost precision (invariant I9).
        assert!(rule_ids(&value).is_empty());
        assert!(rule_ids(&format!("build_id = {value}")).is_empty());
    }

    #[test]
    fn aws_secret_access_key_reports_only_the_value_not_the_field_name() {
        let value = "a".repeat(20) + &"B7c".repeat(6) + "de";
        let line = format!("aws_secret_access_key={value}");
        let found = find_provider_matches(&line);

        assert_eq!(found.len(), 1);
        assert_eq!(
            &line[found[0].start..found[0].end],
            value,
            "the reported span must cover the secret alone, so masking it leaves the \
             field name that identifies the finding"
        );
    }

    #[test]
    fn aws_access_key_matches() {
        assert_eq!(rule_ids("AKIAABCDEFGHIJKLMNOP"), vec!["aws-access-key-id"]);
    }

    #[test]
    fn github_token_variants_match() {
        for prefix in token_scan::GITHUB_TOKEN_PREFIXES {
            let token = prefix.to_string() + &"a".repeat(36);
            assert_eq!(rule_ids(&token), vec!["github-token"], "prefix {prefix}");
        }
        let pat = "github_pat_".to_string() + &"b".repeat(82);
        assert_eq!(rule_ids(&pat), vec!["github-token"]);
    }

    #[test]
    fn github_fine_grained_token_rejects_dashes_which_its_alphabet_excludes() {
        // `[A-Za-z0-9_]` has no dash. An earlier draft used the URL-safe class here and
        // matched a run of dashes GitHub never issues.
        let dashes = "github_pat_".to_string() + &"-".repeat(82);
        assert!(rule_ids(&dashes).is_empty());
        let underscores = "github_pat_".to_string() + &"_".repeat(82);
        assert_eq!(rule_ids(&underscores), vec!["github-token"]);
    }

    #[test]
    fn google_api_key_matches() {
        let key = "AIza".to_string() + &"a".repeat(35);
        assert_eq!(rule_ids(&key), vec!["google-api-key"]);
    }

    #[test]
    fn slack_token_matches_every_documented_prefix() {
        for prefix in token_scan::SLACK_TOKEN_PREFIXES {
            let token = prefix.to_string() + &"1".repeat(20);
            assert_eq!(rule_ids(&token), vec!["slack-token"], "prefix {prefix}");
        }
    }

    #[test]
    fn stripe_key_matches_both_live_prefixes() {
        for prefix in token_scan::STRIPE_KEY_PREFIXES {
            let key = prefix.to_string() + &"a".repeat(24);
            assert_eq!(rule_ids(&key), vec!["stripe-key"], "prefix {prefix}");
        }
    }

    #[test]
    fn anthropic_key_wins_over_openai_pattern() {
        let key = "sk-ant-".to_string() + &"a".repeat(30);
        let hits = find_provider_matches(&key);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_id, "anthropic-api-key");
        assert_eq!(hits[0].confidence, "critical");
    }

    #[test]
    fn openai_key_matches_when_not_anthropic_shaped() {
        let key = "sk-".to_string() + &"a".repeat(30);
        assert_eq!(rule_ids(&key), vec!["openai-api-key"]);
    }

    #[test]
    fn jwt_matches() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dGVzdC1zaWduYXR1cmU";
        assert_eq!(rule_ids(jwt), vec!["jwt"]);
    }

    #[test]
    fn pem_private_key_matches_via_provider_rule_too() {
        assert_eq!(
            rule_ids("-----BEGIN RSA PRIVATE KEY-----"),
            vec!["pem-private-key"]
        );
        assert!(is_pem_private_key("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(!is_pem_private_key("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn telegram_bot_token_matches_via_dedicated_function() {
        let token = "123456789:".to_string() + &"a".repeat(35);
        assert_eq!(
            find_telegram_matches(&token)
                .into_iter()
                .map(|m| m.rule_id)
                .collect::<Vec<_>>(),
            vec!["telegram-bot-token"]
        );
        assert!(find_provider_matches(&token).is_empty());
    }

    #[test]
    fn no_match_on_plain_text() {
        assert!(find_provider_matches("just an ordinary line of code").is_empty());
    }

    #[test]
    fn overlapping_rules_report_the_higher_priority_one_only() {
        // A single line carrying several distinct secrets still reports each once.
        let aws = "AKIA".to_string() + &"A".repeat(16);
        let google = "AIza".to_string() + &"b".repeat(35);
        let line = format!("{aws} {google}");
        let ids = rule_ids(&line);
        assert_eq!(ids, vec!["aws-access-key-id", "google-api-key"]);
    }
}
