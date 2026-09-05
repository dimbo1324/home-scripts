//! Offline verification of the checksum some vendors build into their token format.
//!
//! ## What this buys, and what it must never cost
//!
//! A rule like `github-token` recognises a *shape*: `ghp_` followed by 36 alphanumerics.
//! Documentation, fixtures and tutorials are full of strings with that shape and no
//! secret behind them. GitHub builds a checksum into the format precisely so a scanner
//! can tell the two apart without asking GitHub — the last six characters are a base62
//! encoding of a CRC32 over the random part.
//!
//! ## Why this is off by default
//!
//! GitHub's engineering blog states that the checksum exists and how it is composed. It
//! does **not** publish the exact recipe — which bytes the CRC is taken over, the
//! padding, the alphabet order — and the public implementations that reproduce it are
//! reverse-engineered, disagreeing in at least one detail (whether the prefix is part of
//! the CRC input).
//!
//! That asymmetry decides the design. If this algorithm is right, treating a failed
//! checksum as "not a real token" removes false positives. If it is wrong in any
//! detail, it silently demotes *real* tokens — a recall loss in the one detector the
//! product exists for, which invariant I9 forbids trading away. An unverifiable
//! algorithm therefore may not change a verdict unless the operator asks for it:
//! [`crate::scan::ScanOptions::strict_token_checksums`] is `false` unless set, and with
//! it off nothing here can lower a finding.
//!
//! Flip the default only after a real, freshly issued token of each accepted prefix has
//! been checked against this code.
//!
//! No network access: this is arithmetic over bytes already in memory (invariant I1).

/// GitHub's stated alphabet, in the order that makes the encoding a plain base-62
/// positional numeral.
const BASE62: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Characters of checksum at the end of a classic token.
const CHECKSUM_LEN: usize = 6;

/// Characters of randomness before it. The two together are the 36 the shape matches.
pub(crate) const ENTROPY_LEN: usize = 30;

/// The classic personal/OAuth/user/server/refresh prefixes.
///
/// `ghr_` is listed here although no rule matches it today: this function answers "does
/// this string carry a valid checksum", and answering it for a prefix the rule set has
/// not adopted yet is free and cannot mislead — a token nothing matched is never asked
/// about.
const CLASSIC_PREFIXES: [&str; 5] = ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"];

/// What a checksum had to say about a match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumVerdict {
    /// The format carries no checksum this module knows how to compute — every vendor
    /// except GitHub's classic tokens today, the fine-grained `github_pat_` shape
    /// included. Never a reason to weaken a finding.
    Unknown,
    /// The checksum recomputes to the value carried in the token.
    Valid,
    /// It does not. Only ever acted on in strict mode.
    Invalid,
}

/// CRC-32/ISO-HDLC, the variant `zlib.crc32` computes — bit-reflected, polynomial
/// `0xEDB88320`, pre- and post-inverted.
///
/// Written out rather than pulled from a crate: it is twelve lines, and
/// `codepack-security` carries no run-time parser or codec dependency by design.
pub(crate) fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            // `-(crc & 1)` as a mask: all ones when the low bit is set, zero otherwise.
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// `value` in base 62, left-padded with the alphabet's zero to exactly `CHECKSUM_LEN`.
///
/// Six digits always suffice and never overflow: `62^5` is below `u32::MAX` and `62^6`
/// is above it, so every `u32` has a representation and none needs a seventh digit.
pub(crate) fn base62_checksum(value: u32) -> String {
    let mut digits = [BASE62[0]; CHECKSUM_LEN];
    let mut remaining = value;
    for slot in digits.iter_mut().rev() {
        *slot = BASE62[(remaining % 62) as usize];
        remaining /= 62;
    }
    // Every byte comes from BASE62, which is ASCII.
    String::from_utf8_lossy(&digits).into_owned()
}

/// Whether `token` — the whole match, prefix included — carries a checksum that
/// recomputes.
///
/// Returns [`ChecksumVerdict::Unknown`] for anything whose shape this does not
/// recognise, which is the only safe answer: a scanner that treats "I do not know this
/// format" as "this is not a secret" stops being a scanner.
pub fn github_verdict(token: &str) -> ChecksumVerdict {
    let Some(body) = CLASSIC_PREFIXES
        .iter()
        .find_map(|prefix| token.strip_prefix(prefix))
    else {
        return ChecksumVerdict::Unknown;
    };
    if body.len() != ENTROPY_LEN + CHECKSUM_LEN || !body.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        return ChecksumVerdict::Unknown;
    }
    let (entropy, carried) = body.split_at(ENTROPY_LEN);
    if base62_checksum(crc32(entropy.as_bytes())) == carried {
        ChecksumVerdict::Valid
    } else {
        ChecksumVerdict::Invalid
    }
}

/// The verdict for whichever vendor `rule_id` names. One place to extend when a second
/// vendor's recipe is confirmed.
pub fn verdict_for(rule_id: &str, token: &str) -> ChecksumVerdict {
    match rule_id {
        "github-token" => github_verdict(token),
        _ => ChecksumVerdict::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The CRC-32/ISO-HDLC check value: the standard's own test vector.
    ///
    /// This is the one part of the recipe that is *not* guesswork, so it is pinned
    /// against the published constant rather than against this implementation's own
    /// output. If this fails, the primitive is wrong and every verdict below is
    /// meaningless.
    #[test]
    fn crc32_matches_the_published_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn crc32_of_nothing_is_zero() {
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn base62_is_six_characters_from_the_alphabet() {
        for value in [0u32, 1, 61, 62, 12345, u32::MAX] {
            let encoded = base62_checksum(value);
            assert_eq!(encoded.len(), CHECKSUM_LEN, "value {value}");
            assert!(
                encoded.bytes().all(|byte| BASE62.contains(&byte)),
                "value {value} produced {encoded}"
            );
        }
    }

    #[test]
    fn base62_counts_upwards_and_pads_on_the_left() {
        assert_eq!(base62_checksum(0), "000000");
        assert_eq!(base62_checksum(1), "000001");
        assert_eq!(base62_checksum(10), "00000A");
        assert_eq!(base62_checksum(61), "00000z");
        assert_eq!(base62_checksum(62), "000010");
    }

    /// `u32::MAX` needs six digits and no more — the claim the fixed-width buffer rests
    /// on.
    #[test]
    fn six_digits_hold_every_u32() {
        assert!(62u64.pow(5) < u64::from(u32::MAX));
        assert!(62u64.pow(6) > u64::from(u32::MAX));
        assert_ne!(base62_checksum(u32::MAX), "000000");
    }

    /// Builds a token the way the recipe says one is built.
    ///
    /// This proves the verifier and the construction agree; it does **not** prove either
    /// matches GitHub, which is exactly why `strict_token_checksums` is off by default.
    fn well_formed(prefix: &str, entropy: &str) -> String {
        assert_eq!(entropy.len(), ENTROPY_LEN);
        format!(
            "{prefix}{entropy}{}",
            base62_checksum(crc32(entropy.as_bytes()))
        )
    }

    const ENTROPY: &str = "abcdefghij0123456789ABCDEFGHIJ";

    #[test]
    fn every_classic_prefix_is_recognised() {
        for prefix in CLASSIC_PREFIXES {
            assert_eq!(
                github_verdict(&well_formed(prefix, ENTROPY)),
                ChecksumVerdict::Valid,
                "prefix {prefix}"
            );
        }
    }

    #[test]
    fn a_changed_body_no_longer_matches_its_checksum() {
        let token = well_formed("ghp_", ENTROPY);
        let mut tampered = token.clone();
        // Change one character of the random part, leaving the checksum alone.
        tampered.replace_range(4..5, "z");
        assert_ne!(tampered, token);
        assert_eq!(github_verdict(&tampered), ChecksumVerdict::Invalid);
    }

    #[test]
    fn a_changed_checksum_no_longer_matches_its_body() {
        let token = well_formed("ghp_", ENTROPY);
        let mut tampered = token.clone();
        let last = tampered.len() - 1;
        let replacement = if tampered.ends_with('z') { "y" } else { "z" };
        tampered.replace_range(last.., replacement);
        assert_eq!(github_verdict(&tampered), ChecksumVerdict::Invalid);
    }

    /// The shape documentation samples take, and the whole reason this exists.
    #[test]
    fn a_documentation_placeholder_fails_the_checksum() {
        let placeholder = format!("ghp_{}", "x".repeat(36));
        assert_eq!(github_verdict(&placeholder), ChecksumVerdict::Invalid);
    }

    #[test]
    fn an_unknown_shape_is_unknown_rather_than_invalid() {
        // Not evidence about the token — evidence that this build cannot check it. The
        // distinction is what keeps a verdict from weakening something it never read.
        assert_eq!(github_verdict("hello"), ChecksumVerdict::Unknown);
        assert_eq!(github_verdict("ghp_short"), ChecksumVerdict::Unknown);
        assert_eq!(
            github_verdict(&format!("ghp_{}", "a".repeat(37))),
            ChecksumVerdict::Unknown
        );
        // Non-alphanumerics are not this shape.
        assert_eq!(
            github_verdict(&format!("ghp_{}", "-".repeat(36))),
            ChecksumVerdict::Unknown
        );
    }

    /// The fine-grained format's recipe is not established, so it is deliberately not
    /// claimed.
    #[test]
    fn a_fine_grained_token_is_not_checked() {
        let token = format!("github_pat_{}", "a".repeat(82));
        assert_eq!(github_verdict(&token), ChecksumVerdict::Unknown);
    }

    #[test]
    fn only_the_github_rule_is_routed_to_a_checker() {
        let token = well_formed("ghp_", ENTROPY);
        assert_eq!(verdict_for("github-token", &token), ChecksumVerdict::Valid);
        // Every other vendor: no recipe, so no opinion.
        assert_eq!(
            verdict_for("aws-access-key-id", "AKIAIOSFODNN7EXAMPLE"),
            ChecksumVerdict::Unknown
        );
        assert_eq!(
            verdict_for("high-entropy-token", &token),
            ChecksumVerdict::Unknown
        );
    }
}
