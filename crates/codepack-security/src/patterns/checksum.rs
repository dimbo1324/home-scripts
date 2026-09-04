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
const ENTROPY_LEN: usize = 30;

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
fn crc32(bytes: &[u8]) -> u32 {
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
fn base62_checksum(value: u32) -> String {
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
