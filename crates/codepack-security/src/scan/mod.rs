//! The heuristic scanner — "Enhanced Security Scan v3" — ported from legacy
//! `reports/insights/security.py`, plus provider signatures and entropy (BLUEPRINT
//! §B.1). [`scan_project`] takes a **caller-supplied list of files**; it never walks
//! the filesystem itself (that is `codepack-scanner`'s job, S2; combining the two is
//! S9's). Reading individual file contents from disk is not "walking" and stays in
//! scope here.

mod paths;
pub mod write;

use std::fs;
use std::path::{Path, PathBuf};

use codepack_core::CancellationToken;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::cache;
use crate::classify;
use crate::constants;
use crate::error::{Result, SecurityError};
use crate::patterns::{
    checksum, confidence_rank, credentials, entropy, keyword, prefilter, provider, risky_code,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    SensitiveFile,
    PotentialSecret,
    RiskyCode,
}

/// Mirrors legacy's flat finding dict exactly: `type`, `severity`, `confidence`,
/// `file`, `line`, `rule`, `message`. `message` is **always** either a fixed,
/// hard-coded description or the output of [`keyword::redacted_line`] — invariant I3:
/// the raw matched substring never reaches this field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    #[serde(rename = "type")]
    pub kind: FindingKind,
    pub severity: String,
    pub confidence: String,
    pub file: String,
    pub line: Option<usize>,
    pub rule: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ScanSummary {
    pub sensitive_files: usize,
    pub potential_secrets: usize,
    pub risky_code: usize,
    pub total_findings: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ScanResult {
    pub summary: ScanSummary,
    pub findings: Vec<Finding>,
}

/// Rebuilds a result from a subset of its findings, recounting the summary by kind so
/// it describes what is actually there.
///
/// Used after the allowlist removes accepted findings: a summary left saying "3 secrets"
/// over a list of one is the kind of quiet inconsistency that makes a report untrusted.
pub fn result_from_findings(findings: Vec<Finding>) -> ScanResult {
    let mut summary = ScanSummary::default();
    for finding in &findings {
        match finding.kind {
            FindingKind::SensitiveFile => summary.sensitive_files += 1,
            FindingKind::PotentialSecret => summary.potential_secrets += 1,
            FindingKind::RiskyCode => summary.risky_code += 1,
        }
    }
    summary.total_findings = findings.len();
    ScanResult { summary, findings }
}

/// What a caller may vary about a scan. Everything defaults to the behaviour every
/// release so far produced, so [`scan_project`] and
/// [`scan_project_with_options`] with a default value are the same run.
#[derive(Clone, Copy, Default)]
pub struct ScanOptions<'a> {
    /// Redactor used to build every finding message.
    ///
    /// `None` is the plain, indistinguishable placeholder. A labelled redactor makes
    /// `<REDACTED:s1>` reach `06_security_scan.json`, SARIF and the text report, so a
    /// reader can tell whether two findings are one credential or two — the gap Q34
    /// named, where labels reached the text dump and the git reports but stopped at the
    /// scanner's own artifacts.
    ///
    /// The artifact *shape* is unchanged either way: no field is added, removed or
    /// retyped, only the vocabulary inside `message`, and only when the caller opts in.
    /// That is deliberate — `06_security_scan.json`'s `schema_version` is matched
    /// against the archived legacy implementation by the golden references, so a bump
    /// here could never be satisfied by regenerating them.
    pub redactor: Option<&'a crate::Redactor>,
    /// Let a failed vendor checksum weaken a provider finding.
    ///
    /// Off unless asked for, because the recipe is reverse-engineered rather than
    /// published — see [`crate::patterns::checksum`] for why an unverifiable algorithm
    /// may not be allowed to demote a real token.
    pub strict_token_checksums: bool,
    /// Where an already-scanned file's content-derived findings may be reused from.
    ///
    /// `None` scans everything, which is what every release so far did. See
    /// [`crate::cache`] for what is cacheable, what the key has to cover, and why the
    /// store itself lives outside this crate.
    pub cache: Option<&'a dyn crate::cache::FileScanCache>,
}

/// Written out rather than derived: a cache is a trait object, and requiring every
/// implementation to be `Debug` for the sake of this line would be the tail wagging the
/// dog. Whether one is present is the only part worth printing anyway.
impl std::fmt::Debug for ScanOptions<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScanOptions")
            .field("redactor", &self.redactor)
            .field("strict_token_checksums", &self.strict_token_checksums)
            .field("cache", &self.cache.map(|_| "present"))
            .finish()
    }
}

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
fn sensitive_file_severity(relative: &Path) -> Option<&'static str> {
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

struct SecretHit {
    rule: &'static str,
    confidence: &'static str,
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
fn collect_secret_hits(line: &str, strict_checksums: bool) -> Vec<SecretHit> {
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
fn redacted_message(line: &str, redactor: Option<&crate::Redactor>) -> String {
    let legacy = match redactor {
        Some(redactor) => redactor.redacted_line(line),
        None => keyword::redacted_line(line),
    };
    mask_non_keyword_secret_spans(&legacy, redactor).into_owned()
}

struct RiskyHit {
    severity: &'static str,
    rule: &'static str,
    explanation: &'static str,
}

fn collect_risky_hits(line: &str) -> Vec<RiskyHit> {
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

struct FileRecord {
    severity: &'static str,
    display: String,
}

struct SecretRecord {
    confidence: String,
    display: String,
    line_number: usize,
    rule: String,
    message: String,
}

struct RiskyRecord {
    severity: String,
    display: String,
    line_number: usize,
    rule: String,
    explanation: String,
}

/// Everything one file contributes, kept together so the parallel pass can hand back a
/// single value per file and the caller can flatten the results in input order.
#[derive(Default)]
struct FileScanRecords {
    files: Vec<FileRecord>,
    secrets: Vec<SecretRecord>,
    risky: Vec<RiskyRecord>,
}

/// The body of what used to be `scan_project`'s per-file loop iteration, unchanged in
/// behaviour: a sensitive filename is recorded even for a file whose contents are not
/// read, and every early exit that used to `continue` now returns what has been
/// collected so far.
fn scan_one_file(
    root: &Path,
    relative: &Path,
    max_bytes_per_file: Option<u64>,
    options: &ScanOptions<'_>,
) -> Result<FileScanRecords> {
    let mut records = FileScanRecords::default();

    if let Some(severity) = sensitive_file_severity(relative) {
        records.files.push(FileRecord {
            severity,
            display: paths::rel_display(relative),
        });
    }

    if !classify::should_consider_text_file(relative) {
        return Ok(records);
    }
    let absolute = root.join(relative);
    let metadata = match fs::metadata(&absolute) {
        Ok(metadata) => metadata,
        Err(_) => return Ok(records),
    };
    if let Some(max) = max_bytes_per_file
        && metadata.len() > max
    {
        return Ok(records);
    }
    let raw = fs::read(&absolute).map_err(|source| SecurityError::Read {
        path: absolute.clone(),
        source,
    })?;
    if classify::looks_binary(&raw) {
        return Ok(records);
    }
    let display = paths::rel_display(relative);

    // A labelling run cannot reuse a cached message. `<REDACTED:s1>` is numbered per
    // run, in the order that run happens to meet its secrets, so a message stored by an
    // earlier run would carry a number standing for a different value here — and the
    // bundle's scan report would disagree with its own text dump. Correctness first: the
    // labelled run simply scans.
    let cache = options
        .cache
        .filter(|_| !options.redactor.is_some_and(crate::Redactor::is_labelled));
    let key = cache.map(|_| cache::cache_key(&raw, options.strict_token_checksums));

    if let (Some(cache), Some(key)) = (cache, key.as_deref())
        && let Some(cached) = cache.lookup(key)
    {
        restore_cached(&mut records, &display, cached);
        return Ok(records);
    }

    scan_text_into(&mut records, &decode_text(raw), &display, options);

    if let (Some(cache), Some(key)) = (cache, key.as_deref()) {
        // Stored even when empty: "these bytes contain nothing" is the answer worth
        // most, since it is the common one.
        cache.store(key, &cached_entries(&records));
    }

    Ok(records)
}

/// Bytes to text, with legacy's documented encoding-scope gap: legacy tries six
/// encodings (utf-8, utf-8-sig, cp1251, cp866, utf-16, latin-1); this stage reads UTF-8
/// with a lossy fallback only. The full chain's real owner is the pipeline's text-dump
/// step — pulling an encoding-detection dependency into the detector alone would be
/// scope creep.
fn decode_text(raw: Vec<u8>) -> String {
    match String::from_utf8(raw) {
        Ok(text) => text,
        Err(err) => String::from_utf8_lossy(&err.into_bytes()).into_owned(),
    }
}

/// The per-line detector pass, appending to this file's records.
fn scan_text_into(
    records: &mut FileScanRecords,
    text: &str,
    display: &str,
    options: &ScanOptions<'_>,
) {
    for (idx, line) in text.lines().enumerate() {
        let line_number = idx + 1;
        let secret_hits = collect_secret_hits(line, options.strict_token_checksums);
        if !secret_hits.is_empty() {
            // Computed once per line, shared by every hit on it (see
            // `mask_non_keyword_secret_spans`'s doc comment for why this must not
            // be scoped to only the current hit's own span).
            let message = redacted_message(line, options.redactor);
            for hit in secret_hits {
                records.secrets.push(SecretRecord {
                    confidence: hit.confidence.to_string(),
                    display: display.to_string(),
                    line_number,
                    rule: hit.rule.to_string(),
                    message: message.clone(),
                });
            }
        }
        for hit in collect_risky_hits(line) {
            records.risky.push(RiskyRecord {
                severity: hit.severity.to_string(),
                display: display.to_string(),
                line_number,
                rule: hit.rule.to_string(),
                explanation: hit.explanation.to_string(),
            });
        }
    }
}

/// This file's content-derived records as cache entries, in the order they were found.
///
/// The filename-derived `sensitive_filename` record is deliberately absent: it is a fact
/// about the path, not the bytes, and caching it under a content key would report
/// `.env`'s severity for a copy saved as `notes.txt`.
fn cached_entries(records: &FileScanRecords) -> Vec<cache::CachedFinding> {
    let secrets = records.secrets.iter().map(|secret| cache::CachedFinding {
        kind: FindingKind::PotentialSecret,
        severity: secret.confidence.clone(),
        confidence: secret.confidence.clone(),
        line: secret.line_number,
        rule: secret.rule.clone(),
        message: secret.message.clone(),
    });
    let risky = records.risky.iter().map(|hit| cache::CachedFinding {
        kind: FindingKind::RiskyCode,
        severity: hit.severity.clone(),
        confidence: risky_code::RISKY_CODE_FINDING_CONFIDENCE.to_string(),
        line: hit.line_number,
        rule: hit.rule.clone(),
        message: hit.explanation.clone(),
    });
    secrets.chain(risky).collect()
}

/// The inverse of [`cached_entries`]: each entry goes back into the bucket its kind
/// names, which restores both buckets' original relative order because the two were
/// concatenated in that order when stored.
fn restore_cached(records: &mut FileScanRecords, display: &str, cached: Vec<cache::CachedFinding>) {
    for entry in cached {
        match entry.kind {
            FindingKind::PotentialSecret => records.secrets.push(SecretRecord {
                confidence: entry.confidence,
                display: display.to_string(),
                line_number: entry.line,
                rule: entry.rule,
                message: entry.message,
            }),
            FindingKind::RiskyCode => records.risky.push(RiskyRecord {
                severity: entry.severity,
                display: display.to_string(),
                line_number: entry.line,
                rule: entry.rule,
                explanation: entry.message,
            }),
            // A content cache never holds one, and a stored entry claiming otherwise is
            // from a build whose recipe differed; ignoring it is safer than trusting a
            // path-derived verdict from another file.
            FindingKind::SensitiveFile => {}
        }
    }
}

/// Scans a caller-supplied list of files (relative to `root`) for sensitive filenames,
/// secret-like lines (keyword cascade + provider signatures + entropy), and risky code
/// patterns. `max_bytes_per_file`, when set, skips reading files above that size —
/// their filename is still checked for sensitivity.
///
/// `cancel` is checked once per file (`.ai/project/12-domain-rules.md` requires
/// checking cancellation *inside* the loop, not only between pipeline steps; per-file
/// is this loop's natural granularity, matching `codepack-scanner::walk_project`'s
/// per-entry checks from S2).
///
/// ## Why the parallelism cannot change a single byte of the output
///
/// Files are scanned in parallel, but their records are collected **in input order**
/// (`par_iter` is indexed, so `collect` restores the order) and only then flattened.
/// That matters because the three sorts below are stable and their keys are not unique:
/// two secret hits on the same file and line with the same confidence, or two paths
/// differing only in case, tie — and a tie is resolved by insertion order. Producing the
/// records in a different order would silently reorder findings in
/// `06_security_scan.json`, SARIF and the golden references (invariant I5).
///
/// Errors are selected the same way: the per-file results are collected as
/// `Vec<Result<_>>` and the **first** error in input order is returned, rather than
/// whichever thread happened to fail first.
pub fn scan_project(
    root: &Path,
    relative_files: &[PathBuf],
    max_bytes_per_file: Option<u64>,
    cancel: &CancellationToken,
) -> Result<ScanResult> {
    scan_project_with_options(
        root,
        relative_files,
        max_bytes_per_file,
        cancel,
        &ScanOptions::default(),
    )
}

/// [`scan_project`] with the knobs in [`ScanOptions`]. The four-argument form is kept as
/// the name every caller already uses, and is exactly this function with defaults.
pub fn scan_project_with_options(
    root: &Path,
    relative_files: &[PathBuf],
    max_bytes_per_file: Option<u64>,
    cancel: &CancellationToken,
    options: &ScanOptions<'_>,
) -> Result<ScanResult> {
    let per_file: Vec<Result<FileScanRecords>> = relative_files
        .par_iter()
        .map(|relative| {
            if cancel.is_cancelled() {
                return Err(SecurityError::Cancelled);
            }
            scan_one_file(root, relative, max_bytes_per_file, options)
        })
        .collect();

    let mut files: Vec<FileRecord> = Vec::new();
    let mut secrets: Vec<SecretRecord> = Vec::new();
    let mut risky: Vec<RiskyRecord> = Vec::new();
    for record in per_file {
        let record = record?;
        files.extend(record.files);
        secrets.extend(record.secrets);
        risky.extend(record.risky);
    }

    files.sort_by(|a, b| {
        confidence_rank(&a.severity)
            .cmp(&confidence_rank(&b.severity))
            .then_with(|| a.display.to_lowercase().cmp(&b.display.to_lowercase()))
    });
    secrets.sort_by(|a, b| {
        confidence_rank(&a.confidence)
            .cmp(&confidence_rank(&b.confidence))
            .then_with(|| a.display.to_lowercase().cmp(&b.display.to_lowercase()))
            .then_with(|| a.line_number.cmp(&b.line_number))
    });
    risky.sort_by(|a, b| {
        confidence_rank(&a.severity)
            .cmp(&confidence_rank(&b.severity))
            .then_with(|| a.display.to_lowercase().cmp(&b.display.to_lowercase()))
            .then_with(|| a.line_number.cmp(&b.line_number))
    });

    let mut findings = Vec::with_capacity(files.len() + secrets.len() + risky.len());
    for file in &files {
        findings.push(Finding {
            kind: FindingKind::SensitiveFile,
            severity: file.severity.to_string(),
            confidence: "high".to_string(),
            file: file.display.clone(),
            line: None,
            rule: "sensitive_filename".to_string(),
            message: "Sensitive-looking filename or suffix.".to_string(),
        });
    }
    for secret in &secrets {
        findings.push(Finding {
            kind: FindingKind::PotentialSecret,
            severity: secret.confidence.clone(),
            confidence: secret.confidence.clone(),
            file: secret.display.clone(),
            line: Some(secret.line_number),
            rule: secret.rule.clone(),
            message: secret.message.clone(),
        });
    }
    for hit in &risky {
        findings.push(Finding {
            kind: FindingKind::RiskyCode,
            severity: hit.severity.clone(),
            confidence: risky_code::RISKY_CODE_FINDING_CONFIDENCE.to_string(),
            file: hit.display.clone(),
            line: Some(hit.line_number),
            rule: hit.rule.clone(),
            message: hit.explanation.clone(),
        });
    }

    let summary = ScanSummary {
        sensitive_files: files.len(),
        potential_secrets: secrets.len(),
        risky_code: risky.len(),
        total_findings: findings.len(),
    };

    Ok(ScanResult { summary, findings })
}

#[cfg(test)]
mod tests;
