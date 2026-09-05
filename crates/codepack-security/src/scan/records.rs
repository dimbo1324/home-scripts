//! What one file contributes to a scan.
//!
//! The per-file pass: read it, decide whether the content can be reused from the cache,
//! and turn what the detectors say about each line into records the collector sorts.
//! Kept apart from `detect` because this half touches the disk and the cache, and that
//! half touches neither.

use std::fs;
use std::path::Path;

use crate::cache;
use crate::classify;
use crate::error::{Result, SecurityError};
use crate::patterns::risky_code;

use super::detect::{
    collect_risky_hits, collect_secret_hits, redacted_message, sensitive_file_severity,
};
use super::paths;
use super::types::{FindingKind, ScanOptions};

pub(super) struct FileRecord {
    pub(super) severity: &'static str,
    pub(super) display: String,
}

pub(super) struct SecretRecord {
    pub(super) confidence: String,
    pub(super) display: String,
    pub(super) line_number: usize,
    pub(super) rule: String,
    pub(super) message: String,
}

pub(super) struct RiskyRecord {
    pub(super) severity: String,
    pub(super) display: String,
    pub(super) line_number: usize,
    pub(super) rule: String,
    pub(super) explanation: String,
}

/// Everything one file contributes, kept together so the parallel pass can hand back a
/// single value per file and the caller can flatten the results in input order.
#[derive(Default)]
pub(super) struct FileScanRecords {
    pub(super) files: Vec<FileRecord>,
    pub(super) secrets: Vec<SecretRecord>,
    pub(super) risky: Vec<RiskyRecord>,
}

/// The body of what used to be `scan_project`'s per-file loop iteration, unchanged in
/// behaviour: a sensitive filename is recorded even for a file whose contents are not
/// read, and every early exit that used to `continue` now returns what has been
/// collected so far.
pub(super) fn scan_one_file(
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
