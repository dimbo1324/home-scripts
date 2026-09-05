//! The heuristic scanner — "Enhanced Security Scan v3" — ported from legacy
//! `reports/insights/security.py`, plus provider signatures and entropy (BLUEPRINT
//! §B.1). [`scan_project`] takes a **caller-supplied list of files**; it never walks
//! the filesystem itself (that is `codepack-scanner`'s job, S2; combining the two is
//! S9's). Reading individual file contents from disk is not "walking" and stays in
//! scope here.

mod paths;
pub mod write;

use std::path::{Path, PathBuf};

use codepack_core::CancellationToken;
use rayon::prelude::*;

use crate::error::{Result, SecurityError};
use crate::patterns::{confidence_rank, risky_code};

mod detect;
mod records;
mod types;

pub use types::{Finding, FindingKind, ScanOptions, ScanResult, ScanSummary, result_from_findings};

use records::{FileRecord, FileScanRecords, RiskyRecord, SecretRecord, scan_one_file};

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
        confidence_rank(a.severity)
            .cmp(&confidence_rank(b.severity))
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
