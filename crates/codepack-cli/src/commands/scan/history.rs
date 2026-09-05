//! Scanning every version a file ever had, and naming the commit that introduced one.
//!
//! The walk itself is `crate::history_scan`; what lives here is the reporting half —
//! putting a finding back onto the path it had in the repository, because a path
//! containing a blob id is not something a person recognises.

use codepack_core::CancellationToken;
use codepack_core::config::Config;
use codepack_security::{ScanResult, SecurityOptions, scan_project};

use crate::cli::ScanArgs;
use crate::commands::ProjectContext;
use crate::error::Result;

use super::report::{HistorySummary, ScanReport, assemble};
use super::screening::{BaselineOptions, screen_all};

/// Scans every distinct version of every file the history ever carried.
///
/// The findings are relabelled from the temporary directory the blobs were written to
/// back onto the paths they had in the repository, **before** the allowlist runs: a
/// fingerprint has to be stable and has to name something a person recognises, and a
/// path containing a blob id is neither.
pub(crate) fn build_history(context: &ProjectContext, args: &ScanArgs) -> Result<ScanReport> {
    build_history_with_cancel(context, args, &CancellationToken::new())
}

/// [`build_history`] with a token the caller can trip. A history walk is the longest
/// thing this command does, so it is the one most worth being able to stop.
pub(crate) fn build_history_with_cancel(
    context: &ProjectContext,
    args: &ScanArgs,
    cancel: &CancellationToken,
) -> Result<ScanReport> {
    let options = crate::history_scan::HistoryOptions {
        since: args.since.clone(),
        max_commits: args
            .max_commits
            .unwrap_or(crate::history_scan::DEFAULT_MAX_COMMITS),
    };
    let history = crate::history_scan::collect(&context.root, &options)?;

    let relative_files = history.relative_files();
    let result = if relative_files.is_empty() {
        ScanResult::default()
    } else {
        let scan_options = SecurityOptions::from(&Config {
            text_file_size_limit_enabled: false,
            ..context.config.clone()
        });
        scan_project(
            history.root(),
            &relative_files,
            scan_options.max_bytes_per_file,
            cancel,
        )?
    };

    let (result, origins) = relabel_onto_repository_paths(&result, &history);
    let (screened, baseline) =
        screen_all(&context.root, BaselineOptions::from_args(args), &result)?;

    let summary = HistorySummary {
        commits_walked: history.commits_walked,
        truncated: history.truncated,
        skipped_large_blobs: history.skipped_large_blobs,
        skipped_unsafe_paths: history.skipped_unsafe_paths,
        since: args.since.clone(),
    };

    Ok(assemble(
        context,
        "history",
        relative_files.len(),
        &screened,
        baseline.as_ref(),
        args.fail_on,
        Some(summary),
        &origins,
    ))
}

/// Where a historical finding came from.

#[derive(Debug, Clone)]
pub(super) struct Origin {
    pub(super) commit: String,
    pub(super) committed_at: String,
    pub(super) summary: String,
}

/// Keyed by the repository path a finding was relabelled onto, plus its line.
pub(super) type Origins = std::collections::HashMap<(String, Option<usize>), Origin>;

/// Rewrites `.\<blob id>\<path>` back to `.\<path>` and records which commit each
/// finding came from.
///
/// When two historical versions of the same path both carry a finding on the same line,
/// the **earlier** commit is the one recorded. The walk runs newest-first, so the last
/// write into the map is the oldest commit — and "when did this first get in" is the
/// question a history scan exists to answer.
pub(super) fn relabel_onto_repository_paths(
    result: &ScanResult,
    history: &crate::history_scan::HistoryContent,
) -> (ScanResult, Origins) {
    let by_materialised: std::collections::HashMap<String, &crate::history_scan::HistoricalBlob> =
        history
            .blobs()
            .iter()
            .map(|blob| (display_of(&blob.relative), blob))
            .collect();

    let mut origins: Origins = Origins::new();
    let mut findings = Vec::with_capacity(result.findings.len());

    for finding in &result.findings {
        let Some(blob) = by_materialised.get(&finding.file) else {
            // Not something this walk wrote. Kept as-is rather than dropped: a finding
            // nobody can explain is still a finding, and silently discarding one in a
            // security report is the wrong direction to be wrong in.
            findings.push(finding.clone());
            continue;
        };
        let repo_display = display_of(std::path::Path::new(&blob.repo_path));
        origins.insert(
            (repo_display.clone(), finding.line),
            Origin {
                commit: blob.commit.clone(),
                committed_at: blob.committed_at.clone(),
                summary: blob.summary.clone(),
            },
        );
        findings.push(codepack_security::Finding {
            file: repo_display,
            ..finding.clone()
        });
    }

    let summary = result.summary;
    (ScanResult { summary, findings }, origins)
}

/// The `.\a\b` spelling `codepack-security` gives a relative path. Reproduced here
/// rather than exported from that crate: this is the one place outside it that has to
/// speak its display convention, and a test below pins the two together.
pub(super) fn display_of(relative: &std::path::Path) -> String {
    if relative.as_os_str().is_empty() {
        ".".to_string()
    } else {
        format!(".\\{}", relative.to_string_lossy().replace('/', "\\"))
    }
}
