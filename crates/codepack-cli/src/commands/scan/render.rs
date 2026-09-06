//! The human-readable rendering, and the SARIF side output.
//!
//! Apart from the scanning for the reason every printer is: this is the half that
//! changes for cosmetic reasons, and nothing in it may change a verdict.

use crate::error::Result;
use crate::output;

use codepack_security::{FindingKind, ScanResult};

use super::report::ScanReport;

/// Writes the findings as SARIF 2.1.0, through the same writer the export pipeline uses.
///
/// The **screened** findings, not the raw ones: a finding the team has accepted in
/// `.codepack-allow` must not reappear as a code-scanning alert, or the allowlist would
/// mean one thing at the terminal and another in the pipeline.
pub(super) fn write_sarif(report: &ScanReport, path: &std::path::Path) -> Result<()> {
    let findings = report
        .findings
        .iter()
        .map(|finding| codepack_security::Finding {
            kind: match finding.kind {
                "sensitive_file" => FindingKind::SensitiveFile,
                "risky_code" => FindingKind::RiskyCode,
                _ => FindingKind::PotentialSecret,
            },
            severity: finding.severity.clone(),
            confidence: finding.confidence.clone(),
            file: finding.file.clone(),
            line: finding.line,
            rule: finding.rule.clone(),
            message: finding.message.clone(),
        })
        .collect::<Vec<_>>();

    let result = ScanResult {
        summary: codepack_security::ScanSummary {
            sensitive_files: report.summary.sensitive_files,
            potential_secrets: report.summary.potential_secrets,
            risky_code: report.summary.risky_code,
            total_findings: report.summary.total_findings,
        },
        findings,
    };

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|source| crate::error::CliError::Read {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    codepack_security::scan::write::write_sarif_report(&result, path)
        .map_err(|error| crate::error::CliError::message(error.to_string()))
}

pub(super) fn print_human(report: &ScanReport) {
    output::line(format!("Project:   {}", report.project));
    output::line(format!(
        "Scanned:   {} {} file(s) in {} mode",
        report.scanned_files, report.source, report.safe_mode
    ));
    print_history_notice(report);
    print_suppression_notice(report);
    print_baseline_notice(report);
    output::line("");

    if report.findings.is_empty() {
        if report.source == "staged" && report.scanned_files == 0 {
            output::line("Nothing staged; there is nothing to check.");
        } else {
            output::line("No findings.");
        }
        return;
    }

    output::line(format!(
        "{} finding(s): {} sensitive file(s), {} potential secret(s), {} risky code",
        report.summary.total_findings,
        report.summary.sensitive_files,
        report.summary.potential_secrets,
        report.summary.risky_code
    ));
    if report.summary.critical > 0 {
        output::line(format!("{} of them are critical.", report.summary.critical));
    }
    output::line("");

    for finding in &report.findings {
        let location = match finding.line {
            Some(line) => format!("{}:{}", finding.file, line),
            None => finding.file.clone(),
        };
        output::line(format!(
            "  [{}] {} ({}) — {}",
            finding.severity, location, finding.rule, finding.message
        ));
        // Printed under the finding rather than folded into the location: a history
        // finding is about a commit, and "which commit" is the first thing a reader
        // needs in order to do anything about it.
        if let Some(commit) = &finding.commit {
            let when = finding.committed_at.as_deref().unwrap_or("");
            let subject = finding.commit_summary.as_deref().unwrap_or("");
            output::line(format!("           in commit {commit} ({when}) {subject}"));
        }
        // The fingerprint is printed with the finding, not in a separate block, so
        // accepting one is a copy of the line you are already looking at.
        output::line(format!("           fingerprint: {}", finding.fingerprint));
    }
}

/// Says what a history walk actually covered.
///
/// The truncation notice is deliberately worded as a limit on the *answer*, not as a
/// statistic: "500 commits walked" reads like completeness to someone skimming, and a
/// clean result over part of a history is not a clean history.
pub(super) fn print_history_notice(report: &ScanReport) {
    let Some(history) = &report.history else {
        return;
    };
    match &history.since {
        Some(reference) => output::line(format!(
            "History:   {} commit(s) added since {reference}",
            history.commits_walked
        )),
        None => output::line(format!("History:   {} commit(s)", history.commits_walked)),
    }
    if history.truncated {
        output::line(format!(
            "WARNING:   the walk stopped at {} commits, so anything older was NOT checked. \
             Use --max-commits 0 for the whole history.",
            history.commits_walked
        ));
    }
    if history.skipped_large_blobs > 0 {
        output::line(format!(
            "Note:      {} file version(s) were too large to scan and were skipped.",
            history.skipped_large_blobs
        ));
    }
    if history.truncated_by_size {
        output::line(
            "WARNING:   the walk stopped after materialising as much history as it is \
             allowed to, so older file versions were NOT checked.",
        );
    }
    if history.skipped_unsafe_paths > 0 {
        output::line(format!(
            "WARNING:   {} tree entr(ies) named a path outside the repository and were NOT \
             scanned. That name is itself worth investigating.",
            history.skipped_unsafe_paths
        ));
    }
}

/// Says how many findings the allowlist accepted, and from which file.
///
/// Printed on every run that used an allowlist, including when it suppressed nothing.
/// A reader must never have to wonder whether a quiet report is quiet because there was
/// nothing to say or because something was hidden.
pub(super) fn print_suppression_notice(report: &ScanReport) {
    let Some(path) = &report.allowlist else {
        return;
    };
    if report.suppressed.is_empty() {
        output::line(format!("Allowlist: {path} (nothing suppressed)"));
        return;
    }
    output::line(format!(
        "Allowlist: {path} — {} finding(s) accepted and not shown below:",
        report.suppressed.len()
    ));
    for entry in &report.suppressed {
        output::line(format!(
            "  [{}] {} ({}) — {}",
            entry.severity, entry.file, entry.rule, entry.reason
        ));
    }
}

/// Says how many findings the baseline held back, and from which file.
///
/// Printed for the same reason as the allowlist notice, and separately from it: the two
/// mean different things. An allowlisted finding was read by somebody; a baselined one
/// was merely already there. Counts only — listing several hundred entries a team has
/// deliberately frozen would bury the finding the run exists to show.
pub(super) fn print_baseline_notice(report: &ScanReport) {
    let Some(path) = &report.baseline else {
        return;
    };
    if report.baselined.is_empty() {
        output::line(format!("Baseline:  {path} (nothing held back)"));
        return;
    }
    output::line(format!(
        "Baseline:  {path} — {} finding(s) already recorded and not shown below.",
        report.baselined.len()
    ));
}
