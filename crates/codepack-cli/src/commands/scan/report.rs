//! The shape of what `scan` answers with.
//!
//! Split out of this command's single file on 2026-09-05. These types are the published
//! `--json` contract, so they sit apart from the code that fills them in: somebody
//! checking what a field means should not have to read a scanner to find out.

use codepack_security::FindingKind;
use serde::Serialize;

use crate::cli::SeverityArg;
use crate::commands::ProjectContext;

use super::history::Origins;
use super::screening::BaselineScreen;

#[derive(Debug, Serialize)]
pub(crate) struct ScanReport {
    pub project: String,
    /// Always `full`: a scan deliberately looks at everything the ignore rules include,
    /// not at what an export would keep. Reported so the output is self-explaining.
    pub safe_mode: String,
    /// What the file set was drawn from: every file the ignore rules include, only what
    /// is staged in git, or every distinct version of every file in the history.
    /// Reported so a consumer never has to infer which question this result answers.
    pub source: &'static str,
    pub scanned_files: usize,
    /// Only present for `--history`. Kept in its own object rather than as loose fields
    /// so a consumer can test for the mode by the key's presence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history: Option<HistorySummary>,
    /// The severity at which this run gates, echoed back so a pipeline's log records
    /// which threshold produced the exit code.
    pub fail_on: &'static str,
    pub summary: Summary,
    pub findings: Vec<ReportedFinding>,
    /// Findings accepted by `.codepack-allow`. Always present, even when empty: a
    /// consumer must be able to tell "nothing was suppressed" from "this build of the
    /// report cannot suppress anything".
    pub suppressed: Vec<crate::allow::SuppressedFinding>,
    /// Where the allowlist was read from, when one was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowlist: Option<String>,
    /// Findings held back by a baseline: they were already there when it was recorded.
    /// Separate from `suppressed` because they mean something weaker — nobody reviewed
    /// them, they were merely present.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub baselined: Vec<crate::allow::SuppressedFinding>,
    /// Where the baseline was read from, when one was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline: Option<String>,
}

fn is_zero(count: &usize) -> bool {
    *count == 0
}

/// What a history walk actually covered. Every field here exists so a partial answer
/// cannot pass for a complete one.
#[derive(Debug, Serialize)]
pub(crate) struct HistorySummary {
    pub commits_walked: usize,
    /// True when the commit cap stopped the walk before the history ran out — meaning
    /// "no findings" covers only the commits that were read.
    pub truncated: bool,
    /// Blobs skipped for being too large to be worth materialising.
    pub skipped_large_blobs: usize,
    /// Tree entries skipped for naming a path outside the temporary root. Absent from
    /// the payload when zero, which is an additive change and needs no schema bump.
    #[serde(skip_serializing_if = "is_zero")]
    pub skipped_unsafe_paths: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct Summary {
    pub sensitive_files: usize,
    pub potential_secrets: usize,
    pub risky_code: usize,
    pub total_findings: usize,
    /// Findings at `critical` severity. Broken out because a consumer should not have
    /// to recount it, and because it stayed the meaning of exit code 3 when `--fail-on`
    /// arrived.
    pub critical: usize,
    /// Findings at or above the `--fail-on` threshold — the number the exit code is
    /// actually derived from. Equal to `critical` on a default run.
    pub gating: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct ReportedFinding {
    pub kind: &'static str,
    pub severity: String,
    pub confidence: String,
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    pub rule: String,
    /// Already redacted by `codepack-security` before it ever reaches here — invariant
    /// I3 forbids a raw secret value in any output, and that includes this one.
    pub message: String,
    /// Stable identity of this finding, for pasting into `.codepack-allow`. Reported so
    /// nobody has to derive it by hand — deriving it by hand is how a typo gets into a
    /// file whose entries silently match nothing.
    pub fingerprint: String,
    /// `--history` only: the commit that introduced the content this finding sits in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// `--history` only: when that commit landed, at full precision and in UTC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub committed_at: Option<String>,
    /// `--history` only: that commit's subject line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_summary: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn assemble(
    context: &ProjectContext,
    source: &'static str,
    scanned_files: usize,
    screened: &crate::allow::Screened,
    baseline: Option<&BaselineScreen>,
    fail_on: SeverityArg,
    history: Option<HistorySummary>,
    origins: &Origins,
) -> ScanReport {
    let findings = &screened.findings;
    let critical = findings
        .iter()
        .filter(|finding| finding.severity == "critical")
        .count();
    let gating = findings
        .iter()
        .filter(|finding| fail_on.is_reached_by(&finding.severity))
        .count();

    let count_of = |kind: FindingKind| findings.iter().filter(|f| f.kind == kind).count();

    ScanReport {
        project: context.root.display().to_string(),
        safe_mode: "full".to_string(),
        source,
        scanned_files,
        history,
        fail_on: fail_on.as_str(),
        summary: Summary {
            sensitive_files: count_of(FindingKind::SensitiveFile),
            potential_secrets: count_of(FindingKind::PotentialSecret),
            risky_code: count_of(FindingKind::RiskyCode),
            total_findings: findings.len(),
            critical,
            gating,
        },
        findings: findings
            .iter()
            .map(|finding| {
                let origin = origins.get(&(finding.file.clone(), finding.line));
                ReportedFinding {
                    kind: kind_label(finding.kind),
                    severity: finding.severity.clone(),
                    confidence: finding.confidence.clone(),
                    file: finding.file.clone(),
                    line: finding.line,
                    rule: finding.rule.clone(),
                    message: finding.message.clone(),
                    fingerprint: crate::allow::fingerprint_of(finding),
                    commit: origin.map(|origin| origin.commit.clone()),
                    committed_at: origin.map(|origin| origin.committed_at.clone()),
                    commit_summary: origin.map(|origin| origin.summary.clone()),
                }
            })
            .collect(),
        suppressed: screened.suppressed.clone(),
        allowlist: screened
            .allowlist_path
            .as_ref()
            .map(|path| path.display().to_string()),
        baselined: baseline
            .map(|baseline| baseline.suppressed.clone())
            .unwrap_or_default(),
        baseline: baseline.map(|baseline| baseline.path.display().to_string()),
    }
}

pub(super) fn kind_label(kind: FindingKind) -> &'static str {
    match kind {
        FindingKind::SensitiveFile => "sensitive_file",
        FindingKind::PotentialSecret => "potential_secret",
        FindingKind::RiskyCode => "risky_code",
    }
}
