//! `codepack scan` — the security scanner on its own.
//!
//! This is the command a CI pipeline runs on every push: it answers "does this project
//! contain secrets?" without producing a bundle. It is also the command that gives exit
//! code 3 its meaning.

use codepack_core::CancellationToken;
use codepack_core::config::Config;
use codepack_security::{FindingKind, ScanResult, SecurityOptions, scan_project};
use serde::Serialize;

use crate::cli::{ScanArgs, SeverityArg};
use crate::commands::{self, ProjectContext};
use crate::error::Result;
use crate::exit::Outcome;
use crate::output::{self, Format};

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

/// The two baseline paths a caller may supply. Threaded as one value so every entry
/// point takes the same shape, and so a caller that has no baseline says so once.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct BaselineOptions<'a> {
    /// Findings listed here are not reported: they were already present.
    pub read: Option<&'a std::path::Path>,
    /// Where to record the findings that survived the allowlist.
    pub write: Option<&'a std::path::Path>,
}

impl<'a> BaselineOptions<'a> {
    pub(crate) fn from_args(args: &'a ScanArgs) -> Self {
        Self {
            read: args.baseline.as_deref(),
            write: args.write_baseline.as_deref(),
        }
    }
}

/// What a baseline held back on this run.
struct BaselineScreen {
    path: std::path::PathBuf,
    suppressed: Vec<crate::allow::SuppressedFinding>,
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

pub(crate) fn run(args: &ScanArgs, format: Format) -> Result<Outcome> {
    let context = commands::prepare(&args.project)?;
    let baseline_options = BaselineOptions::from_args(args);
    let report = if args.staged {
        build_staged(&context, args.fail_on, baseline_options)?
    } else if args.history {
        build_history(&context, args)?
    } else {
        build(&context, args.fail_on, baseline_options)?
    };

    if let Some(path) = &args.sarif {
        write_sarif(&report, path)?;
    }

    if format.is_json() {
        output::emit_json("scan", &report)?;
    } else {
        print_human(&report);
    }

    Ok(if report.summary.gating > 0 {
        Outcome::CriticalSecretsFound
    } else {
        Outcome::Success
    })
}

/// Writes the findings as SARIF 2.1.0, through the same writer the export pipeline uses.
///
/// The **screened** findings, not the raw ones: a finding the team has accepted in
/// `.codepack-allow` must not reappear as a code-scanning alert, or the allowlist would
/// mean one thing at the terminal and another in the pipeline.
fn write_sarif(report: &ScanReport, path: &std::path::Path) -> Result<()> {
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

pub(crate) fn build(
    context: &ProjectContext,
    fail_on: SeverityArg,
    baseline_options: BaselineOptions<'_>,
) -> Result<ScanReport> {
    build_with_cancel(
        context,
        fail_on,
        baseline_options,
        &CancellationToken::new(),
    )
}

/// [`build`] with a token the caller can trip, for a client that can ask a running scan
/// to stop.
pub(crate) fn build_with_cancel(
    context: &ProjectContext,
    fail_on: SeverityArg,
    baseline_options: BaselineOptions<'_>,
    cancel: &CancellationToken,
) -> Result<ScanReport> {
    // Scanned with safe mode forced to `full`, meaning "exclude nothing on safety
    // grounds" — so the scan sees every file the ignore rules include, including the
    // ones an export would drop.
    //
    // This is the whole point of the command. Scanning the file set an export *would*
    // produce makes `scan` answer "is my bundle clean?", which is always yes: safe mode
    // removed the dangerous files before the scanner ever looked. A `.env` full of live
    // credentials sitting in the repository would be reported as "No findings", which
    // is worse than useless in the pre-commit and CI gate this command exists to be.
    // `preview` already answers the "what would I share?" question.
    //
    // Ignore rules still apply: `node_modules` and build output are not the user's
    // secrets to answer for, and scanning them would bury real findings in noise.
    let scan_config = Config {
        safe_export_mode: "full".to_string(),
        // A diff mode would narrow the scan to changed files; a secret that was
        // committed last week is still a secret today.
        diff_export_mode: "all".to_string(),
        // The budget drops low-value files, which has nothing to do with whether they
        // hold credentials.
        token_budget: 0,
        // The text-file size limit makes `SecurityOptions` skip a file whole rather
        // than truncate it, and the skip is invisible in the report. Two of the five
        // presets enable it (1 MB and 2 MB), so `scan --preset chatgpt` would answer
        // "No findings" for a credential sitting in a large file. A size limit is a
        // statement about what is worth *shipping*, never about what is worth looking
        // at.
        text_file_size_limit_enabled: false,
        ..context.config.clone()
    };

    let plan = codepack_engine::plan_export(
        &context.root,
        &scan_config,
        &std::collections::HashMap::new(),
        None,
        cancel,
    )?;
    let relative_files: Vec<std::path::PathBuf> = plan
        .export_plan
        .included_files
        .iter()
        .map(|file| to_relative_path(&file.relative_path))
        .collect();

    let options = SecurityOptions::from(&scan_config);
    let result = scan_project(
        &context.root,
        &relative_files,
        options.max_bytes_per_file,
        cancel,
    )?;

    let (screened, baseline) = screen_all(&context.root, baseline_options, &result)?;
    Ok(assemble(
        context,
        "project",
        relative_files.len(),
        &screened,
        baseline.as_ref(),
        fail_on,
        None,
        &Origins::default(),
    ))
}

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
struct Origin {
    commit: String,
    committed_at: String,
    summary: String,
}

/// Keyed by the repository path a finding was relabelled onto, plus its line.
type Origins = std::collections::HashMap<(String, Option<usize>), Origin>;

/// Rewrites `.\<blob id>\<path>` back to `.\<path>` and records which commit each
/// finding came from.
///
/// When two historical versions of the same path both carry a finding on the same line,
/// the **earlier** commit is the one recorded. The walk runs newest-first, so the last
/// write into the map is the oldest commit — and "when did this first get in" is the
/// question a history scan exists to answer.
fn relabel_onto_repository_paths(
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
fn display_of(relative: &std::path::Path) -> String {
    if relative.as_os_str().is_empty() {
        ".".to_string()
    } else {
        format!(".\\{}", relative.to_string_lossy().replace('/', "\\"))
    }
}

/// Scans only what is staged in git, reading the staged content itself.
///
/// The allowlist is still read from the real project root, not from the temporary
/// directory the staged blobs were unpacked into: `.codepack-allow` is a property of the
/// repository, and a staged scan that ignored it would report findings a team has
/// already accepted — the exact noise this feature exists to remove.
pub(crate) fn build_staged(
    context: &ProjectContext,
    fail_on: SeverityArg,
    baseline_options: BaselineOptions<'_>,
) -> Result<ScanReport> {
    build_staged_with_cancel(
        context,
        fail_on,
        baseline_options,
        &CancellationToken::new(),
    )
}

/// [`build_staged`] with a token the caller can trip.
pub(crate) fn build_staged_with_cancel(
    context: &ProjectContext,
    fail_on: SeverityArg,
    baseline_options: BaselineOptions<'_>,
    cancel: &CancellationToken,
) -> Result<ScanReport> {
    let staged = crate::staged::collect(&context.root)?;

    let result = if staged.is_empty() {
        ScanResult::default()
    } else {
        let options = SecurityOptions::from(&Config {
            text_file_size_limit_enabled: false,
            ..context.config.clone()
        });
        scan_project(
            staged.root(),
            staged.relative_files(),
            options.max_bytes_per_file,
            cancel,
        )?
    };

    let (screened, baseline) = screen_all(&context.root, baseline_options, &result)?;
    Ok(assemble(
        context,
        "staged",
        staged.relative_files().len(),
        &screened,
        baseline.as_ref(),
        fail_on,
        None,
        &Origins::default(),
    ))
}

fn screen_with_allowlist(
    project_root: &std::path::Path,
    result: &ScanResult,
) -> Result<crate::allow::Screened> {
    Ok(match crate::allow::load(project_root)? {
        Some((path, index)) => crate::allow::screen(result, &path, &index),
        None => crate::allow::Screened::unfiltered(result),
    })
}

/// The allowlist first, then `--write-baseline`, then `--baseline`, in that order.
///
/// Order matters and is not arbitrary. The allowlist runs first because an accepted
/// finding is accepted, full stop — recording it in a baseline as well would be noise.
/// A baseline is then *written* from what survives, which is exactly the set a team
/// wants frozen. And `--baseline` filters last, so what is reported is what is genuinely
/// new.
fn screen_all(
    project_root: &std::path::Path,
    baseline_options: BaselineOptions<'_>,
    result: &ScanResult,
) -> Result<(crate::allow::Screened, Option<BaselineScreen>)> {
    let screened = screen_with_allowlist(project_root, result)?;

    if let Some(path) = baseline_options.write {
        let written = crate::baseline::write(path, project_root, &screened.to_result())?;
        output::note(format!(
            "baseline written to {} ({written} finding(s))",
            path.display()
        ));
    }

    let Some(path) = baseline_options.read else {
        return Ok((screened, None));
    };
    let index = crate::baseline::load(path)?;
    let after = crate::allow::screen(&screened.to_result(), path, &index);
    Ok((
        crate::allow::Screened {
            findings: after.findings,
            suppressed: screened.suppressed,
            allowlist_path: screened.allowlist_path,
        },
        Some(BaselineScreen {
            path: path.to_path_buf(),
            suppressed: after.suppressed,
        }),
    ))
}

/// Builds the report from the findings that **survived** the allowlist.
///
/// The summary counts are recomputed from the survivors rather than copied from
/// `ScanResult::summary`, which still counts suppressed findings. A report whose header
/// disagreed with its own list would be worse than having no header.
#[allow(clippy::too_many_arguments)]
fn assemble(
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

fn kind_label(kind: FindingKind) -> &'static str {
    match kind {
        FindingKind::SensitiveFile => "sensitive_file",
        FindingKind::PotentialSecret => "potential_secret",
        FindingKind::RiskyCode => "risky_code",
    }
}

/// The plan stores backslash-joined relative paths regardless of platform; rebuild a
/// real path rather than handing the string to `Path::new`, which would treat the whole
/// thing as one component on Unix.
fn to_relative_path(relative: &str) -> std::path::PathBuf {
    relative.split('\\').collect()
}

fn print_human(report: &ScanReport) {
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
fn print_history_notice(report: &ScanReport) {
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
}

/// Says how many findings the allowlist accepted, and from which file.
///
/// Printed on every run that used an allowlist, including when it suppressed nothing.
/// A reader must never have to wonder whether a quiet report is quiet because there was
/// nothing to say or because something was hidden.
fn print_suppression_notice(report: &ScanReport) {
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
fn print_baseline_notice(report: &ScanReport) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::ResolutionTrace;

    fn context_with(root: &std::path::Path, config: Config) -> ProjectContext {
        ProjectContext {
            root: root.to_path_buf(),
            config,
            trace: ResolutionTrace::default(),
        }
    }

    #[test]
    fn a_text_file_size_limit_does_not_hide_a_secret_from_the_scan() {
        // Reachable through `--preset chatgpt`, a user profile, or `.codepack.toml`.
        // The scanner skips an over-limit file entirely, so without the override this
        // reported "No findings" for a file that plainly holds a credential — a silent
        // false negative in the command a CI gate runs.
        let dir = tempfile::tempdir().unwrap();
        let mut contents = "# padding
"
        .repeat(120_000);
        contents.push_str(
            "AWS_SECRET_ACCESS_KEY = \"wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY\"
",
        );
        std::fs::write(dir.path().join("big.py"), &contents).unwrap();
        assert!(
            contents.len() > 1024 * 1024,
            "the file must exceed the limit"
        );

        let config = Config {
            text_file_size_limit_enabled: true,
            max_text_file_mb: 1,
            ..Config::default()
        };
        let report = build(
            &context_with(dir.path(), config),
            SeverityArg::Critical,
            BaselineOptions::default(),
        )
        .unwrap();

        assert!(
            report.summary.total_findings > 0,
            "the credential must be reported despite the size limit"
        );
    }

    /// Builds a repository whose history carries a credential that is no longer in the
    /// working tree. Through `git2`, never a `git` binary.
    fn repository_with_a_deleted_secret(root: &std::path::Path) -> git2::Repository {
        let repository = git2::Repository::init(root).unwrap();
        let signature = git2::Signature::now("Test", "test@example.local").unwrap();

        let commit_all = |message: &str| {
            let mut index = repository.index().unwrap();
            index
                .add_all(["."], git2::IndexAddOption::DEFAULT, None)
                .unwrap();
            index.write().unwrap();
            let tree_id = index.write_tree().unwrap();
            let tree = repository.find_tree(tree_id).unwrap();
            let parents = match repository
                .head()
                .ok()
                .and_then(|head| head.peel_to_commit().ok())
            {
                Some(parent) => vec![parent],
                None => Vec::new(),
            };
            let refs: Vec<&git2::Commit<'_>> = parents.iter().collect();
            repository
                .commit(Some("HEAD"), &signature, &signature, message, &tree, &refs)
                .unwrap();
        };

        std::fs::write(
            root.join("settings.py"),
            "AWS_SECRET_ACCESS_KEY = \"wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY\"\n",
        )
        .unwrap();
        commit_all("add settings");

        std::fs::write(root.join("settings.py"), "SETTINGS = {}\n").unwrap();
        commit_all("remove the credential");

        repository
    }

    fn history_args(project: &std::path::Path) -> ScanArgs {
        ScanArgs {
            project: crate::cli::ProjectArgs {
                path: project.to_path_buf(),
                preset: None,
                profile: None,
                safe_mode: None,
                diff: None,
                budget: None,
                archive_format: None,
            },
            staged: false,
            history: true,
            since: None,
            max_commits: None,
            baseline: None,
            write_baseline: None,
            sarif: None,
            fail_on: SeverityArg::Critical,
        }
    }

    #[test]
    fn a_working_tree_scan_misses_what_a_history_scan_finds() {
        // Both halves matter. The first is what users believe today; the second is what
        // is actually true of the repository they are about to share.
        let dir = tempfile::tempdir().unwrap();
        repository_with_a_deleted_secret(dir.path());
        let context = context_with(dir.path(), Config::default());

        let working_tree =
            build(&context, SeverityArg::Critical, BaselineOptions::default()).unwrap();
        assert_eq!(
            working_tree.summary.potential_secrets, 0,
            "the working tree really is clean"
        );

        let history = build_history(&context, &history_args(dir.path())).unwrap();
        assert!(
            history.summary.potential_secrets > 0,
            "the credential is still in the history and must be reported"
        );
    }

    #[test]
    fn a_history_finding_names_the_commit_and_the_repository_path() {
        let dir = tempfile::tempdir().unwrap();
        repository_with_a_deleted_secret(dir.path());

        let report = build_history(
            &context_with(dir.path(), Config::default()),
            &history_args(dir.path()),
        )
        .unwrap();

        let finding = report
            .findings
            .iter()
            .find(|finding| finding.kind == "potential_secret")
            .expect("the historical credential");

        // Relabelled off the temporary directory: a path holding a blob id names
        // nothing a person can act on.
        assert_eq!(finding.file, ".\\settings.py");
        assert!(finding.commit.is_some(), "no commit was attributed");
        let when = finding.committed_at.clone().unwrap();
        assert!(when.ends_with(" UTC"), "{when}");
        assert_eq!(finding.commit_summary.as_deref(), Some("add settings"));
        assert_eq!(report.source, "history");
        assert!(report.history.is_some());
    }

    #[test]
    fn a_history_scan_of_a_directory_outside_a_repository_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let error = build_history(
            &context_with(dir.path(), Config::default()),
            &history_args(dir.path()),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("git repository"), "{error}");
    }

    #[test]
    fn the_default_threshold_gates_on_exactly_what_it_always_did() {
        let dir = tempfile::tempdir().unwrap();
        // `high`, not `critical`: an assignment in a shell script, the Q25 example.
        std::fs::write(
            dir.path().join("deploy.sh"),
            "export API_KEY=\"abcdef123456\"\n",
        )
        .unwrap();

        let context = context_with(dir.path(), Config::default());
        let default_run =
            build(&context, SeverityArg::Critical, BaselineOptions::default()).unwrap();
        assert!(
            default_run.summary.total_findings > 0,
            "the finding must still be reported"
        );
        assert_eq!(
            default_run.summary.gating, 0,
            "the published exit-code contract gates on critical only"
        );

        let raised = build(&context, SeverityArg::High, BaselineOptions::default()).unwrap();
        assert!(
            raised.summary.gating > 0,
            "--fail-on high must gate on the same finding"
        );
    }

    #[test]
    fn the_severity_threshold_ignores_a_level_this_build_does_not_know() {
        // Failing a pipeline on a guess is worse than not failing it.
        assert!(!SeverityArg::Low.is_reached_by("catastrophic"));
        assert!(SeverityArg::Low.is_reached_by("low"));
        assert!(!SeverityArg::Critical.is_reached_by("high"));
    }

    #[test]
    fn sarif_is_written_from_the_findings_that_survived_the_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("settings.py"),
            "AWS_SECRET_ACCESS_KEY = \"wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY\"\n",
        )
        .unwrap();

        let report = build(
            &context_with(dir.path(), Config::default()),
            SeverityArg::Critical,
            BaselineOptions::default(),
        )
        .unwrap();
        let sarif = dir.path().join("out").join("scan.sarif");
        write_sarif(&report, &sarif).unwrap();

        let text = std::fs::read_to_string(&sarif).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
        let results = parsed["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), report.findings.len());
        assert!(
            !text.contains("wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"),
            "invariant I3: the value must not reach the SARIF file"
        );
    }

    #[test]
    fn the_display_spelling_matches_what_the_scanner_produces() {
        // `display_of` reproduces `codepack-security`'s own relative-path spelling.
        // If that ever changes, the history relabelling silently stops matching and
        // every historical finding loses its commit — so the two are pinned together.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src").join(".env"), "TOKEN=x\n").unwrap();

        let report = build(
            &context_with(dir.path(), Config::default()),
            SeverityArg::Critical,
            BaselineOptions::default(),
        )
        .unwrap();
        let reported = &report.findings[0].file;

        assert_eq!(
            *reported,
            display_of(std::path::Path::new("src/.env")),
            "the scanner's spelling and this module's have drifted"
        );
    }
}
