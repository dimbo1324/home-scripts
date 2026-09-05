//! `codepack export` — the full pipeline.
//!
//! Thin by design: every decision lives in `codepack-engine`, and this module's job is
//! to hand it a resolved configuration, stream its progress to stderr, and turn its
//! outcome into a report and an exit code.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use codepack_core::{CancellationToken, ProgressEvent};
use serde::Serialize;

use crate::cli::ExportArgs;
use crate::commands::{self, ProjectContext};
use crate::error::{CliError, Result};
use crate::exit::Outcome;
use crate::output::{self, Format};
use crate::settings::ResolutionTrace;

#[derive(Debug, Serialize)]
pub(crate) struct ExportReport {
    pub project: String,
    pub profile: String,
    pub safe_mode: String,
    pub diff_mode: String,
    /// `false` when the run was cancelled or hit copy errors. The bundle may still
    /// exist — steps 7 and 8 always run — but it describes an incomplete export.
    pub successful: bool,
    pub cancelled: bool,
    pub files_copied: u32,
    pub files_skipped: u32,
    pub errors: u32,
    /// The archive a user should pick up, or `null` if none was produced.
    pub result_path: Option<String>,
    pub archives: Vec<String>,
    /// Where the bundle was assembled, useful when no single archive was produced.
    pub staging_dir: String,
    pub critical_findings: usize,
    pub run_id: i64,
    pub resolution: ResolutionTrace,
}

pub(crate) fn run(args: &ExportArgs, format: Format) -> Result<Outcome> {
    let context = commands::prepare(&args.project)?;
    let report = build(&context, args.out.as_deref(), format.is_json())?;

    if format.is_json() {
        output::emit_json("export", &report)?;
    } else {
        print_human(&report);
    }

    // Order matters, and it is the same rule the rest of this binary follows: whether
    // the work succeeded outranks what the work found. An export that hit copy errors
    // or was cancelled still writes a bundle — steps 7 and 8 always run — so returning
    // 0 or 3 for it would tell a pipeline an incomplete snapshot is fit to publish.
    Ok(if !report.successful {
        Outcome::Incomplete
    } else if report.critical_findings > 0 {
        Outcome::CriticalSecretsFound
    } else {
        Outcome::Success
    })
}

/// Runs the pipeline and shapes the report, without printing anything.
///
/// Split out of [`run`] so the MCP server can produce exactly the export a user would
/// get from the command line — the same output-root rule, the same history record, the
/// same report — rather than assembling a second one beside it. `quiet` suppresses the
/// per-file log; step transitions still go to stderr, because a long-running job that
/// says nothing at all is indistinguishable from a hung one.
pub(crate) fn build(
    context: &ProjectContext,
    out: Option<&std::path::Path>,
    quiet: bool,
) -> Result<ExportReport> {
    build_with_cancel(context, out, quiet, &CancellationToken::new())
}

/// [`build`] with a token the caller can trip.
///
/// The pipeline already checks cancellation inside each step's loops; this is the wire
/// that lets something outside this process reach it — today, an MCP client sending
/// `notifications/cancelled` while an export is running.
pub(crate) fn build_with_cancel(
    context: &ProjectContext,
    out: Option<&std::path::Path>,
    quiet: bool,
    cancel: &CancellationToken,
) -> Result<ExportReport> {
    let output_root = resolve_output_root(out, &context.root)?;

    let mut conn = commands::open_history_db()?;
    let (progress, events) = codepack_core::progress_channel();

    // Progress goes to stderr so `--json` stdout stays a single parseable document —
    // and, for the MCP server, so the JSON-RPC stream stays parseable at all. The
    // receiver runs on its own thread because the export fills the channel as it goes;
    // draining afterwards would buffer the whole run in memory and show the user
    // nothing until it finished.
    let printer = std::thread::spawn(move || {
        for event in events {
            if let ProgressEvent::Log(log) = event {
                if !quiet {
                    output::note(format!("  {}", log.message));
                }
            } else if let ProgressEvent::StepStarted { step } = event {
                output::note(format!("→ {step}"));
            }
        }
    });

    let outcome = codepack_engine::run_export(
        &mut conn,
        &context.root,
        &output_root,
        &context.config,
        &HashMap::new(),
        &progress,
        cancel,
    );

    // Dropping the sender ends the printer's loop; do it before unwrapping the result
    // so a failed export still joins the thread instead of leaking it.
    drop(progress);
    let _ = printer.join();

    let outcome = outcome?;
    let critical_findings = outcome
        .analytics
        .as_ref()
        .map(|analytics| {
            analytics
                .scan_result
                .findings
                .iter()
                .filter(|finding| finding.severity == "critical")
                .count()
        })
        .unwrap_or(0);

    let report = ExportReport {
        project: context.root.display().to_string(),
        profile: context.config.normalized_export_profile().to_string(),
        safe_mode: context.config.normalized_safe_export_mode().to_string(),
        diff_mode: context.config.normalized_diff_export_mode().to_string(),
        successful: outcome.successful,
        cancelled: outcome.cancelled,
        files_copied: outcome.copy_stats.files_copied,
        files_skipped: outcome.copy_stats.files_skipped,
        errors: outcome.copy_stats.errors,
        result_path: outcome
            .archive_result
            .primary_result()
            .map(|path| path.display().to_string()),
        archives: outcome
            .archive_result
            .archives
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        staging_dir: outcome.paths.staging_dir.display().to_string(),
        critical_findings,
        run_id: outcome.run_id,
        resolution: context.resolution_for_output(),
    };

    Ok(report)
}

/// Decides where the bundle is written, and refuses to put it inside the project.
///
/// **Invariant I2: the export never writes into the source project folder.** The first
/// version of this defaulted `--out` to the current directory, which for the documented
/// invocation — `cd myproject && codepack export` — is the project itself. Two runs then
/// leave two archives in the tree, and the second one has to skip the first one's output
/// as if it were source. The default is therefore the project's *parent*: predictable,
/// outside the project, and matching the "export this project" mental model. Legacy used
/// the Desktop for the same reason; a shell tool has no Desktop, and often no user.
///
/// An explicit `--out` pointing inside the project is a hard error rather than a
/// warning. I2 is absolute, and a warning in CI is a line nobody reads.
fn resolve_output_root(
    requested: Option<&std::path::Path>,
    source_root: &std::path::Path,
) -> Result<PathBuf> {
    let path = match requested {
        Some(path) => path.to_path_buf(),
        None => source_root.parent().map(Path::to_path_buf).ok_or_else(|| {
            CliError::message(format!(
                "{} has no parent directory to write the bundle into; pass --out",
                source_root.display()
            ))
        })?,
    };

    // Checked *before* `create_dir_all`, not after. A refusal that has already created
    // the directory leaves a stray folder inside the project — I2 broken by the check
    // that exists to hold it, and rubbish in `git status` besides.
    //
    // The engine refuses this too (`EngineError::OutputInsideSource`); this stays because
    // it is reached before any directory is made and can say more about the fix.
    let resolved = match codepack_core::validate_destination_outside(source_root, &path) {
        Ok((_, resolved)) => resolved,
        Err(codepack_core::DestinationError::Inside { destination, .. }) => {
            return Err(CliError::message(format!(
                concat!(
                    "refusing to write the bundle into {}: it is inside the project being ",
                    "exported, and the export never writes into the source folder. ",
                    "Choose a directory outside it."
                ),
                destination.display()
            )));
        }
        Err(codepack_core::DestinationError::Resolve { path, source }) => {
            return Err(CliError::Read { path, source });
        }
    };

    std::fs::create_dir_all(&resolved).map_err(|source| CliError::Read {
        path: resolved.clone(),
        source,
    })?;
    Ok(resolved)
}

fn print_human(report: &ExportReport) {
    output::line("");
    if report.successful {
        output::line("Export complete.");
    } else if report.cancelled {
        output::line("Export cancelled — the bundle describes an incomplete run.");
    } else {
        output::line("Export finished with errors — the bundle is incomplete.");
    }

    output::line(format!(
        "  {} file(s) copied, {} skipped, {} error(s)",
        report.files_copied, report.files_skipped, report.errors
    ));
    match &report.result_path {
        Some(path) => output::line(format!("  Result: {path}")),
        None => output::line(format!("  Bundle: {}", report.staging_dir)),
    }
    if report.archives.len() > 1 {
        output::line(format!("  Split into {} parts", report.archives.len()));
    }
    if report.critical_findings > 0 {
        output::line(format!(
            "  {} critical finding(s) — see reports/insights/06_security_scan.txt",
            report.critical_findings
        ));
    }
}
