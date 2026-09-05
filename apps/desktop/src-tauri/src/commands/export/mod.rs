//! Running an export, and cancelling one.
//!
//! ## Why this is not a blocking command
//!
//! An export on a real project takes seconds to minutes. A `#[tauri::command]` that ran
//! it inline would hold the IPC call open for that whole time, and the window would have
//! no way to show progress or offer a cancel button — the two things this stage exists
//! to provide. So [`start_export`] returns a run id immediately and the work happens on
//! a background thread, reporting through `export:progress` and `export:finished`
//! events.
//!
//! The run id is minted before the thread starts, so the UI can cancel an export that
//! has not reached its first step yet.

use std::collections::HashMap;

use codepack_core::config::Config;
use codepack_core::{ProgressEvent, progress_channel};
use tauri::{AppHandle, Emitter, State};

use crate::dto::{ExportFinishedEvent, ExportProgressEvent, ExportReport};
use crate::error::{CommandError, CommandResult};
use crate::state::AppState;

use super::{open_database, resolve_project_root};

#[cfg(test)]
mod tests;

/// Event names, in one place so the frontend's `client.ts` has exactly one thing to
/// match against.
pub const PROGRESS_EVENT: &str = "export:progress";
pub const FINISHED_EVENT: &str = "export:finished";

/// Starts an export and returns its run id.
///
/// `out_dir` is where the bundle is written. It is a parameter rather than a fixed
/// location because legacy always wrote to the Desktop, which is the wrong default for
/// a tool people run on work machines; the UI asks, and the answer travels here.
#[tauri::command]
pub fn start_export(
    app: AppHandle,
    state: State<'_, AppState>,
    project_root: String,
    out_dir: String,
    config: Config,
    file_overrides: HashMap<String, bool>,
) -> CommandResult<String> {
    let root = resolve_project_root(&project_root)?;
    let output_root = resolve_project_root(&out_dir)?;

    let (run_id, cancel) = state.runs.start();
    let runs = state.runs.clone();
    let thread_run_id = run_id.clone();

    // The progress channel is drained on its own thread rather than in the export
    // thread: `run_export` sends into it synchronously, and a full unbounded channel
    // never blocks, but forwarding to the webview from inside the export loop would
    // interleave IPC latency with pipeline work.
    let (sender, receiver) = progress_channel();
    let forward_app = app.clone();
    let forward_run_id = run_id.clone();
    std::thread::spawn(move || {
        for event in receiver {
            let payload = match event {
                ProgressEvent::Log(log) => ExportProgressEvent {
                    run_id: forward_run_id.clone(),
                    message: Some(log.message),
                    step: None,
                    step_finished: false,
                },
                ProgressEvent::StepStarted { step } => ExportProgressEvent {
                    run_id: forward_run_id.clone(),
                    message: None,
                    step: Some(step),
                    step_finished: false,
                },
                ProgressEvent::StepFinished { step } => ExportProgressEvent {
                    run_id: forward_run_id.clone(),
                    message: None,
                    step: Some(step),
                    step_finished: true,
                },
                ProgressEvent::StepProgress {
                    step,
                    current,
                    total,
                } => ExportProgressEvent {
                    run_id: forward_run_id.clone(),
                    message: Some(match total {
                        Some(total) => format!("{step}: {current}/{total}"),
                        None => format!("{step}: {current}"),
                    }),
                    step: None,
                    step_finished: false,
                },
            };
            // A closed window means nobody is listening; the export still finishes and
            // still records its history row, which is what a user who closed the window
            // mid-run would expect to find next time.
            let _ = forward_app.emit(PROGRESS_EVENT, payload);
        }
    });

    std::thread::spawn(move || {
        let outcome = open_database().and_then(|mut connection| {
            run_to_completion(
                &mut connection,
                &root,
                &output_root,
                &config,
                &file_overrides,
                &sender,
                &cancel,
            )
        });
        // Dropping the sender ends the forwarding thread's loop.
        drop(sender);

        let finished = match outcome {
            Ok(report) => ExportFinishedEvent {
                run_id: thread_run_id.clone(),
                report: Some(report),
                error: None,
            },
            Err(error) => ExportFinishedEvent {
                run_id: thread_run_id.clone(),
                report: None,
                error: Some(error.message),
            },
        };

        // Deregistered before the event is emitted, so a cancel arriving in response to
        // the finish notification cannot reach a token nobody owns any more.
        runs.finish(&thread_run_id);
        let _ = app.emit(FINISHED_EVENT, finished);
    });

    Ok(run_id)
}

/// The export itself, on the background thread.
///
/// Takes the database connection as a parameter rather than opening it: that is what
/// lets the tests drive a whole export against a temporary database instead of the
/// user's real history file, and an export is far too consequential to have its only
/// coverage be a mocked one.
///
/// `pub` rather than `pub(crate)` so the integration tests in `tests/` can reach it —
/// that is the whole reason this crate has a `[lib]` target alongside its binary.
pub fn run_to_completion(
    connection: &mut codepack_storage::Connection,
    root: &std::path::Path,
    output_root: &std::path::Path,
    config: &Config,
    file_overrides: &HashMap<String, bool>,
    sender: &codepack_core::ProgressSender,
    cancel: &codepack_core::CancellationToken,
) -> CommandResult<ExportReport> {
    let outcome = codepack_engine::run_export(
        connection,
        root,
        output_root,
        config,
        file_overrides,
        sender,
        cancel,
    )?;

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

    Ok(ExportReport {
        run_id: outcome.run_id,
        project: root.display().to_string(),
        profile: config.normalized_export_profile().to_string(),
        safe_mode: config.normalized_safe_export_mode().to_string(),
        diff_mode: config.normalized_diff_export_mode().to_string(),
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
    })
}

/// Asks a running export to stop.
///
/// Returns `Ok` for an unknown id: the run may have finished between the user pressing
/// the button and this arriving, and surfacing that race as an error would be noise.
/// The pipeline's own guarantees take it from here — steps 7 and 8 still run, the
/// history row is still written, and staging is still cleaned up.
#[tauri::command]
pub fn cancel_export(state: State<'_, AppState>, run_id: String) -> CommandResult<()> {
    state.runs.cancel(&run_id);
    Ok(())
}

/// Where an export's reports actually live, once the run has finished.
///
/// The bundle is written into a **staging directory that the pipeline then deletes** —
/// the surviving artifact is the archive. So neither `PROJECT_PROFILE.json` nor
/// `REPORT_DASHBOARD.html` exists as a loose file next to the result, and reading them
/// means extracting first. (A run with `keep_staging_folder` left staging in place, but
/// relying on that would make Analytics work only for users who enabled a debugging
/// setting.)
///
/// Extraction goes to a per-bundle directory beside the archive rather than a temporary
/// one, so the dashboard's relative links to the other reports keep resolving after this
/// call returns and the user can browse them. Extracting again over an existing
/// directory is harmless and keeps the copy current.
pub(crate) fn extracted_bundle_dir(result_path: &str) -> CommandResult<std::path::PathBuf> {
    // The single gate for five of the six commands that used to take this path on trust.
    // Validated against the export history first: a path is acceptable exactly when a run
    // of this installation produced it.
    let path = super::resolve_export_result(result_path)?;
    extract_validated_bundle(&path, result_path)
}

/// The extraction itself, once the path is known to be an export this installation
/// produced.
///
/// Separated from the check so the two can be read — and tested — apart: this function
/// decides *how* a bundle is opened, and its caller decides *whether* it may be. Nothing
/// but [`extracted_bundle_dir`] should call it.
fn extract_validated_bundle(
    path: &std::path::Path,
    result_path: &str,
) -> CommandResult<std::path::PathBuf> {
    // A split export hands back the archive-set *directory*; a single-ZIP export hands
    // back the file.
    if path.is_dir() {
        if path.join("ARCHIVE_SET_MANIFEST.json").is_file() {
            let destination = extraction_dir_for(path)?;
            codepack_archive::restore_archive_set(path, &destination).map_err(CommandError::new)?;
            return Ok(destination);
        }
        // Already-extracted content, or a kept staging directory.
        return Ok(path.to_path_buf());
    }

    if !path.is_file() {
        return Err(CommandError::new(format!(
            "the export result is no longer where it was recorded: {result_path}"
        )));
    }

    let destination = extraction_dir_for(path)?;
    // `extract_zip_safely` validates every entry against path traversal before writing
    // and now also bounds what the archive may expand into.
    codepack_archive::extract_zip_safely(path, &destination).map_err(CommandError::new)?;
    Ok(destination)
}

/// Where a bundle is unpacked for reading.
///
/// Under the application's own data directory rather than beside the archive. Writing a
/// `_extracted` folder next to somebody's file is a liberty a command should not take —
/// the user never opens that folder by hand, and the archive may sit anywhere. The name
/// is a hash of the archive's path, so two bundles never collide and re-opening the same
/// one reuses its directory.
fn extraction_dir_for(archive: &std::path::Path) -> CommandResult<std::path::PathBuf> {
    use sha2::{Digest, Sha256};

    let paths = codepack_core::AppPaths::resolve().map_err(CommandError::new)?;
    let mut hasher = Sha256::new();
    hasher.update(archive.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    let mut key = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        use std::fmt::Write as _;
        let _ = write!(key, "{byte:02x}");
    }

    let destination = paths.settings_dir().join("extracted").join(key);
    std::fs::create_dir_all(&destination).map_err(|source| {
        CommandError::new(format!(
            "cannot prepare {}: {source}",
            destination.display()
        ))
    })?;
    Ok(destination)
}

/// Finds a bundle file by name, checking the layouts an export can produce.
fn find_in_bundle(bundle_dir: &std::path::Path, relative: &[&str]) -> Option<std::path::PathBuf> {
    // Reports live under `reports/insights/`; the manifest and project profile sit at the
    // bundle root. A bundle whose project directory was included nests everything one
    // level down under the project name, so the root's single subdirectory is tried too.
    let mut roots = vec![bundle_dir.to_path_buf()];
    if let Ok(entries) = std::fs::read_dir(bundle_dir) {
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                roots.push(entry.path());
            }
        }
    }

    for root in roots {
        for candidate in relative {
            let path = root.join(candidate);
            if path.is_file() {
                return Some(path);
            }
        }
    }
    None
}

/// Reads back the `PROJECT_PROFILE.json` a past export wrote, for the Analytics page.
///
/// `result_path` is whatever the run recorded — an archive, or an archive-set directory.
/// The profile is read from inside it; see [`extracted_bundle_dir`] for why extraction is
/// necessary rather than looking beside the file.
#[tauri::command]
pub fn read_project_profile(
    result_path: String,
) -> CommandResult<crate::dto::ProjectProfileSummary> {
    let bundle_dir = extract_validated_bundle(std::path::Path::new(&result_path), &result_path)?;
    let profile_file = find_in_bundle(&bundle_dir, &["PROJECT_PROFILE.json"]).ok_or_else(|| {
        CommandError::new(
            "this export contains no PROJECT_PROFILE.json; the run may have been cancelled \
             before its analytics step ran",
        )
    })?;

    let text = std::fs::read_to_string(&profile_file)?;
    let value: serde_json::Value = serde_json::from_str(&text)?;
    let counts = &value["counts"];

    Ok(crate::dto::ProjectProfileSummary {
        project_type: string_at(&value, "project_type"),
        detected_stack: string_array_at(&value, "detected_stack"),
        risk_level: string_at(&value, "risk_level"),
        risk_reasons: string_array_at(&value, "risk_reasons"),
        files: counts["files"].as_u64().unwrap_or(0) as usize,
        folders: counts["folders"].as_u64().unwrap_or(0) as usize,
        total_size_bytes: counts["total_size_bytes"].as_u64().unwrap_or(0),
    })
}

fn string_at(value: &serde_json::Value, key: &str) -> String {
    value[key].as_str().unwrap_or_default().to_string()
}

fn string_array_at(value: &serde_json::Value, key: &str) -> Vec<String> {
    value[key]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Extracts the bundle and opens one report from it with the OS's default handler.
///
/// Opened from the extracted directory, not a temporary copy, so an HTML page's
/// relative links to the other reports resolve and the user can actually browse them.
/// Shared by [`open_dashboard`] and the three S12 report-opening commands below —
/// each of those is a one-line wrapper naming its own file and its own "not generated"
/// message, rather than a fourth copy of extraction, bundle-layout lookup, and
/// OS-handler dispatch.
fn open_bundle_report(
    result_path: &str,
    candidates: &[&str],
    not_found_message: &str,
) -> CommandResult<()> {
    let bundle_dir = extract_validated_bundle(std::path::Path::new(result_path), result_path)?;
    let file = find_in_bundle(&bundle_dir, candidates)
        .ok_or_else(|| CommandError::new(not_found_message.to_string()))?;

    // Handing a path to the OS handler is the most powerful thing this shell does, so the
    // file is confined to the directory that was just validated and extracted. The lookup
    // walks subdirectories, and a symlink inside an archive would otherwise be a way out
    // of it — the containment is checked on canonicalised paths rather than assumed from
    // how the lookup happens to work today.
    let resolved = file
        .canonicalize()
        .map_err(|source| CommandError::new(format!("cannot open {}: {source}", file.display())))?;
    let root = bundle_dir.canonicalize().unwrap_or(bundle_dir);
    if !resolved.starts_with(&root) {
        return Err(CommandError::new(format!(
            "{} lies outside the extracted bundle and will not be opened",
            resolved.display()
        )));
    }

    tauri_plugin_opener::open_path(resolved.display().to_string(), None::<&str>)
        .map_err(CommandError::new)
}

/// Opens `REPORT_DASHBOARD.html`.
#[tauri::command]
pub fn open_dashboard(result_path: String) -> CommandResult<()> {
    open_bundle_report(
        &result_path,
        &[
            "reports/insights/REPORT_DASHBOARD.html",
            "REPORT_DASHBOARD.html",
        ],
        "this export contains no REPORT_DASHBOARD.html; the run may have been cancelled \
         before its reports were written",
    )
}

/// Opens `PROJECT_OVERVIEW.html` (stage S12, BLUEPRINT §B.9): the plain-language
/// overview for a reader with no code access.
#[tauri::command]
pub fn open_project_overview(result_path: String) -> CommandResult<()> {
    open_bundle_report(
        &result_path,
        &[
            "reports/insights/PROJECT_OVERVIEW.html",
            "PROJECT_OVERVIEW.html",
        ],
        "this export contains no PROJECT_OVERVIEW.html; the run may have been cancelled \
         before its reports were written",
    )
}

/// Opens `ONBOARDING_GUIDE.md` (stage S12).
#[tauri::command]
pub fn open_onboarding_guide(result_path: String) -> CommandResult<()> {
    open_bundle_report(
        &result_path,
        &[
            "reports/insights/ONBOARDING_GUIDE.md",
            "ONBOARDING_GUIDE.md",
        ],
        "this export contains no ONBOARDING_GUIDE.md; the run may have been cancelled \
         before its reports were written",
    )
}

/// Opens `REVIEW_CHECKLIST.md` (stage S12).
#[tauri::command]
pub fn open_review_checklist(result_path: String) -> CommandResult<()> {
    open_bundle_report(
        &result_path,
        &[
            "reports/insights/REVIEW_CHECKLIST.md",
            "REVIEW_CHECKLIST.md",
        ],
        "this export contains no REVIEW_CHECKLIST.md; the run may have been cancelled \
         before its reports were written",
    )
}
