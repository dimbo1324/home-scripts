//! [`run_sterile_copy`]: the standalone pipeline, per file —
//!
//! scanner plan (safe file selection) → safety-skip predicate → read content → redact
//! secrets (invariant I3, before anything is written) → strip comments via tree-sitter →
//! format via a `PATH` tool if one is found → write to `destination_root`, mirroring the
//! relative path from `source_root`.
//!
//! This never goes through `codepack-engine`'s 8-step pipeline (it is not one of its
//! steps, does not touch the ZIP/archive contract, and produces none of the existing
//! ~30 report artifacts) — see `docs/__arch__/open-questions.md`, 2026-07-28.

use std::path::{Path, PathBuf};

use rayon::prelude::*;

use codepack_core::CancellationToken;
use codepack_scanner::{
    ExportIgnoreRules, ScanOptions, build_export_plan, looks_binary, should_consider_text_file,
};
use codepack_security::{redact_secrets, should_skip_file_for_safety};

use crate::error::{Result, SanitizeError};
use crate::format::format_source;
use crate::language::detect_language;
use crate::options::{
    FileOutcome, SterileCopyArchive, SterileCopyOptions, SterileCopyReport, SterileCopySummary,
};
use crate::report::{REPORT_JSON_NAME, REPORT_MARKDOWN_NAME, write_report};
use crate::strip::strip_comments;

/// Runs one sterile-copy pass and writes `STERILE_COPY_REPORT.json`/`.md` into the
/// destination folder alongside the copied files.
pub fn run_sterile_copy(options: &SterileCopyOptions) -> Result<SterileCopyReport> {
    let (canonical_source, canonical_destination) =
        validate_destination(&options.source_root, &options.destination_root)?;
    if let Some(archive_path) = &options.archive_path {
        validate_archive_path(&canonical_source, archive_path)?;
    }

    let scan_options = ScanOptions {
        safe_export_mode: options.safety_mode.clone(),
        ..ScanOptions::default()
    };
    let export_rules = ExportIgnoreRules::from_project_and_config(&canonical_source, &scan_options);
    let safety_mode = options.safety_mode.clone();
    let safety = move |relative_path: &Path| -> Option<(String, String)> {
        let decision = should_skip_file_for_safety(relative_path, &safety_mode);
        decision
            .skip
            .then_some((decision.reason, decision.severity))
    };

    let plan = build_export_plan(
        &canonical_source,
        &scan_options,
        &export_rules,
        &safety,
        &options.cancellation,
    )
    .map_err(|error| match error {
        codepack_scanner::ScannerError::Cancelled => SanitizeError::Cancelled,
        other => SanitizeError::Scanner(other),
    })?;

    let mut per_file: Vec<(PathBuf, FileOutcome)> = plan
        .sensitive_warnings()
        .iter()
        .map(|planned| {
            (
                to_relative_path(&planned.relative_path),
                FileOutcome::SkippedSensitiveOrRedacted,
            )
        })
        .collect();

    let cancel = options.cancellation.clone();
    let source_for_workers = canonical_source.clone();
    let destination_for_workers = canonical_destination.clone();
    let processed: Vec<(PathBuf, FileOutcome)> = plan
        .included_files
        .par_iter()
        .map(|planned| {
            let relative = to_relative_path(&planned.relative_path);
            let outcome = process_file(
                &source_for_workers,
                &destination_for_workers,
                &relative,
                &cancel,
            );
            (relative, outcome)
        })
        .collect();
    per_file.extend(processed);

    let summary = SterileCopySummary::from_outcomes(per_file.iter().map(|(_, outcome)| outcome));
    let mut report = SterileCopyReport {
        per_file,
        summary,
        archive: None,
    };

    write_report(
        &canonical_destination,
        &options.source_root,
        &options.safety_mode,
        &report,
    )?;

    // Packed last, after the report exists, so the archive contains it: the recipient
    // of a `.7z` gets the account of what was stripped, skipped and redacted in the
    // same file as the code it describes.
    //
    // The member list is built from this run's own outcomes, never by walking the
    // destination folder. A user is free to point `--out` at a directory that already
    // holds something, and walking would sweep those files — which passed neither
    // redaction nor the safety filter, and appear in no report — into an archive whose
    // whole promise is that everything inside was screened (invariant I3).
    if let Some(archive_path) = &options.archive_path {
        let members = archive_members(&report);
        let format = resolve_archive_format(options, archive_path);
        let packed = codepack_archive::pack_files(
            &canonical_destination,
            &members,
            archive_path,
            format,
            &options.cancellation,
        )
        .map_err(|source| match source {
            codepack_archive::ArchiveError::Cancelled => SanitizeError::Cancelled,
            source => SanitizeError::Archive {
                path: archive_path.clone(),
                source: Box::new(source),
            },
        })?;
        report.archive = Some(SterileCopyArchive {
            path: packed.archive_path,
            format: packed.format,
            file_count: packed.file_count,
            bytes: packed.archive_bytes,
        });
    }

    Ok(report)
}

/// An explicit choice wins; otherwise the file name decides; otherwise ZIP.
///
/// Naming a file `out.7z` and getting a ZIP would be a small lie the user only
/// discovers on opening it, so the extension is honoured — but it is a *guess*, and an
/// explicit `archive_format` overrides it rather than the other way round.
fn resolve_archive_format(
    options: &SterileCopyOptions,
    archive_path: &Path,
) -> codepack_archive::ArchiveFormat {
    options
        .archive_format
        .or_else(|| codepack_archive::ArchiveFormat::from_path(archive_path))
        .unwrap_or_default()
}

/// Exactly the files this run wrote into the destination: every file that produced
/// content, plus the two report artifacts that describe them.
///
/// [`FileOutcome::SkippedSensitiveOrRedacted`] is the one outcome with no file behind
/// it — that is what "skipped" means — so listing it would ask the archiver for a path
/// that does not exist.
fn archive_members(report: &SterileCopyReport) -> Vec<PathBuf> {
    let mut members: Vec<PathBuf> = report
        .per_file
        .iter()
        .filter(|(_, outcome)| !matches!(outcome, FileOutcome::SkippedSensitiveOrRedacted))
        .map(|(path, _)| path.clone())
        .collect();
    members.push(PathBuf::from(REPORT_JSON_NAME));
    members.push(PathBuf::from(REPORT_MARKDOWN_NAME));
    members.sort();
    members
}

/// The archive is a second thing written outside the source project, and it needs the
/// same guard the destination folder gets: writing it inside the project being read
/// from would modify that project (invariant I2), and a second run would then try to
/// pack the previous archive into the new one.
fn validate_archive_path(canonical_source: &Path, archive_path: &Path) -> Result<()> {
    let prospective =
        codepack_core::resolve_prospective(archive_path).map_err(|error| match error {
            codepack_core::DestinationError::Resolve { path, source } => {
                SanitizeError::Read { path, source }
            }
            // `resolve_prospective` only ever reports a resolution failure; the overlap
            // variant belongs to `validate_destination_outside`.
            other => SanitizeError::Read {
                path: archive_path.to_path_buf(),
                source: std::io::Error::other(other.to_string()),
            },
        })?;
    if prospective.starts_with(canonical_source) {
        return Err(SanitizeError::ArchiveInsideSource {
            source_root: canonical_source.to_path_buf(),
            archive: prospective,
        });
    }
    Ok(())
}

/// Invariant analogous to I2: a sterile copy must never be written into, or as an
/// ancestor of, the project it reads from. The overlap check runs against a
/// *prospective* resolution of `destination_root` before anything is created on disk —
/// `create_dir_all` must never run first, or a rejected call could still leave a stray
/// directory inside the source tree it was never allowed to touch.
fn validate_destination(source_root: &Path, destination_root: &Path) -> Result<(PathBuf, PathBuf)> {
    if !source_root.is_dir() {
        return Err(SanitizeError::SourceNotADirectory {
            path: source_root.to_path_buf(),
        });
    }

    let canonical_source =
        match codepack_core::validate_destination_outside(source_root, destination_root) {
            Ok((canonical_source, _)) => canonical_source,
            Err(codepack_core::DestinationError::Inside {
                source_root,
                destination,
            }) => {
                return Err(SanitizeError::DestinationInsideSource {
                    source_root,
                    destination,
                });
            }
            Err(codepack_core::DestinationError::Resolve { path, source }) => {
                return Err(SanitizeError::Read { path, source });
            }
        };

    std::fs::create_dir_all(destination_root).map_err(|source| SanitizeError::Write {
        path: destination_root.to_path_buf(),
        source,
    })?;
    let canonical_destination = canonicalize(destination_root)?;
    Ok((canonical_source, canonical_destination))
}

fn canonicalize(path: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(path).map_err(|source| SanitizeError::Read {
        path: path.to_path_buf(),
        source,
    })
}

/// The plan stores backslash-joined relative paths regardless of platform (a documented
/// contract of `codepack_scanner::ExportPlan`). One definition of the rebuild, shared with
/// the engine and the CLI: [`codepack_core::relative_from_stored`], which validates the
/// components as well (audit No. 23).
///
/// An unsafe path resolves to the empty path, which `process_file` then joins onto the
/// source root — so it names the root, is not a file, and is reported as an error for that
/// entry rather than being written anywhere it should not be.
fn to_relative_path(relative: &str) -> PathBuf {
    codepack_core::relative_from_stored(relative).unwrap_or_default()
}

fn process_file(
    source_root: &Path,
    destination_root: &Path,
    relative: &Path,
    cancel: &CancellationToken,
) -> FileOutcome {
    if cancel.is_cancelled() {
        return FileOutcome::Error {
            message: "cancelled".to_string(),
        };
    }

    let source_path = source_root.join(relative);
    let raw = match std::fs::read(&source_path) {
        Ok(bytes) => bytes,
        Err(source) => {
            return FileOutcome::Error {
                message: format!("failed to read {}: {source}", source_path.display()),
            };
        }
    };

    if !should_consider_text_file(relative) || looks_binary(&raw) {
        return finish(
            destination_root,
            relative,
            &raw,
            FileOutcome::SkippedUnsupportedLanguage {
                reason: "binary file (not text)".to_string(),
            },
        );
    }

    let text = match String::from_utf8(raw) {
        Ok(text) => text,
        Err(error) => {
            return finish(
                destination_root,
                relative,
                &error.into_bytes(),
                FileOutcome::Error {
                    message: "file content is not valid UTF-8; copied through unmodified"
                        .to_string(),
                },
            );
        }
    };

    // Invariant I3: a secret must never reach an artifact unredacted — applied before
    // any stripping/formatting, and on every path out of this function from here on,
    // including the unsupported-language and parse-error fallbacks below.
    let redacted = redact_secrets(&text);

    let Some(language) = detect_language(relative) else {
        return finish(
            destination_root,
            relative,
            redacted.as_bytes(),
            FileOutcome::SkippedUnsupportedLanguage {
                reason: "not one of the Batch 1 languages (docs/__arch__/open-questions.md, Q24)"
                    .to_string(),
            },
        );
    };

    let Some(stripped) = strip_comments(language, &redacted) else {
        return finish(
            destination_root,
            relative,
            redacted.as_bytes(),
            FileOutcome::Error {
                message: "tree-sitter could not fully parse this file (syntax error); comments \
                          were not stripped to avoid corrupting the code"
                    .to_string(),
            },
        );
    };

    let file_name = relative
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_default();

    match format_source(language, &file_name, &stripped) {
        Some((formatted, formatter)) => finish(
            destination_root,
            relative,
            formatted.as_bytes(),
            FileOutcome::StrippedAndFormatted {
                language: language.label().to_string(),
                formatter,
            },
        ),
        None => finish(
            destination_root,
            relative,
            stripped.as_bytes(),
            FileOutcome::StrippedOnlyNoFormatterFound {
                language: language.label().to_string(),
            },
        ),
    }
}

fn finish(
    destination_root: &Path,
    relative: &Path,
    bytes: &[u8],
    outcome: FileOutcome,
) -> FileOutcome {
    let destination_path = destination_root.join(relative);
    if let Some(parent) = destination_path.parent()
        && let Err(source) = std::fs::create_dir_all(parent)
    {
        return FileOutcome::Error {
            message: format!("failed to create {}: {source}", parent.display()),
        };
    }
    match std::fs::write(&destination_path, bytes) {
        Ok(()) => outcome,
        Err(source) => FileOutcome::Error {
            message: format!("failed to write {}: {source}", destination_path.display()),
        },
    }
}

#[cfg(test)]
mod tests;
