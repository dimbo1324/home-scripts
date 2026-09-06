//! `build_final_archives`: the full write control flow (BLUEPRINT §A.8, legacy
//! `archive_service.py::build_final_archives`).
//!
//! Legacy fires two hooks around archiving: a hardcoded `write_html_dashboard` call
//! and a generic `pre_archive_hook` callback. This crate collapses both into a single
//! caller-supplied `on_plan_ready` callback (S8/S9 design decision, `task-checklist.md`)
//! — the manifest/dashboard refresh itself is `codepack-engine`'s job, not this
//! crate's, since it needs `codepack-reports`, which this crate must never depend on.

use std::path::Path;

use codepack_core::{ArchiveBuildResult, CancellationToken, ExportPaths};
use serde::Serialize;

use crate::entry::{ArchiveEntry, collect_entries};
use crate::error::{ArchiveError, Result};
use crate::format::ArchiveFormat;
use crate::options::ArchiveOptions;
use crate::plan::{
    ArchivePlan, plan_archive, plan_logical_parts, predicted_result_for_plan, sort_entries,
};
use codepack_core::time::now_human_utc;
use codepack_tokens::format_bytes;

fn file_size_or_zero(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

/// Writes one archive (the whole bundle, or one part of a split set) in the requested
/// container.
///
/// Split into a dispatcher plus a per-format writer rather than one function with a
/// `match` inside its loop: the two containers have genuinely different writer APIs, and
/// interleaving them would make the ZIP path — the default, and the one under the
/// frozen split-set contract — harder to read than it was before formats existed.
fn write_archive(
    archive_path: &Path,
    entries: &[ArchiveEntry],
    format: ArchiveFormat,
    cancel: &CancellationToken,
) -> Result<u32> {
    format.ensure_implemented()?;
    if let Some(parent) = archive_path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| ArchiveError::Write {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    match format {
        ArchiveFormat::SevenZip => write_seven_zip(archive_path, entries, cancel),
        // `Rar` is rejected by `ensure_implemented` above; ZIP is both the default and
        // the fallback so a future variant cannot silently produce nothing.
        _ => write_zip(archive_path, entries, cancel),
    }
}

fn write_seven_zip(
    archive_path: &Path,
    entries: &[ArchiveEntry],
    cancel: &CancellationToken,
) -> Result<u32> {
    let mut writer = sevenz_rust2::ArchiveWriter::create(archive_path).map_err(|source| {
        ArchiveError::SevenZip {
            path: archive_path.to_path_buf(),
            source,
        }
    })?;

    let mut count = 0u32;
    for entry in entries {
        if cancel.is_cancelled() {
            break;
        }
        let arcname = entry.arcname.to_string_lossy().replace('\\', "/");
        let file = std::fs::File::open(&entry.path).map_err(|source| ArchiveError::Read {
            path: entry.path.clone(),
            source,
        })?;
        writer
            .push_archive_entry(
                sevenz_rust2::ArchiveEntry::from_path(&entry.path, arcname),
                Some(std::io::BufReader::new(file)),
            )
            .map_err(|source| ArchiveError::SevenZip {
                path: entry.path.clone(),
                source,
            })?;
        count += 1;
    }
    writer.finish().map_err(|source| ArchiveError::Write {
        path: archive_path.to_path_buf(),
        source,
    })?;
    Ok(count)
}

fn write_zip(
    archive_path: &Path,
    entries: &[ArchiveEntry],
    cancel: &CancellationToken,
) -> Result<u32> {
    let file = std::fs::File::create(archive_path).map_err(|source| ArchiveError::Write {
        path: archive_path.to_path_buf(),
        source,
    })?;
    // Buffered: without this every member becomes a stream of small writes straight to
    // the filesystem, and a bundle is thousands of members.
    let mut writer = zip::ZipWriter::new(std::io::BufWriter::with_capacity(1 << 20, file));
    // Level 6 balances speed vs. size reduction (BLUEPRINT §A.8, legacy comment
    // verbatim: `compresslevel=6`).
    //
    // `large_file(true)` writes ZIP64 headers. Off by default in `zip` 8.x, which means a
    // member past 4 GiB fails at write time — at the very end of an export, after every
    // other step has already run (audit No. 30). A checked-in dataset or a database dump
    // reaches that size, and the cost of the flag is a few extra bytes per member.
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .compression_level(Some(6))
        .large_file(true);

    let mut count = 0u32;
    for entry in entries {
        if cancel.is_cancelled() {
            break;
        }
        let arcname = entry.arcname.to_string_lossy().replace('\\', "/");
        writer
            .start_file(arcname, options)
            .map_err(|source| ArchiveError::Zip {
                path: entry.path.clone(),
                source,
            })?;
        let mut source_file =
            std::fs::File::open(&entry.path).map_err(|source| ArchiveError::Read {
                path: entry.path.clone(),
                source,
            })?;
        std::io::copy(&mut source_file, &mut writer).map_err(|source| ArchiveError::Write {
            path: entry.path.clone(),
            source,
        })?;
        count += 1;
    }
    // Flushed explicitly rather than on drop: the writer is buffered now, and a flush
    // that fails while being dropped has nowhere to report itself — a truncated archive
    // would look like a complete one.
    let mut buffered = writer.finish().map_err(|source| ArchiveError::Zip {
        path: archive_path.to_path_buf(),
        source,
    })?;
    std::io::Write::flush(&mut buffered).map_err(|source| ArchiveError::Write {
        path: archive_path.to_path_buf(),
        source,
    })?;
    Ok(count)
}

fn part_archive_name(
    paths: &ExportPaths,
    index: u32,
    group_hint: &str,
    format: ArchiveFormat,
) -> String {
    format!(
        "{}_part_{:03}_{}.{}",
        paths.bundle_name,
        index,
        group_hint,
        format.extension()
    )
}

#[derive(Serialize, Clone)]
struct PartManifestEntry {
    archive: String,
    groups: Vec<String>,
    files: u32,
    estimated_input_size: u64,
    estimated_input_size_human: String,
    compressed_size: u64,
    compressed_size_human: String,
}

#[derive(Serialize)]
struct ArchiveSetManifest {
    generated_at: String,
    bundle_name: String,
    split: bool,
    limit_bytes: u64,
    limit_human: String,
    archives: Vec<String>,
    parts: Vec<PartManifestEntry>,
    oversized_files: Vec<String>,
    restore_note: String,
}

fn write_restore_files(
    paths: &ExportPaths,
    result: &ArchiveBuildResult,
    parts: &[PartManifestEntry],
    limit_bytes: u64,
    format: ArchiveFormat,
) -> Result<()> {
    let Some(output_dir) = &result.output_dir else {
        return Ok(());
    };
    std::fs::create_dir_all(output_dir).map_err(|source| ArchiveError::Write {
        path: output_dir.clone(),
        source,
    })?;

    let manifest = ArchiveSetManifest {
        generated_at: now_human_utc(),
        bundle_name: paths.bundle_name.clone(),
        split: result.split,
        limit_bytes,
        limit_human: format_bytes(limit_bytes),
        archives: result
            .archives
            .iter()
            .filter_map(|path| {
                path.file_name()
                    .map(|name| name.to_string_lossy().into_owned())
            })
            .collect(),
        parts: parts.to_vec(),
        oversized_files: result.oversized_files.clone(),
        restore_note: format!(
            "Extract all {} files into the same destination folder. Every archive preserves original paths.",
            format.extension().to_uppercase()
        ),
    };

    let manifest_path = output_dir.join("ARCHIVE_SET_MANIFEST.json");
    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    std::fs::write(&manifest_path, manifest_json).map_err(|source| ArchiveError::Write {
        path: manifest_path.clone(),
        source,
    })?;

    let instructions = "# Restore Instructions\n\n\
1. Create an empty destination folder.\n\
2. Extract every ZIP file from this archive set into that same folder.\n\
3. Keep the relative paths exactly as stored in the archives.\n\n\
The file `ARCHIVE_SET_MANIFEST.json` lists all archive parts and any oversized entries.\n";
    let instructions_path = output_dir.join("RESTORE_INSTRUCTIONS.md");
    std::fs::write(&instructions_path, instructions).map_err(|source| ArchiveError::Write {
        path: instructions_path,
        source,
    })
}

/// Builds the final archive output(s) from an already-staged tree.
///
/// Control flow (mirrors legacy's `build_final_archives`, with its two hooks
/// collapsed into one — see the module doc comment):
///
/// 1. `plan_archive` (first pass).
/// 2. Write `27_archive_plan.md`/`.json`.
/// 3. `plan_archive` again (second pass — picks up the just-written report file).
/// 4. Call `on_plan_ready` once with this plan and its predicted result.
/// 5. `plan_archive` again (third pass — picks up whatever `on_plan_ready` itself wrote).
/// 6. If the plan is a single ZIP: write it, then check its *actual* on-disk size
///    against the hard limit. If it fits, done. If not, discard it, re-walk the
///    staging tree (picking up anything the caller's `on_plan_ready` itself wrote —
///    matches legacy, which re-walks after its second hook call too; an earlier
///    version of this function reused the stale pre-hook entries here, silently
///    dropping any content the second hook call added from the split archive),
///    force split mode, and call `on_plan_ready` a second time with the new plan.
/// 7. Write each split part, tracking any part whose actual written size still
///    exceeds the hard limit into `oversized_files` (no recursive re-split — matches
///    legacy).
/// 8. Write `ARCHIVE_SET_MANIFEST.json`/`RESTORE_INSTRUCTIONS.md`.
pub fn build_final_archives(
    paths: &ExportPaths,
    options: &ArchiveOptions,
    cancel: &CancellationToken,
    on_plan_ready: &mut dyn FnMut(&ArchivePlan, &ArchiveBuildResult),
) -> Result<ArchiveBuildResult> {
    let mut plan = plan_archive(
        paths,
        options.include_project,
        options.part_limit_bytes,
        cancel,
    )?;
    crate::report::write_archive_plan_report(
        &plan,
        &paths.insights_dir.join("27_archive_plan.md"),
    )?;
    plan = plan_archive(
        paths,
        options.include_project,
        options.part_limit_bytes,
        cancel,
    )?;

    if !cancel.is_cancelled() {
        let predicted = predicted_result_for_plan(paths, &plan);
        on_plan_ready(&plan, &predicted);
        plan = plan_archive(
            paths,
            options.include_project,
            options.part_limit_bytes,
            cancel,
        )?;
    }

    if !plan.split {
        let count = write_archive(
            &paths.final_zip,
            &plan.parts[0].entries,
            options.format,
            cancel,
        )?;
        if cancel.is_cancelled() {
            let archives = if paths.final_zip.exists() {
                vec![paths.final_zip.clone()]
            } else {
                Vec::new()
            };
            return Ok(ArchiveBuildResult {
                archives,
                output_dir: None,
                split: false,
                file_count: count,
                skipped_project_files: plan.skipped_project_files,
                oversized_files: Vec::new(),
            });
        }

        let compressed_size = file_size_or_zero(&paths.final_zip);
        if compressed_size <= plan.limit_bytes {
            return Ok(ArchiveBuildResult {
                archives: vec![paths.final_zip.clone()],
                output_dir: None,
                split: false,
                file_count: count,
                skipped_project_files: plan.skipped_project_files,
                oversized_files: Vec::new(),
            });
        }

        // Oversized after write: discard the single ZIP (best-effort delete, matching
        // legacy's `missing_ok=True`) and rebuild as a split set. Re-walk before
        // committing to split mode, matching legacy's own re-walk after its second
        // hook call — the caller's `on_plan_ready` (invoked just above, via the
        // *first* on_plan_ready call at line ~198) may have already written new or
        // updated content that must land in the split set.
        let _ = std::fs::remove_file(&paths.final_zip);
        let (mut entries, skipped_project_files) =
            collect_entries(paths, options.include_project, cancel)?;
        sort_entries(&mut entries);
        plan.entries = entries;
        plan.skipped_project_files = skipped_project_files;
        plan.split = true;
        plan.parts = plan_logical_parts(&plan.entries, plan.target_bytes);

        if !cancel.is_cancelled() {
            let predicted = predicted_result_for_plan(paths, &plan);
            on_plan_ready(&plan, &predicted);

            // Legacy re-walks a second time here too, to pick up whatever this
            // *second* on_plan_ready call itself wrote before the split parts are
            // physically built — otherwise content written only in response to
            // "we're now definitely splitting" would be silently missing from the
            // archive.
            let (mut entries, skipped_project_files) =
                collect_entries(paths, options.include_project, cancel)?;
            sort_entries(&mut entries);
            plan.entries = entries;
            plan.skipped_project_files = skipped_project_files;
            plan.parts = plan_logical_parts(&plan.entries, plan.target_bytes);
        }
    }

    std::fs::create_dir_all(&paths.archive_set_dir).map_err(|source| ArchiveError::Write {
        path: paths.archive_set_dir.clone(),
        source,
    })?;

    let mut result = ArchiveBuildResult {
        archives: Vec::new(),
        output_dir: Some(paths.archive_set_dir.clone()),
        split: true,
        file_count: 0,
        skipped_project_files: plan.skipped_project_files,
        oversized_files: Vec::new(),
    };
    let mut part_manifest: Vec<PartManifestEntry> = Vec::new();

    for part in &plan.parts {
        if cancel.is_cancelled() {
            break;
        }
        let archive_name = part_archive_name(paths, part.index, &part.group_hint, options.format);
        let archive_path = paths.archive_set_dir.join(&archive_name);
        let count = write_archive(&archive_path, &part.entries, options.format, cancel)?;
        result.archives.push(archive_path.clone());
        result.file_count += count;

        let compressed_size = file_size_or_zero(&archive_path);
        if compressed_size > plan.limit_bytes {
            let mut oversized: Vec<String> = part
                .entries
                .iter()
                .filter(|entry| entry.size >= plan.target_bytes)
                .map(|entry| entry.arcname.to_string_lossy().replace('\\', "/"))
                .collect();
            if oversized.is_empty() {
                oversized.push(archive_name.clone());
            }
            result.oversized_files.extend(oversized);
        }

        part_manifest.push(PartManifestEntry {
            archive: archive_name,
            groups: part.groups().into_iter().map(str::to_string).collect(),
            files: count,
            estimated_input_size: part.estimated_bytes(),
            estimated_input_size_human: format_bytes(part.estimated_bytes()),
            compressed_size,
            compressed_size_human: format_bytes(compressed_size),
        });
    }

    write_restore_files(
        paths,
        &result,
        &part_manifest,
        plan.limit_bytes,
        options.format,
    )?;
    Ok(result)
}
