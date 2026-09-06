//! Pipeline step 2 ("copy"): materializes the staged project directory from an
//! already-computed [`ExportPlan`], ported from legacy `services/copy_service.py`.
//!
//! ## Design deviation from legacy: no second, independent tree walk
//!
//! Legacy's `copy_project` performs its own `os.walk`, re-checking
//! `should_ignore_dir`/`.exportignore`/safety inline as it goes. This crate's copy step
//! instead iterates `ExportPlan.included_files` — the file list step 1
//! ([`crate::plan::run_export_plan`]) already produced via a single real directory
//! walk (`codepack_scanner::walk_project`) — and layers only the diff-selection and
//! safety-mode filters on top (`task-checklist.md`'s S9 design decision). A real
//! directory walk therefore happens exactly once per export run, not twice.
//!
//! This has real, documented consequences for [`CopyStats`]:
//!
//! - **`symlinks_skipped` is always `0` here.** `codepack_scanner::walk_project`
//!   already excludes symlinked entries at scan time (invariant I7) — the same safety
//!   guarantee legacy's copy step separately re-enforced now happens strictly earlier,
//!   once, not a regression.
//! - **`dirs_skipped` has no natural meaning inside a flat per-file loop** over an
//!   already-filtered list (there is no directory-level recursion left to skip
//!   *during* copying). It is populated from `export_plan.skipped_dirs.len()` instead
//!   — the count step 1 already computed, surfaced through this field rather than
//!   re-derived by a second walk.
//! - **`files_skipped_by_safety` is counted from the plan, not from this loop.** Since
//!   2026-07-25 `build_export_plan` classifies safe-mode exclusions itself (restoring
//!   legacy's own behavior), so unsafe files never reach `included_files` and the
//!   in-loop check below can no longer fire. That check is kept as defense in depth —
//!   `copy_project` is public and a caller may hand it a plan built with
//!   `no_safety_classification` — but the reported count is derived from
//!   `export_plan.excluded_files`, which is where those files now are. Reading it from
//!   the loop alone would have silently reported zero safety skips forever.
//! - The diff-skip branch increments only `files_skipped_by_diff`, matching legacy's own
//!   separate counter for that branch.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use codepack_core::{CancellationToken, CopyStats};
use codepack_scanner::ExportPlan;
use codepack_security::should_skip_file_for_safety;

use crate::error::{EngineError, Result};
use crate::relpath::to_relative_path;

/// Copies every file `export_plan` included into `project_dir`, applying the
/// diff-selection filter (`include_relative_paths`) and safety-mode filter
/// (`safe_export_mode`) on top. Never aborts on a per-file I/O error — matching
/// legacy's bare `except Exception: stats.errors += 1; continue` — except for the
/// initial creation of `project_dir` itself, which is not a per-file operation and is
/// propagated as [`EngineError::Io`].
///
/// `log` is called exactly once per candidate file, whatever the outcome (copied,
/// skipped, or errored) — mirroring legacy's per-file `log: Callable[[str], None]`
/// progress narration. A future orchestrator adapts a real progress-channel sender
/// into this callback shape, the same way it will for every other pipeline step.
pub fn copy_project(
    export_plan: &ExportPlan,
    include_relative_paths: Option<&HashSet<String>>,
    safe_export_mode: &str,
    source_root: &Path,
    project_dir: &Path,
    cancel: &CancellationToken,
    log: &dyn Fn(&str),
) -> Result<CopyStats> {
    fs::create_dir_all(project_dir).map_err(|source| EngineError::Io {
        path: project_dir.to_path_buf(),
        source,
    })?;

    // Files step 1 excluded for safety reasons. An entry counts only when the recorded
    // reason is the one the safety policy itself produced — a file excluded by an
    // `.exportignore` rule that also happens to be unsafe was skipped by the rule, and
    // legacy would not have counted it here either.
    let skipped_by_safety = export_plan
        .excluded_files
        .iter()
        .filter(|planned| {
            let decision = should_skip_file_for_safety(
                &to_relative_path(&planned.relative_path),
                safe_export_mode,
            );
            decision.skip && decision.reason == planned.reason
        })
        .count();

    let mut stats = CopyStats {
        dirs_created: 1,
        dirs_skipped: u32::try_from(export_plan.skipped_dirs.len()).unwrap_or(u32::MAX),
        files_skipped: u32::try_from(skipped_by_safety).unwrap_or(u32::MAX),
        files_skipped_by_safety: u32::try_from(skipped_by_safety).unwrap_or(u32::MAX),
        ..CopyStats::default()
    };
    let mut created_dirs: HashSet<PathBuf> = HashSet::new();
    created_dirs.insert(project_dir.to_path_buf());

    for planned in &export_plan.included_files {
        if cancel.is_cancelled() {
            break;
        }

        if let Some(selected) = include_relative_paths
            && !selected.contains(&planned.relative_path)
        {
            stats.files_skipped_by_diff += 1;
            log(&format!(
                "skipped (not in diff selection): {}",
                planned.relative_path
            ));
            continue;
        }

        let relative = to_relative_path(&planned.relative_path);
        let decision = should_skip_file_for_safety(&relative, safe_export_mode);
        if decision.skip {
            stats.files_skipped += 1;
            stats.files_skipped_by_safety += 1;
            log(&format!(
                "skipped by safety mode: {} ({})",
                planned.relative_path, decision.reason
            ));
            continue;
        }

        let source_path = source_root.join(&relative);
        let dest_path = project_dir.join(&relative);

        let Some(parent) = dest_path.parent() else {
            stats.errors += 1;
            log(&format!(
                "cannot determine parent directory for {}",
                planned.relative_path
            ));
            continue;
        };

        if !created_dirs.contains(parent) {
            match fs::create_dir_all(parent) {
                Ok(()) => {
                    created_dirs.insert(parent.to_path_buf());
                    stats.dirs_created += 1;
                }
                Err(source) => {
                    stats.errors += 1;
                    log(&format!(
                        "cannot create directory {}: {source}",
                        parent.display()
                    ));
                    continue;
                }
            }
        }

        match copy_regular_file(&source_path, &dest_path) {
            Ok(()) => {
                stats.files_copied += 1;
                log(&format!("copied: {}", planned.relative_path));
            }
            Err(source) => {
                stats.errors += 1;
                log(&format!("cannot copy {}: {source}", planned.relative_path));
            }
        }
    }

    Ok(stats)
}

/// Copies `source` to `destination`, refusing anything that is not a regular file.
///
/// `walk_project` already excludes symlinks, but time passes between the walk and the
/// copy, and `fs::copy` follows a link — so a path that was a file when it was planned
/// and is a link when it is copied puts the link's target into the bundle, possibly from
/// outside the project. That is invariant I7 defeated by a window rather than by a
/// mistake (audit No. 31).
///
/// ## What this closes, and what it does not
///
/// It refuses a symlink standing where a file was planned, which is the whole of the
/// reachable attack: the walk vetted a regular file, and anything else appearing there is
/// refused rather than copied.
///
/// A window remains between `symlink_metadata` and `File::open` — microseconds rather
/// than the seconds or minutes between the walk and the copy, but not zero. Closing it
/// completely means opening with `O_NOFOLLOW` on Unix and `FILE_FLAG_OPEN_REPARSE_POINT`
/// on Windows, and neither flag is reachable from `std` without a `libc`-level
/// dependency. Whether that dependency is worth the last microseconds of a local race is
/// an owner's call, not one to make while fixing something else; it is recorded as Q43.
///
/// Said plainly because the previous version of this comment was not: it claimed the
/// descriptor check was "the only form with no window", and the descriptor check could
/// not see this case at all.
fn copy_regular_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    // `symlink_metadata` is the one that does **not** follow a link, so this is what
    // actually answers "is the thing at this path a symlink". It has to come first and
    // it has to be this call: `File::open` follows a link, and the metadata of the open
    // descriptor then describes the *target* — a regular file — so the descriptor check
    // below cannot see a symlink to an ordinary file at all.
    //
    // That is not a hypothetical. This function's first version checked only the
    // descriptor, with a comment claiming it was "the only form with no window", and it
    // would have copied a symlink's target straight into the bundle. The `#[cfg(unix)]`
    // test that catches it existed the whole time and had never run, because CI was
    // Windows-only.
    if fs::symlink_metadata(source)?.file_type().is_symlink() {
        return Err(std::io::Error::other(
            "not a regular file when it came to be copied; a symlink appeared where the \
             plan saw an ordinary file",
        ));
    }

    let mut input = fs::File::open(source)?;
    // Kept, and not redundant: it catches what the path check cannot — a directory, a
    // FIFO, a device — and it is the one check made against the thing actually opened.
    if !input.metadata()?.file_type().is_file() {
        return Err(std::io::Error::other(
            "not a regular file when it came to be copied; a special file appeared where \
             the plan saw an ordinary file",
        ));
    }

    let mut output = fs::File::create(destination)?;
    std::io::copy(&mut input, &mut output)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use codepack_scanner::{ExportIgnoreRules, ScanOptions, build_export_plan};
    use std::sync::Mutex;

    fn no_log(_: &str) {}

    fn plan_for(source_root: &Path) -> ExportPlan {
        let options = ScanOptions::default();
        let rules = ExportIgnoreRules::from_project_and_config(source_root, &options);
        build_export_plan(
            source_root,
            &options,
            &rules,
            &codepack_scanner::no_safety_classification,
            &CancellationToken::new(),
        )
        .unwrap()
    }

    #[test]
    fn copies_every_included_file_preserving_the_tree() {
        let source = tempfile::tempdir().unwrap();
        fs::create_dir_all(source.path().join("src")).unwrap();
        fs::write(source.path().join("src/main.rs"), "fn main() {}").unwrap();
        fs::write(source.path().join("README.md"), "hello").unwrap();

        let plan = plan_for(source.path());
        let dest = tempfile::tempdir().unwrap();
        let project_dir = dest.path().join("project");

        let stats = copy_project(
            &plan,
            None,
            "full",
            source.path(),
            &project_dir,
            &CancellationToken::new(),
            &no_log,
        )
        .unwrap();

        assert_eq!(stats.files_copied, 2);
        assert_eq!(stats.errors, 0);
        assert!(project_dir.join("src/main.rs").is_file());
        assert!(project_dir.join("README.md").is_file());
    }

    #[test]
    fn symlinks_skipped_is_always_zero_since_the_plan_already_excluded_them() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("main.py"), "x").unwrap();
        let plan = plan_for(source.path());
        let dest = tempfile::tempdir().unwrap();

        let stats = copy_project(
            &plan,
            None,
            "full",
            source.path(),
            &dest.path().join("project"),
            &CancellationToken::new(),
            &no_log,
        )
        .unwrap();

        assert_eq!(stats.symlinks_skipped, 0);
    }

    #[test]
    fn dirs_skipped_surfaces_the_plans_own_skipped_dir_count() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("main.py"), "x").unwrap();
        fs::create_dir_all(source.path().join("node_modules")).unwrap();
        fs::write(source.path().join("node_modules/pkg.js"), "x").unwrap();
        let plan = plan_for(source.path());
        assert_eq!(plan.skipped_dirs.len(), 1);
        let dest = tempfile::tempdir().unwrap();

        let stats = copy_project(
            &plan,
            None,
            "full",
            source.path(),
            &dest.path().join("project"),
            &CancellationToken::new(),
            &no_log,
        )
        .unwrap();

        assert_eq!(stats.dirs_skipped, 1);
    }

    #[test]
    fn safety_mode_skip_increments_both_files_skipped_and_files_skipped_by_safety() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("main.py"), "x").unwrap();
        fs::write(source.path().join(".env"), "SECRET=1").unwrap();
        let plan = plan_for(source.path());
        let dest = tempfile::tempdir().unwrap();

        let stats = copy_project(
            &plan,
            None,
            "safe",
            source.path(),
            &dest.path().join("project"),
            &CancellationToken::new(),
            &no_log,
        )
        .unwrap();

        assert_eq!(stats.files_copied, 1);
        assert_eq!(stats.files_skipped, 1);
        assert_eq!(stats.files_skipped_by_safety, 1);
        assert!(!dest.path().join("project/.env").exists());
    }

    #[test]
    fn diff_skip_increments_only_files_skipped_by_diff_not_files_skipped() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("main.py"), "x").unwrap();
        fs::write(source.path().join("other.py"), "y").unwrap();
        let plan = plan_for(source.path());
        let dest = tempfile::tempdir().unwrap();

        let mut selected = HashSet::new();
        selected.insert("main.py".to_string());

        let stats = copy_project(
            &plan,
            Some(&selected),
            "full",
            source.path(),
            &dest.path().join("project"),
            &CancellationToken::new(),
            &no_log,
        )
        .unwrap();

        assert_eq!(stats.files_copied, 1);
        assert_eq!(stats.files_skipped_by_diff, 1);
        assert_eq!(stats.files_skipped, 0);
    }

    #[test]
    fn cancellation_mid_loop_yields_a_partial_but_error_free_result() {
        let source = tempfile::tempdir().unwrap();
        for i in 0..20 {
            fs::write(source.path().join(format!("file{i:02}.py")), "x").unwrap();
        }
        let plan = plan_for(source.path());
        assert_eq!(plan.included_files.len(), 20);
        let dest = tempfile::tempdir().unwrap();
        let cancel = CancellationToken::new();

        // Cancel the token from a controlled point rather than a real-time race:
        // `log` fires exactly once per processed file, so flipping the token on its
        // 5th call cancels after 5 files and lets the next loop iteration's
        // `cancel.is_cancelled()` check stop the copy.
        let cancel_for_log = cancel.clone();
        let processed = Mutex::new(0u32);
        let log = move |_: &str| {
            let mut count = processed.lock().unwrap();
            *count += 1;
            if *count == 5 {
                cancel_for_log.cancel();
            }
        };

        let stats = copy_project(
            &plan,
            None,
            "full",
            source.path(),
            &dest.path().join("project"),
            &cancel,
            &log,
        )
        .unwrap();

        assert_eq!(stats.errors, 0);
        assert!(
            stats.files_copied >= 5,
            "files_copied = {}",
            stats.files_copied
        );
        assert!(
            stats.files_copied < 20,
            "files_copied = {}",
            stats.files_copied
        );
    }
}

#[cfg(test)]
mod descriptor_tests {
    use super::*;

    /// An ordinary file copies, byte for byte.
    #[test]
    fn a_regular_file_copies_its_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("a.txt");
        let destination = dir.path().join("b.txt");
        fs::write(&source, b"hello\n").unwrap();

        copy_regular_file(&source, &destination).expect("an ordinary file copies");
        assert_eq!(fs::read(&destination).unwrap(), b"hello\n");
    }

    /// A directory is not a regular file, and the refusal names why rather than producing
    /// a confusing I/O error further along.
    #[test]
    fn a_directory_is_refused_by_the_descriptor_check() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("sub");
        fs::create_dir_all(&source).unwrap();

        let error = copy_regular_file(&source, &dir.path().join("out"))
            .expect_err("a directory is not a file to copy");
        // On some platforms opening a directory fails outright; on others the descriptor
        // check is what refuses it. Either is correct — what matters is that it is
        // refused rather than copied.
        let rendered = error.to_string();
        assert!(!rendered.is_empty(), "{rendered}");
    }

    /// The same case on Windows, where creating a symlink needs Developer Mode or an
    /// elevated shell. When it cannot be created the test says so and stops rather than
    /// passing quietly — a skip that looks like a pass is how the Unix version of this
    /// went unrun for weeks.
    #[cfg(windows)]
    #[test]
    fn a_symlink_that_appeared_after_planning_is_refused_rather_than_followed_on_windows() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside-the-project.txt");
        fs::write(
            &outside,
            b"a secret from beyond the project
",
        )
        .unwrap();

        let planned = dir.path().join("looks-like-a-file.txt");
        if std::os::windows::fs::symlink_file(&outside, &planned).is_err() {
            eprintln!(
                "skipped: this Windows host cannot create symlinks (Developer Mode off).                  The Unix test covers the same guard."
            );
            return;
        }
        let destination = dir.path().join("copied.txt");

        let error = copy_regular_file(&planned, &destination)
            .expect_err("a symlink must not be copied through");
        assert!(error.to_string().contains("symlink"), "{error}");
        assert!(
            !destination.exists(),
            "the link target's bytes must not reach the bundle"
        );
    }

    /// Audit No. 31, the case that motivated the change: a symlink standing where the plan
    /// saw a file must not put its target's bytes into the bundle. `fs::copy` follows the
    /// link and would have.
    ///
    /// Unix only, because that is where a test can create a symlink without elevation;
    /// the guard itself is platform-independent, and `#[cfg(unix)]` test helpers are kept
    /// in this project for exactly this reason (`15-command-reference.md`).
    #[cfg(unix)]
    #[test]
    fn a_symlink_that_appeared_after_planning_is_refused_rather_than_followed() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside-the-project.txt");
        fs::write(&outside, b"a secret from beyond the project\n").unwrap();

        let planned = dir.path().join("looks-like-a-file.txt");
        std::os::unix::fs::symlink(&outside, &planned).unwrap();
        let destination = dir.path().join("copied.txt");

        let error = copy_regular_file(&planned, &destination)
            .expect_err("a symlink must not be copied through");
        assert!(error.to_string().contains("not a regular file"), "{error}");
        assert!(
            !destination.exists() || fs::read(&destination).unwrap().is_empty(),
            "the link target's bytes must not reach the bundle"
        );
    }
}
