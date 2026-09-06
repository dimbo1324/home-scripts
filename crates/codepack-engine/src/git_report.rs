//! Pipeline step 4 ("Git report"): a read-only, `git2`-based snapshot of the
//! **original** source repository's status/branch/log/HEAD diff, ported from legacy
//! `reports/git_report.py::write_git_report`, which shells out to four (or five, with
//! `include_patch`) `git` subprocess commands and redacts their output.
//!
//! Domain rules forbid shelling out to `git` from any crate in this workspace
//! (`.ai/project/12-domain-rules.md`) — every section below is the **equivalent**
//! read-only query against the same repository via `git2`, not a literal reproduction
//! of subprocess stdout framing. There is no real subprocess exit code to report here,
//! so — unlike legacy's own `exit_code:`/`--- stdout ---`/`--- stderr ---` markers —
//! this only writes the section header and its (redacted) content lines; inventing a
//! fabricated exit code would be dishonest, not parity. This mirrors the posture
//! `codepack_reports`'s own Group C reports (`05_git_deep.txt`, not itself reusable
//! here: its `git_support` module is private to that crate) already established for
//! the same "subprocess command list" → "git2 equivalent" translation.
//!
//! [`Repository::discover`] is used, not `::open`: this walks upward from
//! `source_root` exactly like the real `git` CLI does from a given `cwd`, matching
//! legacy's actual subprocess behavior (`cwd=source_root`) more faithfully than
//! `codepack_reports::git_support::open_repository`'s `Repository::open` (a
//! deliberately different, documented choice for that module's own two reports) would.
//! `codepack_diff::selection::git_common::discover_repository` already established this
//! exact call for the same "just run git from this cwd" semantics; that helper is
//! `pub(super)` to its own module, so this reimplements the one-line call rather than
//! reaching across a crate's private module boundary.
//!
//! ## Redaction: the stronger keyword cascade, not legacy's own choice
//!
//! Every line is redacted through `codepack_security::Redactor::redacted_line`
//! when a redactor is supplied — **not** the narrower [`codepack_security::redact_secrets`],
//! which is legacy's own `git_report.py` call. Stage S7's independent review found and
//! fixed a real secret-leak bug caused by exactly that weaker function in a report
//! context (a `DATABASE_URL=...` value slipping through `docker_report.py`'s call
//! site), and every git-touching report `codepack-reports` writes was switched to the
//! stronger cascade as a result (see `codepack_reports::context::redact_line`'s doc
//! comment). This pass follows that same, already-corrected precedent for a second
//! Git-touching report rather than reintroducing the weaker legacy call.

use std::fs;
use std::path::Path;

use git2::{
    Delta, DiffFindOptions, DiffFormat, Oid, Repository, Signature, Sort, Status, StatusOptions,
};

use codepack_core::CancellationToken;

use crate::error::{EngineError, Result};
use codepack_core::time::UtcDateTime;

use crate::layout::section_rule;
use crate::timestamp::human_now_utc;

fn current_branch_name(repo: &Repository) -> Option<String> {
    let head_ref = repo.find_reference("HEAD").ok()?;
    let target = head_ref.symbolic_target().ok()??;
    target
        .strip_prefix("refs/heads/")
        .map(|name| name.to_string())
}

fn short_oid(oid: Oid) -> String {
    oid.to_string().chars().take(7).collect()
}

fn signature_display(signature: &Signature<'_>) -> String {
    let name = signature.name().unwrap_or("(unknown)");
    let email = signature.email().unwrap_or("(unknown)");
    format!("{name} <{email}>")
}

/// A commit's timestamp (`git2::Commit::time`, the committer moment), rendered in UTC
/// down to the second. Git stores it as signed epoch seconds plus a separate timezone
/// offset; the offset is deliberately dropped here for
/// the same reason every other timestamp in this crate renders UTC (see
/// [`codepack_core::time`]) — a stable, unambiguous rendering beats reproducing each
/// committer's local zone.
fn format_commit_datetime(seconds_since_epoch: i64) -> String {
    UtcDateTime::from_unix_seconds(seconds_since_epoch).format_human_utc()
}

fn short_status_code(status: Status) -> String {
    if status.contains(Status::WT_NEW) && !status.contains(Status::INDEX_NEW) {
        return "??".to_string();
    }
    let index_char = if status.contains(Status::INDEX_NEW) {
        'A'
    } else if status.contains(Status::INDEX_MODIFIED) {
        'M'
    } else if status.contains(Status::INDEX_DELETED) {
        'D'
    } else if status.contains(Status::INDEX_RENAMED) {
        'R'
    } else if status.contains(Status::INDEX_TYPECHANGE) {
        'T'
    } else {
        ' '
    };
    let wt_char = if status.contains(Status::WT_MODIFIED) {
        'M'
    } else if status.contains(Status::WT_DELETED) {
        'D'
    } else if status.contains(Status::WT_TYPECHANGE) {
        'T'
    } else if status.contains(Status::WT_RENAMED) {
        'R'
    } else {
        ' '
    };
    format!("{index_char}{wt_char}")
}

fn status_short(repo: &Repository) -> Vec<String> {
    let mut opts = StatusOptions::new();
    opts.include_untracked(true).recurse_untracked_dirs(true);
    let Ok(statuses) = repo.statuses(Some(&mut opts)) else {
        return Vec::new();
    };
    let branch = current_branch_name(repo).unwrap_or_else(|| "HEAD (detached)".to_string());
    let mut lines = vec![format!("## {branch}")];
    for entry in statuses.iter() {
        let Ok(path) = entry.path() else { continue };
        lines.push(format!("{} {path}", short_status_code(entry.status())));
    }
    lines
}

/// Legacy's `git log --oneline -5`, plus each commit's committer moment — the
/// `--date=iso-strict --pretty=%h %cd %s` shape rather than the bare `--oneline` one.
///
/// Owner decision 2026-08-05: a log a reader cannot place in time is half a log, and
/// this project routinely produces several commits in one day. The committer date is
/// the one shown, not the author date, because it is what orders the history as it
/// actually landed — a rebased or cherry-picked commit keeps its original author date.
fn recent_log(repo: &Repository, limit: usize) -> Vec<String> {
    let Ok(mut revwalk) = repo.revwalk() else {
        return Vec::new();
    };
    if revwalk.push_head().is_err() {
        return Vec::new();
    }
    let _ = revwalk.set_sorting(Sort::TIME);
    let mut lines = Vec::new();
    for oid in revwalk.take(limit) {
        let Ok(oid) = oid else { continue };
        let Ok(commit) = repo.find_commit(oid) else {
            continue;
        };
        lines.push(format!(
            "{} {} {}",
            short_oid(oid),
            format_commit_datetime(commit.time().seconds()),
            commit.summary().ok().flatten().unwrap_or("")
        ));
    }
    lines
}

fn empty_tree<'repo>(
    repo: &'repo Repository,
) -> std::result::Result<git2::Tree<'repo>, git2::Error> {
    let oid = repo.treebuilder(None)?.write()?;
    repo.find_tree(oid)
}

fn head_commit(repo: &Repository) -> Option<git2::Commit<'_>> {
    repo.head().ok()?.peel_to_commit().ok()
}

fn parent_tree<'repo>(
    repo: &'repo Repository,
    commit: &git2::Commit<'repo>,
) -> Option<git2::Tree<'repo>> {
    match commit.parent(0) {
        Ok(parent) => parent.tree().ok(),
        Err(_) => empty_tree(repo).ok(),
    }
}

fn status_letter(status: Delta) -> &'static str {
    match status {
        Delta::Added => "A",
        Delta::Deleted => "D",
        Delta::Modified => "M",
        Delta::Renamed => "R",
        Delta::Copied => "C",
        _ => "?",
    }
}

fn name_status_lines(diff: &git2::Diff<'_>) -> Vec<String> {
    diff.deltas()
        .filter_map(|delta| {
            let path = delta
                .new_file()
                .path()
                .or_else(|| delta.old_file().path())?;
            Some(format!(
                "{}\t{}",
                status_letter(delta.status()),
                path.display()
            ))
        })
        .collect()
}

fn patch_path(patch: &git2::Patch<'_>) -> String {
    patch
        .delta()
        .new_file()
        .path()
        .or_else(|| patch.delta().old_file().path())
        .map(|path| path.display().to_string())
        .unwrap_or_default()
}

fn stat_lines(diff: &git2::Diff<'_>) -> Vec<String> {
    let mut lines = Vec::new();
    for idx in 0..diff.deltas().count() {
        let Ok(Some(patch)) = git2::Patch::from_diff(diff, idx) else {
            continue;
        };
        let Ok((_, insertions, deletions)) = patch.line_stats() else {
            continue;
        };
        lines.push(format!(
            "{} | +{insertions} -{deletions}",
            patch_path(&patch)
        ));
    }
    if let Ok(stats) = diff.stats() {
        lines.push(format!(
            "{} file(s) changed, {} insertion(s)(+), {} deletion(s)(-)",
            stats.files_changed(),
            stats.insertions(),
            stats.deletions()
        ));
    }
    lines
}

fn commit_header_lines(commit: &git2::Commit<'_>) -> Vec<String> {
    let mut lines = vec![
        format!("commit {}", commit.id()),
        format!("Author: {}", signature_display(&commit.author())),
        format!(
            "Date:   {}",
            format_commit_datetime(commit.time().seconds())
        ),
        String::new(),
    ];
    let message = commit.message().unwrap_or("");
    if message.is_empty() {
        lines.push("    (no commit message)".to_string());
    } else {
        for line in message.lines() {
            lines.push(format!("    {line}"));
        }
    }
    lines
}

fn show_stat_name_status(repo: &Repository) -> Vec<String> {
    let Some(commit) = head_commit(repo) else {
        return vec!["(this repository has no commits yet)".to_string()];
    };
    let Ok(head_tree) = commit.tree() else {
        return Vec::new();
    };
    let parent = parent_tree(repo, &commit);
    let Ok(diff) = repo.diff_tree_to_tree(parent.as_ref(), Some(&head_tree), None) else {
        return Vec::new();
    };

    let mut lines = commit_header_lines(&commit);
    lines.push(String::new());
    lines.extend(name_status_lines(&diff));
    lines.push(String::new());
    lines.extend(stat_lines(&diff));
    lines
}

fn show_patch(repo: &Repository) -> Vec<String> {
    let Some(commit) = head_commit(repo) else {
        return vec!["(this repository has no commits yet)".to_string()];
    };
    let Ok(head_tree) = commit.tree() else {
        return Vec::new();
    };
    let parent = parent_tree(repo, &commit);
    let Ok(mut diff) = repo.diff_tree_to_tree(parent.as_ref(), Some(&head_tree), None) else {
        return Vec::new();
    };
    let mut find_opts = DiffFindOptions::new();
    find_opts.renames(true);
    if diff.find_similar(Some(&mut find_opts)).is_err() {
        return Vec::new();
    }

    let mut raw = String::new();
    let printed = diff.print(DiffFormat::Patch, |_delta, _hunk, line| {
        let origin = line.origin();
        if origin == '+' || origin == '-' || origin == ' ' {
            raw.push(origin);
        }
        if let Ok(text) = std::str::from_utf8(line.content()) {
            raw.push_str(text);
        }
        true
    });
    if printed.is_err() {
        return Vec::new();
    }
    raw.lines().map(str::to_string).collect()
}

fn write_section(
    out: &mut String,
    command: &str,
    lines: &[String],
    redactor: Option<&codepack_security::Redactor>,
) {
    out.push_str(&format!("$ {command}\n"));
    if lines.is_empty() {
        out.push_str("(no output)\n");
    } else {
        for line in lines {
            let rendered = match redactor {
                Some(redactor) => redactor.redacted_line(line),
                None => line.clone(),
            };
            out.push_str(&rendered);
            out.push('\n');
        }
    }
    out.push('\n');
    out.push_str(&section_rule('-'));
    out.push_str("\n\n");
}

fn finish(out: String, output_file: &Path) -> Result<()> {
    fs::write(output_file, out).map_err(|source| EngineError::Io {
        path: output_file.to_path_buf(),
        source,
    })
}

/// Runs pipeline step 4. `include_patch` mirrors `config.include_git_patch`;
/// `redactor` is `Some` exactly when `config.redact_secrets` is set, and carries the
/// run's placeholder policy with it — one argument rather than a boolean and a redactor
/// that could disagree with each other. Never returns `Err` for a
/// missing or unreadable Git repository — an un-versioned project must still export
/// cleanly, the same principle `codepack_diff`'s `disabled_by_git_error` already
/// encodes for diff selection.
/// `disclosed_source_root` is what the report should call the project's root — the real
/// path, or the project's name when `Config::disclose_absolute_paths` is off. Passed in
/// rather than derived here: this crate deliberately knows nothing about `Config`, and the
/// caller already holds both (audit No. 21).
#[allow(clippy::too_many_arguments)]
pub fn write_git_report(
    source_root: &Path,
    disclosed_source_root: &str,
    output_file: &Path,
    include_patch: bool,
    redactor: Option<&codepack_security::Redactor>,
    log: &dyn Fn(&str),
    cancel: &CancellationToken,
) -> Result<()> {
    let mut out = String::new();
    out.push_str("=== Git Report ===\n");
    out.push_str(&format!("Source root: {disclosed_source_root}\n"));
    out.push_str(&format!("Generated: {}\n", human_now_utc()));
    out.push_str(&format!(
        "Patch included: {}\n",
        if include_patch { "yes" } else { "no" }
    ));
    out.push_str("Git commands are read-only. The .git directory is not copied.\n");
    out.push_str(if redactor.is_some() {
        "Secret redaction is applied to command output.\n"
    } else {
        "Secret redaction is disabled.\n"
    });
    out.push_str(&section_rule('='));
    out.push_str("\n\n");

    let Ok(repo) = Repository::discover(source_root) else {
        out.push_str("No Git repository was found for this project; Git sections are skipped.\n");
        log("git report: no repository found");
        return finish(out, output_file);
    };

    macro_rules! bail_if_cancelled {
        () => {
            if cancel.is_cancelled() {
                out.push_str("\nCANCELLED BY USER\n");
                return finish(out, output_file);
            }
        };
    }

    bail_if_cancelled!();
    write_section(
        &mut out,
        "git status --short --branch",
        &status_short(&repo),
        redactor,
    );

    bail_if_cancelled!();
    write_section(
        &mut out,
        "git branch --show-current",
        &[current_branch_name(&repo).unwrap_or_default()],
        redactor,
    );

    bail_if_cancelled!();
    write_section(
        &mut out,
        "git log -5 --date=iso-strict --pretty=%h %cd %s",
        &recent_log(&repo, 5),
        redactor,
    );

    bail_if_cancelled!();
    write_section(
        &mut out,
        "git show --stat --name-status HEAD",
        &show_stat_name_status(&repo),
        redactor,
    );

    if include_patch {
        bail_if_cancelled!();
        write_section(
            &mut out,
            "git show --patch --find-renames HEAD",
            &show_patch(&repo),
            redactor,
        );
    }

    log("git report written");
    finish(out, output_file)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_log(_: &str) {}

    fn init_repo(dir: &Path) -> Repository {
        Repository::init(dir).expect("git2 init in a fresh tempdir cannot fail")
    }

    fn commit_all(repo: &Repository, message: &str) -> Oid {
        let mut index = repo
            .index()
            .expect("freshly opened repo has a usable index");
        index
            .add_all(["*"], git2::IndexAddOption::DEFAULT, None)
            .expect("adding all paths in a tempdir cannot fail");
        index.write().expect("writing the index cannot fail here");
        let tree_id = index
            .write_tree()
            .expect("writing the tree from a valid index cannot fail");
        let tree = repo
            .find_tree(tree_id)
            .expect("the tree was just written by this same call");
        let signature = Signature::now("Test User", "test@example.local")
            .expect("a fixed, valid signature cannot fail");
        let parent = repo.head().ok().and_then(|head| head.peel_to_commit().ok());
        let parents: Vec<git2::Commit<'_>> = parent.into_iter().collect();
        let parent_refs: Vec<&git2::Commit<'_>> = parents.iter().collect();
        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            message,
            &tree,
            &parent_refs,
        )
        .expect("committing a valid tree in a fresh repo cannot fail")
    }

    #[test]
    fn degrades_gracefully_when_no_repository_is_present() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.py"), "x = 1\n").unwrap();
        let output = dir.path().join("git_report.txt");

        write_git_report(
            dir.path(),
            &dir.path().display().to_string(),
            &output,
            false,
            Some(&codepack_security::Redactor::plain()),
            &no_log,
            &CancellationToken::new(),
        )
        .unwrap();

        let content = std::fs::read_to_string(&output).unwrap();
        assert!(content.contains("No Git repository was found"));
    }

    #[test]
    fn a_secret_in_a_commit_message_is_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let repo = init_repo(dir.path());
        std::fs::write(dir.path().join("main.py"), "print('hi')\n").unwrap();
        commit_all(&repo, "init: rotate API_KEY=sk-super-secret-value");
        let output = dir.path().join("git_report.txt");

        write_git_report(
            dir.path(),
            &dir.path().display().to_string(),
            &output,
            false,
            Some(&codepack_security::Redactor::plain()),
            &no_log,
            &CancellationToken::new(),
        )
        .unwrap();

        let content = std::fs::read_to_string(&output).unwrap();
        assert!(!content.contains("sk-super-secret-value"));
    }

    #[test]
    fn a_secret_in_tracked_file_diff_is_redacted_when_patch_is_included() {
        let dir = tempfile::tempdir().unwrap();
        let repo = init_repo(dir.path());
        std::fs::write(dir.path().join(".env"), "API_KEY=sk-super-secret-value\n").unwrap();
        commit_all(&repo, "add env file");
        let output = dir.path().join("git_report.txt");

        write_git_report(
            dir.path(),
            &dir.path().display().to_string(),
            &output,
            true,
            Some(&codepack_security::Redactor::plain()),
            &no_log,
            &CancellationToken::new(),
        )
        .unwrap();

        let content = std::fs::read_to_string(&output).unwrap();
        assert!(!content.contains("sk-super-secret-value"));
        assert!(content.contains("$ git show --patch --find-renames HEAD"));
    }

    #[test]
    fn branch_log_and_status_sections_render_for_a_simple_repo() {
        let dir = tempfile::tempdir().unwrap();
        let repo = init_repo(dir.path());
        std::fs::write(dir.path().join("a.py"), "1\n").unwrap();
        commit_all(&repo, "first");
        std::fs::write(dir.path().join("b.py"), "2\n").unwrap();
        commit_all(&repo, "second");
        std::fs::write(dir.path().join("untracked.txt"), "x\n").unwrap();
        let output = dir.path().join("git_report.txt");

        write_git_report(
            dir.path(),
            &dir.path().display().to_string(),
            &output,
            false,
            None,
            &no_log,
            &CancellationToken::new(),
        )
        .unwrap();

        let content = std::fs::read_to_string(&output).unwrap();
        assert!(content.contains("$ git status --short --branch"));
        assert!(content.contains("untracked.txt"));
        assert!(content.contains("$ git branch --show-current"));
        assert!(content.contains("$ git log -5 --date=iso-strict --pretty=%h %cd %s"));
        assert!(content.contains("first"));
        assert!(content.contains("second"));
        // Every logged commit is placed in time to the second. The indented copy of
        // the message inside the `git show` section ends with the same words, so log
        // lines are told apart by not being indented.
        let logged: Vec<&str> = content
            .lines()
            .filter(|line| {
                !line.starts_with(' ') && (line.ends_with("first") || line.ends_with("second"))
            })
            .collect();
        assert_eq!(logged.len(), 2, "both commits appear in the log section");
        for line in logged {
            assert!(line.contains(" UTC "), "{line} carries no moment");
        }
        assert!(content.contains("$ git show --stat --name-status HEAD"));
        assert!(content.contains("b.py"));
        assert!(content.contains("Secret redaction is disabled."));
    }

    #[test]
    fn the_initial_commit_does_not_panic_computing_stat_name_status() {
        let dir = tempfile::tempdir().unwrap();
        let repo = init_repo(dir.path());
        std::fs::write(dir.path().join("only.py"), "1\n").unwrap();
        commit_all(&repo, "initial commit, no parent");
        let output = dir.path().join("git_report.txt");

        write_git_report(
            dir.path(),
            &dir.path().display().to_string(),
            &output,
            false,
            Some(&codepack_security::Redactor::plain()),
            &no_log,
            &CancellationToken::new(),
        )
        .unwrap();

        let content = std::fs::read_to_string(&output).unwrap();
        assert!(content.contains("only.py"));
        assert!(content.contains("A\tonly.py"));
    }
}
