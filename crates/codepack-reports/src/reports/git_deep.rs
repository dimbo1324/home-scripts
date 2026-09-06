//! `05_git_deep.txt`, ported from legacy
//! `reports/insights/git_deep.py::write_git_deep_report`. Legacy shells out to ten
//! separate `git` subprocess commands (`status --short --branch`, `branch
//! --show-current`, `branch -a`, `remote -v`, `diff --stat`, `diff --name-only`,
//! `ls-files`, `ls-files --others --exclude-standard`,
//! `log --decorate --graph -20` (legacy's own call was `--oneline`; owner decision
//! 2026-08-05 adds `--date=iso-strict` so each commit carries its moment),
//! `rev-parse --show-toplevel`) and redacts
//! each command's raw stdout/stderr before writing it. Domain rules forbid shelling
//! out to `git` from this crate (`unsafe`/subprocess bans aside, `codepack-reports`
//! must never invoke an external `git` binary) — every section here is the
//! **equivalent** read-only query against the same repository via `git2`
//! ([`crate::git_support`]), not a literal reproduction of subprocess stdout framing
//! (no fake exit codes/STDOUT/STDERR markers, since none of that is real here).
//!
//! Every dynamic line (branch names, remote URLs, commit subjects, paths) is routed
//! through [`redact_line`] before being written — invariant I3: a commit message or a
//! remote URL can carry an inline credential just as easily as file content can.

use std::path::Path;

use git2::{BranchType, Patch, Repository, Sort, Status, StatusOptions};

use crate::context::{ReportContext, redact_line};
use crate::error::ReportError;
use crate::git_support::{open_repository, short_oid};
use crate::plugin::ReportJob;
use crate::profile;
use crate::reports::layout::section_rule;

pub const JOB: ReportJob = ReportJob {
    filename: "05_git_deep.txt",
    profiles: profile::GIT_DEEP_TXT,
    description: "Read-only Git deep-dive: branches, remotes, diff stat, tracked/untracked files.",
    run: write_git_deep_report,
};

fn write_section(out: &mut String, label: &str, lines: &[String]) {
    out.push('\n');
    out.push_str(&section_rule('='));
    out.push_str(&format!("\n$ {label}\n"));
    out.push_str(&section_rule('='));
    out.push_str("\n\n");
    if lines.is_empty() {
        out.push_str("(no output)\n");
        return;
    }
    for line in lines {
        out.push_str(&redact_line(line));
        out.push('\n');
    }
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
    let branch = crate::git_support::current_branch_name(repo)
        .unwrap_or_else(|| "HEAD (detached)".to_string());
    let mut lines = vec![format!("## {branch}")];
    for entry in statuses.iter() {
        let Ok(path) = entry.path() else { continue };
        lines.push(format!("{} {path}", short_status_code(entry.status())));
    }
    lines
}

fn all_branches(repo: &Repository) -> Vec<String> {
    let current = crate::git_support::current_branch_name(repo);
    let Ok(branches) = repo.branches(None) else {
        return Vec::new();
    };
    let mut items: Vec<(String, bool)> = Vec::new();
    for item in branches.flatten() {
        let (branch, branch_type) = item;
        let Ok(Some(name)) = branch.name() else {
            continue;
        };
        let display = match branch_type {
            BranchType::Remote => format!("remotes/{name}"),
            BranchType::Local => name.to_string(),
        };
        let is_current = branch_type == BranchType::Local && current.as_deref() == Some(name);
        items.push((display, is_current));
    }
    items.sort_by(|a, b| a.0.cmp(&b.0));
    items
        .into_iter()
        .map(|(display, is_current)| format!("{}{display}", if is_current { "* " } else { "  " }))
        .collect()
}

fn remotes_verbose(repo: &Repository) -> Vec<String> {
    let Ok(names) = repo.remotes() else {
        return Vec::new();
    };
    let mut lines = Vec::new();
    for name in names.iter().flatten().flatten() {
        let Ok(remote) = repo.find_remote(name) else {
            continue;
        };
        let fetch_url = remote.url().unwrap_or("(no url)");
        lines.push(format!("{name}\t{fetch_url} (fetch)"));
        let push_url = remote.pushurl().ok().flatten().unwrap_or(fetch_url);
        lines.push(format!("{name}\t{push_url} (push)"));
    }
    lines
}

fn patch_path(patch: &Patch<'_>) -> String {
    patch
        .delta()
        .new_file()
        .path()
        .or_else(|| patch.delta().old_file().path())
        .map(|path| path.display().to_string())
        .unwrap_or_default()
}

fn diff_stat(repo: &Repository) -> Vec<String> {
    let Ok(diff) = repo.diff_index_to_workdir(None, None) else {
        return Vec::new();
    };
    let mut lines = Vec::new();
    for idx in 0..diff.deltas().count() {
        let Ok(Some(patch)) = Patch::from_diff(&diff, idx) else {
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

fn diff_name_only(repo: &Repository) -> Vec<String> {
    let Ok(diff) = repo.diff_index_to_workdir(None, None) else {
        return Vec::new();
    };
    diff.deltas()
        .filter_map(|delta| delta.new_file().path().or_else(|| delta.old_file().path()))
        .map(|path| path.display().to_string())
        .collect()
}

fn ls_files(repo: &Repository) -> Vec<String> {
    let Ok(index) = repo.index() else {
        return Vec::new();
    };
    index
        .iter()
        .map(|entry| String::from_utf8_lossy(&entry.path).into_owned())
        .collect()
}

fn ls_files_untracked(repo: &Repository) -> Vec<String> {
    let mut opts = StatusOptions::new();
    opts.include_untracked(true).recurse_untracked_dirs(true);
    let Ok(statuses) = repo.statuses(Some(&mut opts)) else {
        return Vec::new();
    };
    let mut lines = Vec::new();
    for entry in statuses.iter() {
        let status = entry.status();
        if status.contains(Status::WT_NEW)
            && !status.contains(Status::INDEX_NEW)
            && let Ok(path) = entry.path()
        {
            lines.push(path.to_string());
        }
    }
    lines
}

/// The graph-marker log line, `* <short oid> <moment> <subject>`. The moment is the
/// committer date, which is what orders the history as it landed; see
/// [`crate::git_support::format_commit_datetime`] for why it is rendered in full.
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
            "* {} {} {}",
            short_oid(oid),
            crate::git_support::format_commit_datetime(commit.time().seconds()),
            commit.summary().ok().flatten().unwrap_or("")
        ));
    }
    lines
}

fn write_git_deep_report(ctx: &ReportContext<'_>, output_file: &Path) -> Result<(), ReportError> {
    let mut out = String::new();
    out.push_str("=== Git Deep Report ===\n");
    out.push_str(&format!("Source root: {}\n", ctx.disclosed_source_root()));
    out.push_str(&format!("Generated: {}\n", ctx.plan.generated_at));
    out.push_str(
        "Important: this report is read-only and never switches branches or modifies the repository.\n",
    );
    out.push_str(&section_rule('='));
    out.push_str("\n\n");

    let Some(repo) = open_repository(&ctx.source_root) else {
        out.push_str("No .git directory was found in the selected root.\n");
        return std::fs::write(output_file, out).map_err(|source| ReportError::Write {
            path: output_file.to_path_buf(),
            source,
        });
    };

    write_section(
        &mut out,
        "git status --short --branch",
        &status_short(&repo),
    );
    write_section(
        &mut out,
        "git branch --show-current",
        &[crate::git_support::current_branch_name(&repo).unwrap_or_default()],
    );
    write_section(&mut out, "git branch -a", &all_branches(&repo));
    write_section(&mut out, "git remote -v", &remotes_verbose(&repo));
    write_section(&mut out, "git diff --stat", &diff_stat(&repo));
    write_section(&mut out, "git diff --name-only", &diff_name_only(&repo));
    write_section(&mut out, "git ls-files", &ls_files(&repo));
    write_section(
        &mut out,
        "git ls-files --others --exclude-standard",
        &ls_files_untracked(&repo),
    );
    write_section(
        &mut out,
        "git log --decorate --graph -20 --date=iso-strict --pretty=%h %cd %s",
        &recent_log(&repo, 20),
    );
    // Not `repo.workdir()`: that is the machine's absolute path, and this section was
    // the last artifact still printing one with `disclose_absolute_paths` off. It hid
    // from the bundle-wide test because libgit2 renders a Windows path with forward
    // slashes, matching neither spelling the test searched for; both Unix runners saw it
    // at once (2026-09-06). The header line above already answers the same question,
    // through the same method, so this now agrees with it.
    write_section(
        &mut out,
        "git rev-parse --show-toplevel",
        &[ctx.disclosed_source_root()],
    );

    std::fs::write(output_file, out).map_err(|source| ReportError::Write {
        path: output_file.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git_support::test_support::{commit_all, init_repo, write_file};
    use crate::test_support::Fixture;

    #[test]
    fn writes_not_a_repository_note_when_no_git_directory_exists() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("main.py"), "x = 1\n").unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_git_deep_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("No .git directory was found in the selected root."));
    }

    #[test]
    fn writes_git_sections_and_redacts_a_secret_in_a_commit_message() {
        let dir = tempfile::tempdir().unwrap();
        let repo = init_repo(dir.path());
        write_file(dir.path(), "main.py", "print('hi')\n");
        commit_all(&repo, "init: rotate API_KEY=sk-super-secret-value");
        repo.remote("origin", "https://example.com/demo/repo.git")
            .unwrap();
        write_file(dir.path(), "untracked.txt", "hi\n");

        let plan = crate::test_support::build_plan(dir.path());
        let inventory = crate::context::Inventory::from_plan(&plan);
        let config = codepack_core::config::Config::default();
        let cancel = codepack_core::CancellationToken::new();
        let ctx = ReportContext {
            source_root: dir.path().to_path_buf(),
            staging_root: dir.path().to_path_buf(),
            inventory: &inventory,
            plan: &plan,
            scan: None,
            diff: None,
            config: &config,
            cancel: &cancel,
            profile: "full",
        };
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_git_deep_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("$ git status --short --branch"));
        assert!(content.contains("$ git branch -a"));
        assert!(content.contains("$ git remote -v"));
        assert!(content.contains("origin\thttps://example.com/demo/repo.git"));
        assert!(content.contains("untracked.txt"));
        assert!(content.contains("main.py"));
        assert!(!content.contains("sk-super-secret-value"));
        assert!(content.contains("<REDACTED>"));
    }

    /// The `git rev-parse --show-toplevel` section used to print libgit2's own workdir,
    /// which is the machine's absolute path whatever `disclose_absolute_paths` says. Its
    /// spelling — forward slashes on Windows too — is what let it slip past the
    /// bundle-wide sweep until both Unix runners failed on it.
    #[test]
    fn the_toplevel_section_never_names_the_machines_directories() {
        let dir = tempfile::tempdir().unwrap();
        let repo = init_repo(dir.path());
        write_file(dir.path(), "main.py", "print('hi')\n");
        commit_all(&repo, "init");

        let plan = crate::test_support::build_plan(dir.path());
        let inventory = crate::context::Inventory::from_plan(&plan);
        let config = codepack_core::config::Config {
            disclose_absolute_paths: false,
            ..codepack_core::config::Config::default()
        };
        let cancel = codepack_core::CancellationToken::new();
        let ctx = ReportContext {
            source_root: dir.path().to_path_buf(),
            staging_root: dir.path().to_path_buf(),
            inventory: &inventory,
            plan: &plan,
            scan: None,
            diff: None,
            config: &config,
            cancel: &cancel,
            profile: "full",
        };
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_git_deep_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        let root = dir.path().display().to_string();
        for spelling in [root.clone(), root.replace('\\', "/")] {
            assert!(!content.contains(&spelling), "the report names {spelling}");
        }
        assert!(content.contains("$ git rev-parse --show-toplevel"));
    }
}
