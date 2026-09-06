//! `21_git_timeline_report.md`, ported from legacy
//! `reports/insights/git_timeline.py::write_git_timeline_report`. Legacy shells out to
//! `git branch --show-current`, `git rev-parse --short HEAD`, `git shortlog -sne HEAD`,
//! `git log --date=iso-strict --pretty=... -30` (legacy's own call used `--date=short`;
//! owner decision 2026-08-05 requires the full moment), and
//! `git log --numstat --pretty=format: -200`;
//! every one of those is reproduced here as a read-only `git2` query
//! ([`crate::git_support`]) rather than a subprocess call (domain rules forbid shelling
//! out to `git` from this crate).
//!
//! Every dynamic line (branch name, author identity, commit subject, file path) is
//! routed through [`redact_line`] before being written — invariant I3.

use std::collections::BTreeMap;
use std::path::Path;

use git2::{Patch, Repository, Sort};

use crate::context::{ReportContext, redact_line};
use crate::error::ReportError;
use crate::git_support::{
    current_branch_name, format_commit_datetime, open_repository, short_oid, signature_display,
};
use crate::plugin::ReportJob;
use crate::profile;

pub const JOB: ReportJob = ReportJob {
    filename: "21_git_timeline_report.md",
    profiles: profile::GIT_TIMELINE_REPORT_MD,
    description: "Recent commits, contributors, and file churn (read-only Git history).",
    run: write_git_timeline_report,
};

const CONTRIBUTOR_LIMIT: usize = 50;
const RECENT_COMMIT_LIMIT: usize = 30;
const CHURN_COMMIT_WINDOW: usize = 200;
const CHURN_DISPLAY_LIMIT: usize = 50;

fn contributors(repo: &Repository) -> Vec<(String, usize)> {
    let Ok(mut revwalk) = repo.revwalk() else {
        return Vec::new();
    };
    if revwalk.push_head().is_err() {
        return Vec::new();
    }
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for oid in revwalk {
        let Ok(oid) = oid else { continue };
        let Ok(commit) = repo.find_commit(oid) else {
            continue;
        };
        *counts
            .entry(signature_display(&commit.author()))
            .or_insert(0) += 1;
    }
    let mut items: Vec<(String, usize)> = counts.into_iter().collect();
    items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    items
}

fn recent_commits(repo: &Repository, limit: usize) -> Vec<String> {
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
        let author = commit.author();
        let moment = format_commit_datetime(author.when().seconds());
        lines.push(format!(
            "`{}` {moment} — {}: {}",
            short_oid(oid),
            signature_display(&author),
            commit.summary().ok().flatten().unwrap_or("")
        ));
    }
    lines
}

fn file_churn(repo: &Repository, commit_window: usize) -> Vec<(String, i64, usize)> {
    let Ok(mut revwalk) = repo.revwalk() else {
        return Vec::new();
    };
    if revwalk.push_head().is_err() {
        return Vec::new();
    }
    let _ = revwalk.set_sorting(Sort::TIME);

    let mut churn: BTreeMap<String, (i64, usize)> = BTreeMap::new();
    for oid in revwalk.take(commit_window) {
        let Ok(oid) = oid else { continue };
        let Ok(commit) = repo.find_commit(oid) else {
            continue;
        };
        let Ok(tree) = commit.tree() else { continue };
        let parent_tree = commit.parent(0).ok().and_then(|parent| parent.tree().ok());
        let Ok(diff) = repo.diff_tree_to_tree(parent_tree.as_ref(), Some(&tree), None) else {
            continue;
        };
        for idx in 0..diff.deltas().count() {
            let Ok(Some(patch)) = Patch::from_diff(&diff, idx) else {
                continue;
            };
            let path = patch
                .delta()
                .new_file()
                .path()
                .or_else(|| patch.delta().old_file().path())
                .map(|path| path.display().to_string())
                .unwrap_or_default();
            if path.is_empty() {
                continue;
            }
            let Ok((_, insertions, deletions)) = patch.line_stats() else {
                continue;
            };
            let entry = churn.entry(path).or_insert((0, 0));
            entry.0 += (insertions + deletions) as i64;
            entry.1 += 1;
        }
    }
    let mut items: Vec<(String, i64, usize)> = churn
        .into_iter()
        .map(|(path, (amount, touches))| (path, amount, touches))
        .collect();
    items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    items
}

fn write_git_timeline_report(
    ctx: &ReportContext<'_>,
    output_file: &Path,
) -> Result<(), ReportError> {
    let mut out = String::new();
    out.push_str("# Git Timeline Report\n\n");
    out.push_str(&format!(
        "Source root: `{}`\n\n",
        ctx.disclosed_source_root()
    ));
    out.push_str(&format!("Generated: {}\n\n", ctx.plan.generated_at));
    out.push_str("This report uses read-only Git queries and does not change the repository.\n\n");

    let Some(repo) = open_repository(&ctx.source_root) else {
        out.push_str("No `.git` directory was found in the selected root.\n");
        return std::fs::write(output_file, out).map_err(|source| ReportError::Write {
            path: output_file.to_path_buf(),
            source,
        });
    };

    out.push_str("## Repository summary\n\n");

    out.push_str("### Current branch\n\n");
    match current_branch_name(&repo) {
        Some(name) => out.push_str(&format!("- `{}`\n\n", redact_line(&name))),
        None => out.push_str("- not available\n\n"),
    }

    out.push_str("### HEAD commit\n\n");
    match repo.head().ok().and_then(|head| head.peel_to_commit().ok()) {
        Some(commit) => out.push_str(&format!("- `{}`\n\n", short_oid(commit.id()))),
        None => out.push_str("- not available\n\n"),
    }

    out.push_str("### Contributors\n\n");
    let contributors = contributors(&repo);
    if contributors.is_empty() {
        out.push_str("- not available\n\n");
    } else {
        for (author, count) in contributors.iter().take(CONTRIBUTOR_LIMIT) {
            out.push_str(&format!("- `{count:>6}\t{}`\n", redact_line(author)));
        }
        out.push('\n');
    }

    out.push_str("## Last 30 commits\n\n");
    let commits = recent_commits(&repo, RECENT_COMMIT_LIMIT);
    if commits.is_empty() {
        out.push_str("No commits detected.\n");
    } else {
        for line in &commits {
            out.push_str(&format!("- {}\n", redact_line(line)));
        }
    }

    out.push_str("\n## Files with the most churn in the last 200 commits\n\n");
    let churn = file_churn(&repo, CHURN_COMMIT_WINDOW);
    if churn.is_empty() {
        out.push_str("No churn data available.\n");
    } else {
        out.push_str(&format!("{:>10} {:>8}  File\n", "Churn", "Touches"));
        for (path, amount, touches) in churn.iter().take(CHURN_DISPLAY_LIMIT) {
            out.push_str(&redact_line(&format!(
                "{amount:>10} {touches:>8}  {path}\n"
            )));
        }
    }

    std::fs::write(output_file, out).map_err(|source| ReportError::Write {
        path: output_file.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git_support::test_support::{commit_all, init_repo, write_file};

    #[test]
    fn writes_not_a_repository_note_when_no_git_directory_exists() {
        let fixture = crate::test_support::Fixture::new(|root| {
            std::fs::write(root.join("main.py"), "x = 1\n").unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_git_timeline_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("No `.git` directory was found in the selected root."));
    }

    #[test]
    fn writes_contributors_recent_commits_and_churn_with_secret_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let repo = init_repo(dir.path());
        write_file(dir.path(), "main.py", "print(1)\n");
        commit_all(&repo, "init: add API_KEY=sk-super-secret-value to config");
        write_file(dir.path(), "main.py", "print(1)\nprint(2)\n");
        commit_all(&repo, "second commit");

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

        write_git_timeline_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.starts_with("# Git Timeline Report"));
        assert!(content.contains("### Contributors"));
        assert!(content.contains("Test User <test@example.local>"));
        assert!(content.contains("## Last 30 commits"));
        assert!(content.contains("second commit"));
        // Each commit line carries the moment, not just the day: two commits made
        // seconds apart (as these two are) are otherwise indistinguishable in order.
        assert!(
            content.contains(" UTC — Test User"),
            "commit lines must carry hh:mm:ss UTC"
        );
        assert!(content.contains("## Files with the most churn"));
        assert!(content.contains("main.py"));
        assert!(!content.contains("sk-super-secret-value"));
        assert!(content.contains("<REDACTED>"));
    }
}
