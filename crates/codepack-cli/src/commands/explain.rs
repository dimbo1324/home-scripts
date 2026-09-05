//! `codepack explain <file>` — why one file did or did not make it into the export.
//!
//! The export plan already records a `reason` for every file it classified, and
//! `preview` already builds that plan without writing anything. What was missing was a
//! way to ask about *one* path: `preview --list-files` prints what got in, which is the
//! wrong half of the question — a user chasing a missing file needs to know what
//! excluded it, and a user worried about a leak needs to know why something got in.
//!
//! Every answer is a success. "Excluded because it matched a sensitive name" is the
//! explanation working, not a failure, so the exit code stays 0 for all three outcomes
//! and 1 is reserved for actually failing to produce an answer.

use std::path::Path;

use serde::Serialize;

use codepack_engine::explain::VERDICT_NOT_PLANNED;

use crate::cli::ExplainArgs;
use crate::commands::{self, ProjectContext};
use crate::error::Result;
use crate::exit::Outcome;
use crate::output::{self, Format};
use crate::settings::ResolutionTrace;

#[derive(Debug, Serialize)]
pub(crate) struct ExplainReport {
    pub project: String,
    /// The path as the plan spells it (backslash-joined, relative to the project), so
    /// the answer can be matched against `manifest.json` and the plan by eye.
    pub file: String,
    pub profile: String,
    pub safe_mode: String,
    pub diff_mode: String,
    /// `included`, `excluded`, `not_in_diff`, or `not_planned`.
    pub verdict: &'static str,
    /// The plan's own wording where it has one; otherwise an explanation assembled
    /// from what the plan does record about the path's directories.
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_human: Option<String>,
    /// The skipped directory on this path, when one explains a `not_planned` verdict.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped_directory: Option<String>,
    /// Whether the file exists on disk at all. A `not_planned` verdict means something
    /// quite different for a typo than for a file the walk chose not to visit.
    pub exists_on_disk: bool,
    pub resolution: ResolutionTrace,
}

pub(crate) fn run(args: &ExplainArgs, format: Format) -> Result<Outcome> {
    let context = commands::prepare(&args.project)?;
    let report = build(&context, &args.file)?;

    if format.is_json() {
        output::emit_json("explain", &report)?;
    } else {
        print_human(&report);
    }
    Ok(Outcome::Success)
}

pub(crate) fn build(context: &ProjectContext, requested: &Path) -> Result<ExplainReport> {
    let explanation =
        codepack_engine::explain::explain_file(&context.root, &context.config, requested)?;
    Ok(ExplainReport {
        project: context.root.display().to_string(),
        file: explanation.file,
        profile: explanation.profile,
        safe_mode: explanation.safe_mode,
        diff_mode: explanation.diff_mode,
        verdict: explanation.verdict,
        reason: explanation.reason,
        group: explanation.group,
        severity: explanation.severity,
        size: explanation.size,
        size_human: explanation.size.map(codepack_tokens::format_bytes),
        skipped_directory: explanation.skipped_directory,
        exists_on_disk: explanation.exists_on_disk,
        resolution: context.resolution_for_output(),
    })
}

fn print_human(report: &ExplainReport) {
    output::line(format!("Project:   {}", report.project));
    output::line(format!(
        "Settings:  profile={} safe-mode={} diff={}",
        report.profile, report.safe_mode, report.diff_mode
    ));
    output::line("");
    output::line(format!("File:      {}", report.file));
    output::line(format!("Verdict:   {}", report.verdict));
    output::line(format!("Reason:    {}", report.reason));

    if let (Some(group), Some(severity)) = (&report.group, &report.severity) {
        output::line(format!("Group:     {group}"));
        output::line(format!("Severity:  {severity}"));
    }
    if let Some(size_human) = &report.size_human {
        output::line(format!("Size:      {size_human}"));
    }
    if report.verdict == VERDICT_NOT_PLANNED && !report.exists_on_disk {
        output::line("");
        output::line("This path does not exist in the project.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::ResolutionTrace;
    use codepack_core::config::Config;
    use codepack_engine::explain::{VERDICT_EXCLUDED, VERDICT_INCLUDED, VERDICT_NOT_IN_DIFF};

    fn context(root: &Path, safe_mode: &str) -> ProjectContext {
        let config = Config {
            safe_export_mode: safe_mode.to_string(),
            ..Config::default()
        };
        ProjectContext {
            root: root.to_path_buf(),
            config,
            trace: ResolutionTrace::default(),
        }
    }

    /// Commits everything in the tree, so a `uncommitted` diff selection has something
    /// to exclude. Built through `git2`, never a `git` binary (project rule).
    fn commit_everything(root: &Path) {
        use git2::{IndexAddOption, Repository, Signature};

        let repository = Repository::init(root).unwrap();
        let mut index = repository.index().unwrap();
        index.add_all(["*"], IndexAddOption::DEFAULT, None).unwrap();
        index.write().unwrap();
        let tree_id = index.write_tree().unwrap();
        let tree = repository.find_tree(tree_id).unwrap();
        let signature = Signature::now("Test", "test@example.local").unwrap();
        repository
            .commit(Some("HEAD"), &signature, &signature, "seed", &tree, &[])
            .unwrap();
    }

    fn project() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/main.rs"), "fn main() {}\n").unwrap();
        std::fs::write(dir.path().join(".env"), "TOKEN=x\n").unwrap();
        std::fs::create_dir_all(dir.path().join("node_modules/left-pad")).unwrap();
        std::fs::write(
            dir.path().join("node_modules/left-pad/index.js"),
            "module.exports = 1;\n",
        )
        .unwrap();
        dir
    }

    #[test]
    fn an_included_file_is_explained_with_its_group() {
        let dir = project();
        let report = build(&context(dir.path(), "safe"), Path::new("src/main.rs")).unwrap();

        assert_eq!(report.verdict, VERDICT_INCLUDED);
        assert_eq!(report.file, "src\\main.rs");
        assert!(report.group.is_some());
        assert!(report.size.is_some());
        assert!(report.exists_on_disk);
    }

    #[test]
    fn a_file_excluded_by_safe_mode_says_which_rule_excluded_it() {
        let dir = project();
        let report = build(&context(dir.path(), "safe"), Path::new(".env")).unwrap();

        assert_eq!(report.verdict, VERDICT_EXCLUDED);
        // Naming the rule, not merely "a non-empty string": the fallback wording is
        // always non-empty, so a weaker assertion would keep passing if the plan ever
        // stopped saying *why* — which is the whole gap this command closes.
        assert!(
            report.reason.to_lowercase().contains("credential"),
            "expected the credential-filename rule to be named, got {:?}",
            report.reason
        );
        assert_eq!(report.severity.as_deref(), Some("critical"));
    }

    #[test]
    fn a_file_outside_the_diff_selection_is_not_reported_as_included() {
        // The `PR Review` preset makes `uncommitted` an everyday setting: the rules
        // include a committed, unmodified file, but the copy step will skip it because
        // it is not in the diff selection. Saying "included" would be a confident wrong
        // answer about a file that reaches no bundle.
        let dir = project();
        commit_everything(dir.path());

        let mut context = context(dir.path(), "safe");
        context.config.diff_export_mode = "uncommitted".to_string();

        let report = build(&context, Path::new("src/main.rs")).unwrap();

        assert_eq!(report.verdict, VERDICT_NOT_IN_DIFF, "{}", report.reason);
        assert!(report.reason.contains("diff"), "{}", report.reason);
    }

    #[test]
    fn an_uncommitted_file_is_included_under_the_same_diff_mode() {
        // The other half of the previous test: `not_in_diff` must reflect the diff
        // selection, not simply "this mode always says no".
        let dir = project();
        commit_everything(dir.path());
        std::fs::write(dir.path().join("src/fresh.rs"), "fn fresh() {}\n").unwrap();

        let mut context = context(dir.path(), "safe");
        context.config.diff_export_mode = "uncommitted".to_string();

        let report = build(&context, Path::new("src/fresh.rs")).unwrap();
        assert_eq!(report.verdict, VERDICT_INCLUDED, "{}", report.reason);
    }

    #[test]
    fn a_file_under_a_skipped_directory_is_told_which_directory() {
        let dir = project();
        let report = build(
            &context(dir.path(), "safe"),
            Path::new("node_modules/left-pad/index.js"),
        )
        .unwrap();

        assert_eq!(report.verdict, VERDICT_NOT_PLANNED);
        assert!(
            report
                .skipped_directory
                .as_deref()
                .is_some_and(|entry| entry.contains("node_modules")),
            "reason was {:?}",
            report.reason
        );
    }

    #[test]
    fn a_path_that_does_not_exist_gets_an_answer_not_an_error() {
        let dir = project();
        let report = build(&context(dir.path(), "safe"), Path::new("src/nope.rs")).unwrap();

        assert_eq!(report.verdict, VERDICT_NOT_PLANNED);
        assert!(!report.exists_on_disk);
        assert!(report.reason.contains("no such file"), "{}", report.reason);
    }

    #[test]
    fn absolute_relative_and_plan_spellings_all_agree() {
        let dir = project();
        let context = context(dir.path(), "safe");

        let relative = build(&context, Path::new("src/main.rs")).unwrap();
        let absolute = build(&context, &dir.path().join("src/main.rs")).unwrap();
        let plan_form = build(&context, Path::new("src\\main.rs")).unwrap();
        let dotted = build(&context, Path::new("./src/main.rs")).unwrap();

        for other in [&absolute, &plan_form, &dotted] {
            assert_eq!(other.file, relative.file);
            assert_eq!(other.verdict, relative.verdict);
        }
    }

    #[test]
    fn a_path_outside_the_project_is_refused_rather_than_answered_about() {
        let dir = project();
        let outside = tempfile::tempdir().unwrap();
        let error = build(
            &context(dir.path(), "safe"),
            &outside.path().join("elsewhere.rs"),
        )
        .unwrap_err();

        assert!(error.to_string().contains("not inside"), "{error}");
    }

    #[test]
    fn a_traversal_attempt_is_refused() {
        let dir = project();
        let error = build(&context(dir.path(), "safe"), Path::new("../secrets.txt")).unwrap_err();
        assert!(error.to_string().contains("escapes"), "{error}");
    }
}
