//! `codepack scan` — the security scanner on its own.
//!
//! This is the command a CI pipeline runs on every push: it answers "does this project
//! contain secrets?" without producing a bundle. It is also the command that gives exit
//! code 3 its meaning.

mod history;
mod render;
mod report;
mod screening;

// The command's surface, unchanged by the split: `commands::scan::X` still resolves for
// every X the rest of this binary uses, so nothing outside this directory moved.
pub(crate) use history::{build_history, build_history_with_cancel};
pub(crate) use report::ScanReport;
pub(crate) use screening::BaselineOptions;

use codepack_core::CancellationToken;
use codepack_core::config::Config;
use codepack_security::{ScanResult, SecurityOptions, scan_project};

use crate::cli::{ScanArgs, SeverityArg};
use crate::commands::{self, ProjectContext};
use crate::error::Result;
use crate::exit::Outcome;
use crate::output::{self, Format};

use history::Origins;
use render::{print_human, write_sarif};
use report::assemble;
use screening::screen_all;

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

    // Not a silent skip: a staged entry whose path climbs out of the tree is a fact
    // about the repository, and a scan that quietly did not read it must say so, or
    // "nothing found" covers less than the reader believes.
    if staged.unsafe_paths() > 0 {
        crate::output::note(format!(
            "WARNING: {} staged entr(ies) named a path outside the working tree and were \
             NOT scanned. A repository whose index carries such a name is worth a look.",
            staged.unsafe_paths()
        ));
    }

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

/// Shared with the engine and `codepack-sanitize` — see
/// [`codepack_core::relative_from_stored`], which validates as well as rebuilds
/// (audit No. 23). An unsafe path resolves to the empty path and the scan simply finds
/// nothing at it.
fn to_relative_path(relative: &str) -> std::path::PathBuf {
    codepack_core::relative_from_stored(relative).unwrap_or_default()
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
            history::display_of(std::path::Path::new("src/.env")),
            "the scanner's spelling and this module's have drifted"
        );
    }
}
