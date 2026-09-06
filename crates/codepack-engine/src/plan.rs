//! Pipeline step 1 ("plan"): assembles the export plan and the diff selection, writes
//! `28_export_plan.json`/`.md` and `29_export_comparison_report.md`, and folds
//! per-file overrides into both. Ported from legacy `exporter.py::run`'s step-1 setup
//! (`ExportIgnoreRules` construction, `resolve_diff_selection`,
//! `combined_selected_paths`, `build_export_plan`).
//!
//! `previous_snapshot` is a real parameter, not hardcoded `None`: this crate has no
//! storage dependency yet (stage S9's Group Z wires `codepack-storage`'s baseline
//! lookup through this same parameter once that crate exists).
//!
//! Legacy's `incremental_selection` branch of `combined_selected_paths` is permanently
//! dead code (never ported — see `codepack-diff`'s own module doc) and is not
//! reproduced here: [`combined_selected_paths`] only ever has zero or one active
//! selector (`diff_selection.paths`), never an intersection of several.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use codepack_core::config::Config;
use codepack_core::{CancellationToken, ExportPaths};
use codepack_diff::{
    DiffOptions, DiffSelection, Snapshot, resolve_diff_selection, write_diff_report,
};
use codepack_scanner::{
    ExportIgnoreRules, ExportPlan, ScanOptions, build_export_plan, should_consider_text_file,
    write_export_plan_files,
};

use codepack_security::should_skip_file_for_safety;

use crate::error::Result;
use crate::ignored_dirs::ignored_dir_names_for;

/// Everything step 1 produces that later steps (copy, reports, archiving) need.
#[derive(Debug, Clone)]
pub struct PlanOutcome {
    pub export_plan: ExportPlan,
    pub diff_selection: DiffSelection,
    /// The casefolded ignored-directory-name set used for this run — the same set
    /// [`codepack_diff::resolve_diff_selection`] and any later diff/snapshot call need,
    /// computed once here so every step agrees on it.
    pub ignored_dir_names: HashSet<String>,
    /// `None` means "no path filter" (copy everything the plan included); `Some` is the
    /// backslash-joined relative-path set the copy step should restrict itself to,
    /// after folding in `file_overrides`.
    pub include_relative_paths: Option<HashSet<String>>,
    /// How many files the "fit to budget" pass (BLUEPRINT §B.3) moved out of
    /// `included_files`. Always `0` unless `Config::token_budget` is set.
    pub dropped_by_budget: usize,
}

/// Runs pipeline step 1. `file_overrides` mirrors legacy's `file_overrides: dict[str,
/// bool]`: a relative path (either separator style; normalized internally) mapped to
/// `true` (force-include) or `false` (force-exclude). Applied in the same two places
/// legacy applies it: into [`ExportIgnoreRules`] before planning, and into the
/// diff-selection path set afterward.
pub fn run_export_plan(
    paths: &ExportPaths,
    config: &Config,
    file_overrides: &HashMap<String, bool>,
    previous_snapshot: Option<&Snapshot>,
    cancel: &CancellationToken,
) -> Result<PlanOutcome> {
    let mut outcome = plan_export(
        &paths.source_root,
        config,
        file_overrides,
        previous_snapshot,
        cancel,
    )?;

    // `28_export_plan.json` names the source root too, and it goes into the bundle like
    // every other artifact. `codepack-scanner` builds the plan and has no business
    // knowing about a disclosure policy, so the decision is applied here, where the
    // config already is. The field is a label — nothing reads it back as a path — so
    // setting it changes what is written and nothing else.
    //
    // This was missed when the rest of audit No. 21 was done, and the bundle-wide test
    // that should have caught it compared a raw Windows path against JSON, where every
    // separator is doubled. The test now checks both spellings.
    outcome.export_plan.source_root =
        codepack_core::config::disclosed_root(config, &paths.source_root, &paths.project_name);

    write_export_plan_files(
        &outcome.export_plan,
        &paths.insights_dir.join("28_export_plan.json"),
        &paths.insights_dir.join("28_export_plan.md"),
    )?;
    write_diff_report(
        &paths.insights_dir.join("29_export_comparison_report.md"),
        &outcome.diff_selection,
    )?;

    Ok(outcome)
}

/// Step 1 without writing anything.
///
/// [`run_export_plan`] is this plus the two report files, which is the right shape for
/// the pipeline but the wrong one for a caller that only wants to know what *would* be
/// exported — `codepack-cli`'s `preview` must not write into the user's project
/// (invariant I2 makes that non-negotiable for the source tree, and writing a report
/// nobody asked for is unwelcome anywhere).
///
/// Takes `source_root` rather than [`ExportPaths`] precisely because a preview has no
/// output directory to derive them from.
pub fn plan_export(
    source_root: &Path,
    config: &Config,
    file_overrides: &HashMap<String, bool>,
    previous_snapshot: Option<&Snapshot>,
    cancel: &CancellationToken,
) -> Result<PlanOutcome> {
    let ignored_dir_names = ignored_dir_names_for(source_root, config);

    let scan_options = ScanOptions::from(config);
    let mut export_rules = ExportIgnoreRules::from_project_and_config(source_root, &scan_options);
    for (relative_path, include) in file_overrides {
        if *include {
            export_rules.add_always_include_file(relative_path);
        } else {
            export_rules.add_file_rule(relative_path);
        }
    }

    // Safe-export-mode classification is the engine's to supply: `codepack-scanner`
    // deliberately keeps no dependency on `codepack-security` (see
    // `codepack_scanner::SafetyClassifier`). Without this the plan reported `.env` as
    // included/info while the copy step correctly excluded it — a report that
    // contradicted the bundle it described.
    let safe_mode = config.normalized_safe_export_mode().to_string();
    let safety = move |relative_path: &Path| {
        let decision = should_skip_file_for_safety(relative_path, &safe_mode);
        decision
            .skip
            .then_some((decision.reason, decision.severity))
    };
    let mut export_plan =
        build_export_plan(source_root, &scan_options, &export_rules, &safety, cancel)?;

    // BLUEPRINT §B.3. No-op unless the caller set a budget, so the default export path
    // is unchanged; when set, the plan written below already reflects the selection, so
    // the copy step and every report see one consistent file list.
    let dropped_by_budget = crate::budget::apply_token_budget(
        &mut export_plan,
        source_root,
        config,
        &export_rules,
        cancel,
    );

    let diff_options = DiffOptions::from(config);
    let diff_selection = resolve_diff_selection(
        source_root,
        &diff_options,
        previous_snapshot,
        &ignored_dir_names,
        &should_consider_text_file,
        cancel,
    )?;

    let include_relative_paths = combined_selected_paths(&diff_selection, file_overrides);

    Ok(PlanOutcome {
        export_plan,
        diff_selection,
        ignored_dir_names,
        include_relative_paths,
        dropped_by_budget,
    })
}

/// Ported from legacy `combined_selected_paths`, minus the permanently-dead
/// `incremental_selection` branch (see the module doc comment). `file_overrides` keys
/// are normalized to backslash-joined form here, matching
/// [`codepack_diff::DiffSelection::paths`]'s own join convention.
fn combined_selected_paths(
    diff_selection: &DiffSelection,
    file_overrides: &HashMap<String, bool>,
) -> Option<HashSet<String>> {
    let mut result = diff_selection.paths.clone()?;
    for (relative_path, include) in file_overrides {
        let key = relative_path.replace('/', "\\");
        if *include {
            result.insert(key);
        } else {
            result.remove(&key);
        }
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::build_export_paths;

    fn config_with_mode(diff_export_mode: &str) -> Config {
        Config {
            diff_export_mode: diff_export_mode.to_string(),
            ..Config::default()
        }
    }

    fn stage(source_root: &std::path::Path, output_root: &std::path::Path) -> ExportPaths {
        build_export_paths(source_root, output_root)
    }

    #[test]
    fn all_mode_has_no_path_filter_and_includes_every_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.py"), "print(1)").unwrap();
        let output = tempfile::tempdir().unwrap();
        let paths = stage(dir.path(), output.path());
        let config = config_with_mode("all");

        let outcome = run_export_plan(
            &paths,
            &config,
            &HashMap::new(),
            None,
            &CancellationToken::new(),
        )
        .unwrap();

        assert!(outcome.include_relative_paths.is_none());
        assert_eq!(outcome.export_plan.included_files.len(), 1);
    }

    #[test]
    fn writes_plan_and_diff_report_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.py"), "print(1)").unwrap();
        let output = tempfile::tempdir().unwrap();
        let paths = stage(dir.path(), output.path());
        let config = config_with_mode("all");

        run_export_plan(
            &paths,
            &config,
            &HashMap::new(),
            None,
            &CancellationToken::new(),
        )
        .unwrap();

        assert!(paths.insights_dir.join("28_export_plan.json").is_file());
        assert!(paths.insights_dir.join("28_export_plan.md").is_file());
        assert!(
            paths
                .insights_dir
                .join("29_export_comparison_report.md")
                .is_file()
        );
    }

    #[test]
    fn file_override_force_include_rescues_an_exportignore_excluded_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".exportignore"), "*.log\n").unwrap();
        std::fs::write(dir.path().join("app.log"), "x").unwrap();
        let output = tempfile::tempdir().unwrap();
        let paths = stage(dir.path(), output.path());
        let config = config_with_mode("all");

        let mut overrides = HashMap::new();
        overrides.insert("app.log".to_string(), true);

        let outcome =
            run_export_plan(&paths, &config, &overrides, None, &CancellationToken::new()).unwrap();

        let included: Vec<&str> = outcome
            .export_plan
            .included_files
            .iter()
            .map(|f| f.relative_path.as_str())
            .collect();
        assert!(included.contains(&"app.log"));
    }

    #[test]
    fn file_override_force_exclude_removes_a_file_that_would_otherwise_be_included() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.py"), "x").unwrap();
        let output = tempfile::tempdir().unwrap();
        let paths = stage(dir.path(), output.path());
        let config = config_with_mode("all");

        let mut overrides = HashMap::new();
        overrides.insert("main.py".to_string(), false);

        let outcome =
            run_export_plan(&paths, &config, &overrides, None, &CancellationToken::new()).unwrap();

        assert!(outcome.export_plan.included_files.is_empty());
    }

    #[test]
    fn last_export_mode_override_forces_in_a_file_the_diff_would_otherwise_treat_as_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("stable.py"), "same content").unwrap();
        let stable_hash = codepack_diff::hash_file(&dir.path().join("stable.py")).unwrap();

        let output = tempfile::tempdir().unwrap();
        let paths = stage(dir.path(), output.path());
        let config = config_with_mode("last_export");

        let previous = Snapshot {
            files: [(
                "stable.py".to_string(),
                codepack_diff::SnapshotFile {
                    rel_path: "stable.py".to_string(),
                    sha256: stable_hash,
                    size: 12,
                    loc: 1,
                    mtime_ns: 0,
                },
            )]
            .into_iter()
            .collect(),
        };

        let mut overrides = HashMap::new();
        overrides.insert("stable.py".to_string(), true);

        let outcome = run_export_plan(
            &paths,
            &config,
            &overrides,
            Some(&previous),
            &CancellationToken::new(),
        )
        .unwrap();

        let combined = outcome.include_relative_paths.unwrap();
        assert!(combined.contains("stable.py"));
    }

    #[test]
    fn combined_selected_paths_returns_none_when_diff_selection_is_unlimited() {
        let selection = DiffSelection {
            mode: "all".to_string(),
            base: "полный экспорт".to_string(),
            paths: None,
            files: Vec::new(),
            warning: None,
        };
        assert!(combined_selected_paths(&selection, &HashMap::new()).is_none());
    }

    #[test]
    fn combined_selected_paths_applies_overrides_on_top_of_a_limited_selection() {
        let mut paths: HashSet<String> = HashSet::new();
        paths.insert("keep.py".to_string());
        paths.insert("drop.py".to_string());
        let selection = DiffSelection {
            mode: "uncommitted".to_string(),
            base: "рабочая копия".to_string(),
            paths: Some(paths),
            files: Vec::new(),
            warning: None,
        };

        let mut overrides = HashMap::new();
        overrides.insert("drop.py".to_string(), false);
        overrides.insert("added.py".to_string(), true);

        let combined = combined_selected_paths(&selection, &overrides).unwrap();
        assert!(combined.contains("keep.py"));
        assert!(!combined.contains("drop.py"));
        assert!(combined.contains("added.py"));
    }
}
