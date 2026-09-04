//! Pipeline step 6 ("analytics"): re-plans over the **copy**, runs the security scanner
//! exactly once, assembles [`codepack_reports::context::ReportContext`], and runs the
//! full report catalog plus `PROJECT_PROFILE.json`/`REPORT_PLUGINS.json`. Ported from
//! legacy `exporter.py`'s analytics step, which is a thin sequencing layer over
//! `reports/insights/orchestrator.py` and `services/security_scanner.py`.
//!
//! ## Design: a second, cheap `build_export_plan` pass over the copy
//!
//! Step 1's [`crate::plan::PlanOutcome::export_plan`] describes the *source* tree
//! before safety/diff filtering; some of those included files never actually made it
//! into `paths.project_dir` (the copy step, pipeline step 2, may have dropped them for
//! safety or diff reasons). Re-planning over `paths.project_dir` itself — rather than
//! trying to derive "what really got copied" by intersecting step 1's plan with step
//! 2's [`codepack_core::CopyStats`] — reflects what actually survived into the copy,
//! and lets this crate reuse `codepack_reports::context::Inventory::from_plan` and every
//! report job unchanged, without adding new API surface to the already-shipped,
//! reviewed `codepack-reports` crate (`task-checklist.md`'s S9 design decision).
//!
//! This is the **only** place in the whole pipeline that calls
//! `codepack_security::scan_project` — `codepack_reports::reports::security_scan::JOB`
//! is a thin adapter over an already-computed [`ScanResult`], it never scans itself.

use std::path::PathBuf;

use std::path::Path;

use codepack_core::config::Config;
use codepack_core::{CancellationToken, ExportPaths};
use codepack_diff::DiffSelection;
use codepack_reports::context::{Inventory, ReportContext};
use codepack_reports::{ReportJob, RunSummary};
use codepack_scanner::{ExportIgnoreRules, ExportPlan, ScanOptions, build_export_plan};
use codepack_security::cache::FileScanCache;
use codepack_security::{
    Redactor, ScanOptions as SecurityScanOptions, ScanResult, SecurityOptions,
    scan_project_with_options,
};
use codepack_storage::Connection;

use codepack_security::should_skip_file_for_safety;

use crate::error::Result;
use crate::relpath::to_relative_path;
use crate::scan_cache::SqliteScanCache;

/// Everything later steps (manifest writing, storage, the step-8 dashboard-refresh
/// hook) need from this step. `inventory`/`replan` are owned copies of this function's
/// own internal re-plan-over-the-copy, kept alive past this function's return so Group
/// Z's `on_plan_ready` closure can rebuild an equivalent [`ReportContext`] for
/// `REPORT_DASHBOARD.html`'s mid-archiving refresh without re-planning a third time.
pub struct AnalyticsOutcome {
    pub scan_result: ScanResult,
    pub run_summary: RunSummary,
    pub inventory: Inventory,
    pub replan: ExportPlan,
}

fn full_job_catalog() -> Vec<ReportJob> {
    // Legacy's job #0 leads the catalog, so `REPORT_PLUGINS.json` lists it first and
    // `reports/insights/00_project_profile.json` exists before any later report can
    // reference it.
    std::iter::once(codepack_reports::project_profile::JOB)
        .chain(codepack_reports::group_a_jobs())
        .chain(codepack_reports::group_b_jobs())
        .chain(codepack_reports::group_c_jobs())
        .chain(codepack_reports::group_d_jobs())
        .chain(codepack_reports::group_e_jobs())
        .chain(codepack_reports::group_f_jobs())
        .chain(codepack_reports::group_h_human_jobs())
        .chain(codepack_reports::group_g_finish_jobs())
        .collect()
}

/// Runs pipeline step 6. `diff_selection` is [`crate::plan::PlanOutcome::diff_selection`]
/// from step 1, threaded through so `ReportContext.diff` reflects the same selection the
/// copy step honored — not re-derived a second time.
///
/// Never turns a single report job's failure into a hard `Err` from this function
/// (`codepack_reports::run_reports`'s own fault tolerance, BLUEPRINT §A.7); only a
/// genuine setup failure (the re-plan itself, or `scan_project` erroring on
/// cancellation) propagates.
pub fn run_analytics(
    conn: &mut Connection,
    paths: &ExportPaths,
    config: &Config,
    diff_selection: &DiffSelection,
    cancel: &CancellationToken,
    log: &dyn Fn(&str),
) -> Result<AnalyticsOutcome> {
    let scan_options = ScanOptions::from(config);
    let export_rules =
        ExportIgnoreRules::from_project_and_config(&paths.project_dir, &scan_options);
    // The copy step already applied the same safe-mode policy, so nothing here can be
    // newly excluded — the classifier is passed anyway so this re-plan and the step-1
    // plan are produced by identical rules rather than by two subtly different ones.
    let safe_mode = config.normalized_safe_export_mode().to_string();
    let safety = move |relative_path: &Path| {
        let decision = should_skip_file_for_safety(relative_path, &safe_mode);
        decision
            .skip
            .then_some((decision.reason, decision.severity))
    };
    let replan = build_export_plan(
        &paths.project_dir,
        &scan_options,
        &export_rules,
        &safety,
        cancel,
    )?;

    let relative_files: Vec<PathBuf> = replan
        .included_files
        .iter()
        .map(|planned| to_relative_path(&planned.relative_path))
        .collect();

    let security_options = SecurityOptions::from(config);
    let redactor = Redactor::new(config.redaction_labels);
    // Loaded before the scan and written back after it: the pass is parallel and a
    // `Connection` is not `Sync`, so the workers read from memory. A cache failure is
    // never allowed to fail an export — it is an optimisation, and the scan can always
    // just do the work.
    let cache = match SqliteScanCache::load(conn) {
        Ok(cache) => Some(cache),
        Err(error) => {
            log(&format!(
                "scan cache unavailable, scanning everything: {error}"
            ));
            None
        }
    };
    let scan_result = scan_project_with_options(
        &paths.project_dir,
        &relative_files,
        security_options.max_bytes_per_file,
        cancel,
        &SecurityScanOptions {
            // Labels reach the scanner's own artifacts too, not only the text dump and
            // the git reports (Q34). With `redaction_labels` off — the default — this
            // redactor is the plain one and every message is byte for byte what it was.
            redactor: Some(&redactor),
            strict_token_checksums: config.strict_token_checksums,
            cache: cache.as_ref().map(|cache| cache as &dyn FileScanCache),
        },
    )?;
    if let Some(cache) = cache
        && let Err(error) = cache.flush(conn)
    {
        log(&format!("scan cache not updated: {error}"));
    }

    // `.codepack-allow` is read from the **source** project, not from the staging copy:
    // it is the user's own reviewed-findings file, and it applies to the bundle the same
    // way it applies to `scan` and `verify` (Q26). A missing file leaves everything
    // untouched, so a project without one pays nothing for this.
    let screened = codepack_security::allow::screen_project(&paths.source_root, &scan_result)?;
    if screened.has_suppressions() {
        // Never silently dropped: the run log says how many and by whose authority.
        log(&format!(
            "security scan: {} finding(s) accepted by {}",
            screened.suppressed.len(),
            screened
                .allowlist_path
                .as_deref()
                .unwrap_or_else(|| Path::new(codepack_core::ALLOWLIST_FILE_NAME))
                .display()
        ));
    }
    let scan_result = screened.to_result();

    let inventory = Inventory::from_plan(&replan);
    let profile = config.normalized_export_profile();

    let ctx = ReportContext {
        source_root: paths.source_root.clone(),
        staging_root: paths.project_dir.clone(),
        inventory: &inventory,
        plan: &replan,
        scan: Some(&scan_result),
        diff: Some(diff_selection),
        config,
        cancel,
        profile,
    };

    let jobs = full_job_catalog();

    codepack_reports::write_report_plugins_json(&jobs, &paths.insights_dir)?;

    let run_summary = codepack_reports::run_reports(&jobs, &ctx, &paths.insights_dir);

    // Legacy's `project_profile_job` writes the catalog file and then copies it to the
    // bundle root (`shutil.copyfile`), rather than building the profile twice.
    let profile_in_catalog = paths.insights_dir.join("00_project_profile.json");
    if !profile_in_catalog.is_file() {
        // `run_reports` is fault tolerant: a failing job writes ERROR_<name>.txt and the
        // run continues, and cancellation stops the catalog before any job runs. Either
        // way `PROJECT_PROFILE.json` — an artifact named in invariant I5 — is simply
        // absent from the bundle. Legacy was equally quiet about it; being quiet about a
        // missing contract artifact is not something to reproduce.
        log(
            "PROJECT_PROFILE.json not written: report job 00_project_profile.json produced no file",
        );
    }
    if profile_in_catalog.is_file() {
        std::fs::copy(&profile_in_catalog, &paths.project_profile_file).map_err(|source| {
            crate::error::EngineError::Io {
                path: paths.project_profile_file.clone(),
                source,
            }
        })?;
    }
    log(&format!(
        "analytics: {} report(s) succeeded, {} failed, {} skipped{}",
        run_summary.succeeded.len(),
        run_summary.failed.len(),
        run_summary.skipped.len(),
        if run_summary.cancelled {
            " (cancelled)"
        } else {
            ""
        }
    ));

    Ok(AnalyticsOutcome {
        scan_result,
        run_summary,
        inventory,
        replan,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::copy::copy_project;
    use crate::paths::build_export_paths;
    use crate::plan::run_export_plan;
    use std::collections::HashMap;
    use std::fs;

    fn no_log(_: &str) {}

    fn staged_paths(source: &std::path::Path, output: &std::path::Path) -> ExportPaths {
        let paths = build_export_paths(source, output);
        let config = Config::default();
        let cancel = CancellationToken::new();
        let outcome = run_export_plan(&paths, &config, &HashMap::new(), None, &cancel).unwrap();
        copy_project(
            &outcome.export_plan,
            outcome.include_relative_paths.as_ref(),
            config.normalized_safe_export_mode(),
            source,
            &paths.project_dir,
            &cancel,
            &no_log,
        )
        .unwrap();
        fs::create_dir_all(&paths.insights_dir).unwrap();
        paths
    }

    #[test]
    fn a_secret_in_the_copy_produces_a_real_security_scan_and_expected_artifacts() {
        // A secret embedded in an ordinary `.py` file, not `.env`: `Config::default()`'s
        // safe export mode strips `.env`-shaped files during the copy step entirely, so
        // a secret placed there would never reach the copy this step re-plans over.
        let source = tempfile::tempdir().unwrap();
        fs::write(
            source.path().join("config.py"),
            "API_KEY = \"sk-super-secret-value\"\n",
        )
        .unwrap();
        fs::write(source.path().join("main.py"), "print(1)\n").unwrap();
        let output = tempfile::tempdir().unwrap();
        let paths = staged_paths(source.path(), output.path());
        let config = Config::default();
        let diff_selection = DiffSelection {
            mode: "all".to_string(),
            base: "full export".to_string(),
            paths: None,
            files: Vec::new(),
            warning: None,
        };

        let db = tempfile::tempdir().unwrap();
        let mut conn = codepack_storage::open(&db.path().join("history.db")).unwrap();
        let outcome = run_analytics(
            &mut conn,
            &paths,
            &config,
            &diff_selection,
            &CancellationToken::new(),
            &no_log,
        )
        .unwrap();

        assert!(!outcome.scan_result.findings.is_empty());
        assert!(paths.insights_dir.join("06_security_scan.txt").is_file());
        assert!(paths.insights_dir.join("06_security_scan.json").is_file());
        assert!(paths.insights_dir.join("06_security_scan.sarif").is_file());
        assert!(paths.project_profile_file.is_file());
        assert!(paths.insights_dir.join("REPORT_PLUGINS.json").is_file());
        assert!(paths.insights_dir.join("REPORT_DASHBOARD.html").is_file());
    }

    #[test]
    fn minimal_profile_still_produces_a_gated_subset_without_erroring() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("main.py"), "print(1)\n").unwrap();
        let output = tempfile::tempdir().unwrap();
        let paths = staged_paths(source.path(), output.path());
        let config = Config {
            export_profile: "minimal".to_string(),
            ..Config::default()
        };
        let diff_selection = DiffSelection {
            mode: "all".to_string(),
            base: "full export".to_string(),
            paths: None,
            files: Vec::new(),
            warning: None,
        };

        let db = tempfile::tempdir().unwrap();
        let mut conn = codepack_storage::open(&db.path().join("history.db")).unwrap();
        let outcome = run_analytics(
            &mut conn,
            &paths,
            &config,
            &diff_selection,
            &CancellationToken::new(),
            &no_log,
        )
        .unwrap();

        assert!(!outcome.run_summary.cancelled);
        assert!(paths.project_profile_file.is_file());
    }
}
