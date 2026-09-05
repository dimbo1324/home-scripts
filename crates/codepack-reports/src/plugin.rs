//! [`ReportJob`]/[`run_reports`]: the flat plugin table and fault-tolerant runner,
//! ported from legacy `reports/insights/plugins.py`/`orchestrator.py`'s per-plugin
//! loop. A job's own `run` returning `Err`, *or* genuinely panicking, is caught here
//! and turned into an `ERROR_<name>.txt` artifact — the rest of the run continues
//! either way (BLUEPRINT §A.7's fault-tolerance rule; unlike legacy's exception-blind
//! `except Exception`, a Rust `panic!` does not itself unwind past a Python-style
//! `try`, so [`std::panic::catch_unwind`] is required to reach parity).

use std::fs;
use std::path::Path;

use rayon::prelude::*;

use crate::context::ReportContext;
use crate::error::ReportError;
use crate::profile;

pub struct ReportJob {
    pub filename: &'static str,
    pub profiles: &'static [&'static str],
    pub description: &'static str,
    pub run: fn(&ReportContext<'_>, &Path) -> Result<(), ReportError>,
}

impl ReportJob {
    pub fn should_run(&self, profile: &str) -> bool {
        profile::should_run(profile, self.profiles)
    }
}

#[derive(Debug, Clone, Default)]
pub struct RunSummary {
    pub succeeded: Vec<&'static str>,
    pub failed: Vec<(&'static str, String)>,
    pub skipped: Vec<&'static str>,
    pub cancelled: bool,
    /// Set when a `ERROR_<name>.txt` diagnostic itself could not be written — best
    /// effort, never causes the run to stop early.
    pub diagnostic_write_failures: Vec<&'static str>,
}

impl RunSummary {
    /// Folds another phase's summary into this one, keeping phase order.
    ///
    /// The catalog is run in phases rather than as one list (see
    /// [`run_reports_parallel`]), and a caller wants one summary describing all of it.
    pub fn absorb(&mut self, other: RunSummary) {
        self.succeeded.extend(other.succeeded);
        self.failed.extend(other.failed);
        self.skipped.extend(other.skipped);
        self.diagnostic_write_failures
            .extend(other.diagnostic_write_failures);
        self.cancelled |= other.cancelled;
    }
}

/// What one job did, before the sequential fold turns it into a [`RunSummary`].
enum JobOutcome {
    /// Cancellation was already observed when this job came up.
    NotRun,
    Skipped,
    Succeeded,
    Failed(String),
}

/// Runs every job in `jobs`, in order, against `ctx`, writing each job's output under
/// `out_dir`. Skips a job whose profile set does not match `ctx.profile`; stops (but
/// does not fail) the remaining jobs once cancellation is observed between jobs.
/// A single job's failure — `Err` or panic — never aborts the run.
pub fn run_reports(jobs: &[ReportJob], ctx: &ReportContext<'_>, out_dir: &Path) -> RunSummary {
    let mut summary = RunSummary::default();

    for job in jobs {
        if ctx.cancel.is_cancelled() {
            summary.cancelled = true;
            break;
        }
        if !job.should_run(ctx.profile) {
            summary.skipped.push(job.filename);
            continue;
        }

        let output_file = out_dir.join(job.filename);
        let run = job.run;
        let outcome =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(ctx, &output_file)));

        match outcome {
            Ok(Ok(())) => summary.succeeded.push(job.filename),
            Ok(Err(err)) => {
                record_failure(&mut summary, out_dir, job.filename, err.to_string());
            }
            Err(payload) => {
                record_failure(
                    &mut summary,
                    out_dir,
                    job.filename,
                    panic_message(payload.as_ref()),
                );
            }
        }
    }

    summary
}

/// [`run_reports`] with the jobs run concurrently.
///
/// Only for jobs that are genuinely independent. Most of the catalog is: each job writes
/// one file of its own and reads nothing but `ctx`. The exceptions are real, so a caller
/// must keep them in their own phases — `REPORT_DASHBOARD.html` reads
/// `22_project_health_report.md` and `06_security_scan.json` as already-written
/// siblings, and is documented as having to run last.
///
/// The summary is assembled from the outcomes **in job order**, not in completion order,
/// so a run's log reads the same whichever thread finished first. `ERROR_<name>.txt`
/// files are written during that sequential fold for the same reason.
pub fn run_reports_parallel(
    jobs: &[ReportJob],
    ctx: &ReportContext<'_>,
    out_dir: &Path,
) -> RunSummary {
    let outcomes: Vec<(&'static str, JobOutcome)> = jobs
        .par_iter()
        .map(|job| {
            if ctx.cancel.is_cancelled() {
                return (job.filename, JobOutcome::NotRun);
            }
            if !job.should_run(ctx.profile) {
                return (job.filename, JobOutcome::Skipped);
            }
            let output_file = out_dir.join(job.filename);
            let run = job.run;
            let outcome =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(ctx, &output_file)));
            match outcome {
                Ok(Ok(())) => (job.filename, JobOutcome::Succeeded),
                Ok(Err(err)) => (job.filename, JobOutcome::Failed(err.to_string())),
                Err(payload) => (
                    job.filename,
                    JobOutcome::Failed(panic_message(payload.as_ref())),
                ),
            }
        })
        .collect();

    let mut summary = RunSummary::default();
    for (filename, outcome) in outcomes {
        match outcome {
            JobOutcome::NotRun => summary.cancelled = true,
            JobOutcome::Skipped => summary.skipped.push(filename),
            JobOutcome::Succeeded => summary.succeeded.push(filename),
            JobOutcome::Failed(message) => {
                record_failure(&mut summary, out_dir, filename, message);
            }
        }
    }

    summary
}

fn record_failure(
    summary: &mut RunSummary,
    out_dir: &Path,
    filename: &'static str,
    message: String,
) {
    if write_error_file(out_dir, filename, &message).is_err() {
        summary.diagnostic_write_failures.push(filename);
    }
    summary.failed.push((filename, message));
}

/// Legacy: `safe_filename = filename.replace("/", "_").replace("\\", "_")`, then
/// `ERROR_{safe_filename}.txt` — note this deliberately does **not** strip the
/// original extension, so e.g. `01_summary.txt` yields `ERROR_01_summary.txt.txt`.
fn write_error_file(out_dir: &Path, filename: &str, message: &str) -> std::io::Result<()> {
    let sanitized = filename.replace(['/', '\\'], "_");
    let error_path = out_dir.join(format!("ERROR_{sanitized}.txt"));
    let body = format!("Failed to create {filename}\n\n{message}\n");
    fs::write(error_path, body)
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "report job panicked with a non-string payload".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{Inventory, ReportContext};
    use codepack_core::CancellationToken;
    use codepack_core::config::Config;
    use codepack_scanner::{ExportIgnoreRules, ScanOptions, build_export_plan};

    fn fixture_ctx(
        dir: &std::path::Path,
    ) -> (codepack_scanner::ExportPlan, Config, CancellationToken) {
        let plan = build_export_plan(
            dir,
            &ScanOptions::default(),
            &ExportIgnoreRules::default(),
            &codepack_scanner::no_safety_classification,
            &CancellationToken::new(),
        )
        .unwrap();
        (plan, Config::default(), CancellationToken::new())
    }

    fn ok_job(filename: &'static str, profiles: &'static [&'static str]) -> ReportJob {
        ReportJob {
            filename,
            profiles,
            description: "test job",
            run: |_ctx, output| {
                fs::write(output, "ok\n").map_err(|source| ReportError::Write {
                    path: output.to_path_buf(),
                    source,
                })
            },
        }
    }

    fn failing_job(filename: &'static str) -> ReportJob {
        ReportJob {
            filename,
            profiles: profile::ALL_PROFILES,
            description: "always fails",
            run: |_ctx, _output| {
                Err(ReportError::Write {
                    path: std::path::PathBuf::from("nope"),
                    source: std::io::Error::other("boom"),
                })
            },
        }
    }

    fn panicking_job(filename: &'static str) -> ReportJob {
        ReportJob {
            filename,
            profiles: profile::ALL_PROFILES,
            description: "always panics",
            run: |_ctx, _output| panic!("deliberate test panic"),
        }
    }

    #[test]
    fn failing_job_writes_error_file_and_others_still_complete() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.py"), "x = 1\n").unwrap();
        let (plan, config, cancel) = fixture_ctx(dir.path());
        let inventory = Inventory::from_plan(&plan);
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

        let jobs = vec![
            failing_job("01_fails.txt"),
            panicking_job("02_panics.txt"),
            ok_job("03_ok.txt", profile::ALL_PROFILES),
        ];
        let summary = run_reports(&jobs, &ctx, out_dir.path());

        assert_eq!(summary.succeeded, vec!["03_ok.txt"]);
        assert_eq!(summary.failed.len(), 2);
        assert!(!summary.cancelled);

        let error_one = out_dir.path().join("ERROR_01_fails.txt.txt");
        assert!(error_one.exists());
        let content_one = std::fs::read_to_string(&error_one).unwrap();
        assert!(content_one.contains("01_fails.txt"));
        assert!(content_one.contains("boom"));

        let error_two = out_dir.path().join("ERROR_02_panics.txt.txt");
        assert!(error_two.exists());
        let content_two = std::fs::read_to_string(&error_two).unwrap();
        assert!(content_two.contains("deliberate test panic"));

        assert!(out_dir.path().join("03_ok.txt").exists());
    }

    #[test]
    fn profile_gating_skips_unlisted_jobs() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.py"), "x = 1\n").unwrap();
        let (plan, config, cancel) = fixture_ctx(dir.path());
        let inventory = Inventory::from_plan(&plan);
        let ctx = ReportContext {
            source_root: dir.path().to_path_buf(),
            staging_root: dir.path().to_path_buf(),
            inventory: &inventory,
            plan: &plan,
            scan: None,
            diff: None,
            config: &config,
            cancel: &cancel,
            profile: "minimal",
        };
        let out_dir = tempfile::tempdir().unwrap();

        let jobs = vec![
            ok_job("quick_only.txt", &["quick"]),
            ok_job("minimal_ok.txt", &["minimal"]),
        ];
        let summary = run_reports(&jobs, &ctx, out_dir.path());

        assert_eq!(summary.skipped, vec!["quick_only.txt"]);
        assert_eq!(summary.succeeded, vec!["minimal_ok.txt"]);
    }

    #[test]
    fn cancellation_stops_remaining_jobs() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.py"), "x = 1\n").unwrap();
        let (plan, config, cancel) = fixture_ctx(dir.path());
        cancel.cancel();
        let inventory = Inventory::from_plan(&plan);
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

        let jobs = vec![ok_job("never_runs.txt", profile::ALL_PROFILES)];
        let summary = run_reports(&jobs, &ctx, out_dir.path());

        assert!(summary.cancelled);
        assert!(summary.succeeded.is_empty());
        assert!(!out_dir.path().join("never_runs.txt").exists());
    }

    // --- Parallel execution (2026-09-05) --------------------------------------------
    //
    // The catalogue is run in phases: the profile first, the independent reports
    // concurrently, the dashboard last. Only the middle phase goes through
    // `run_reports_parallel`, and its whole obligation is to be indistinguishable from
    // the sequential runner for jobs that are genuinely independent.

    /// Builds a context over a throwaway project, so the tests below read as one line.
    struct Fixture {
        _project: tempfile::TempDir,
        out_dir: tempfile::TempDir,
        plan: codepack_scanner::ExportPlan,
        config: Config,
        cancel: CancellationToken,
    }

    impl Fixture {
        fn new() -> Self {
            let project = tempfile::tempdir().unwrap();
            std::fs::write(project.path().join("main.py"), "x = 1\n").unwrap();
            let (plan, config, cancel) = fixture_ctx(project.path());
            Self {
                _project: project,
                out_dir: tempfile::tempdir().unwrap(),
                plan,
                config,
                cancel,
            }
        }

        fn context<'a>(&'a self, inventory: &'a Inventory) -> ReportContext<'a> {
            ReportContext {
                source_root: self._project.path().to_path_buf(),
                staging_root: self._project.path().to_path_buf(),
                inventory,
                plan: &self.plan,
                scan: None,
                diff: None,
                config: &self.config,
                cancel: &self.cancel,
                profile: "full",
            }
        }
    }

    fn many_jobs() -> Vec<ReportJob> {
        vec![
            ok_job("01_a.txt", profile::ALL_PROFILES),
            failing_job("02_fails.txt"),
            ok_job("03_c.txt", profile::ALL_PROFILES),
            panicking_job("04_panics.txt"),
            ok_job("05_e.txt", profile::ALL_PROFILES),
        ]
    }

    /// The obligation in one assertion: same jobs, same context, same summary — in the
    /// same order, not merely the same set.
    #[test]
    fn the_parallel_runner_reports_exactly_what_the_sequential_one_does() {
        let fixture = Fixture::new();
        let inventory = Inventory::from_plan(&fixture.plan);
        let ctx = fixture.context(&inventory);

        let sequential = run_reports(&many_jobs(), &ctx, fixture.out_dir.path());
        let parallel_out = tempfile::tempdir().unwrap();
        let parallel = run_reports_parallel(&many_jobs(), &ctx, parallel_out.path());

        assert_eq!(parallel.succeeded, sequential.succeeded);
        assert_eq!(parallel.skipped, sequential.skipped);
        assert_eq!(parallel.cancelled, sequential.cancelled);
        assert_eq!(
            parallel
                .failed
                .iter()
                .map(|(name, _)| *name)
                .collect::<Vec<_>>(),
            sequential
                .failed
                .iter()
                .map(|(name, _)| *name)
                .collect::<Vec<_>>(),
        );
    }

    #[test]
    fn a_failing_or_panicking_job_still_leaves_its_error_file() {
        let fixture = Fixture::new();
        let inventory = Inventory::from_plan(&fixture.plan);
        let ctx = fixture.context(&inventory);

        let summary = run_reports_parallel(&many_jobs(), &ctx, fixture.out_dir.path());

        assert_eq!(summary.failed.len(), 2);
        assert!(
            fixture
                .out_dir
                .path()
                .join("ERROR_02_fails.txt.txt")
                .exists()
        );
        let panicked =
            std::fs::read_to_string(fixture.out_dir.path().join("ERROR_04_panics.txt.txt"))
                .unwrap();
        assert!(panicked.contains("deliberate test panic"));
        // And every independent job still produced its own output.
        assert!(fixture.out_dir.path().join("01_a.txt").exists());
        assert!(fixture.out_dir.path().join("05_e.txt").exists());
    }

    #[test]
    fn a_job_outside_the_profile_is_skipped_not_run() {
        let fixture = Fixture::new();
        let inventory = Inventory::from_plan(&fixture.plan);
        // `full` runs everything, so gating is only observable from a narrower profile.
        let ctx = ReportContext {
            profile: "minimal",
            ..fixture.context(&inventory)
        };

        let jobs = vec![
            ok_job("quick_only.txt", &["quick"]),
            ok_job("minimal_ok.txt", &["minimal"]),
        ];
        let summary = run_reports_parallel(&jobs, &ctx, fixture.out_dir.path());

        assert_eq!(summary.skipped, vec!["quick_only.txt"]);
        assert_eq!(summary.succeeded, vec!["minimal_ok.txt"]);
        assert!(!fixture.out_dir.path().join("quick_only.txt").exists());
    }

    #[test]
    fn cancellation_stops_the_parallel_phase_too() {
        let fixture = Fixture::new();
        fixture.cancel.cancel();
        let inventory = Inventory::from_plan(&fixture.plan);
        let ctx = fixture.context(&inventory);

        let summary = run_reports_parallel(&many_jobs(), &ctx, fixture.out_dir.path());

        assert!(summary.cancelled);
        assert!(summary.succeeded.is_empty());
        assert!(!fixture.out_dir.path().join("01_a.txt").exists());
    }

    /// Repeated runs must produce the same summary, or a run's log would depend on which
    /// thread happened to finish first.
    #[test]
    fn the_summary_does_not_depend_on_completion_order() {
        let fixture = Fixture::new();
        let inventory = Inventory::from_plan(&fixture.plan);
        let ctx = fixture.context(&inventory);

        let first = run_reports_parallel(&many_jobs(), &ctx, fixture.out_dir.path());
        for _ in 0..10 {
            let out = tempfile::tempdir().unwrap();
            let again = run_reports_parallel(&many_jobs(), &ctx, out.path());
            assert_eq!(again.succeeded, first.succeeded);
            assert_eq!(again.skipped, first.skipped);
            assert_eq!(
                again
                    .failed
                    .iter()
                    .map(|(name, _)| *name)
                    .collect::<Vec<_>>(),
                first
                    .failed
                    .iter()
                    .map(|(name, _)| *name)
                    .collect::<Vec<_>>(),
            );
        }
    }

    #[test]
    fn an_empty_phase_is_an_empty_summary() {
        let fixture = Fixture::new();
        let inventory = Inventory::from_plan(&fixture.plan);
        let ctx = fixture.context(&inventory);

        let summary = run_reports_parallel(&[], &ctx, fixture.out_dir.path());
        assert!(summary.succeeded.is_empty());
        assert!(summary.failed.is_empty());
        assert!(summary.skipped.is_empty());
        assert!(!summary.cancelled);
    }

    /// Phases are folded into one summary, and the caller must see all of it.
    #[test]
    fn absorbing_a_phase_keeps_every_outcome_and_the_phase_order() {
        let mut first = RunSummary {
            succeeded: vec!["a"],
            failed: vec![("b", "boom".to_string())],
            skipped: vec!["c"],
            cancelled: false,
            diagnostic_write_failures: vec!["d"],
        };
        first.absorb(RunSummary {
            succeeded: vec!["e"],
            failed: vec![("f", "bang".to_string())],
            skipped: vec!["g"],
            cancelled: true,
            diagnostic_write_failures: vec!["h"],
        });

        assert_eq!(first.succeeded, vec!["a", "e"]);
        assert_eq!(first.skipped, vec!["c", "g"]);
        assert_eq!(first.diagnostic_write_failures, vec!["d", "h"]);
        assert_eq!(
            first
                .failed
                .iter()
                .map(|(name, _)| *name)
                .collect::<Vec<_>>(),
            vec!["b", "f"]
        );
        // One cancelled phase cancels the run.
        assert!(first.cancelled);
    }

    #[test]
    fn absorbing_an_uncancelled_phase_does_not_clear_a_cancellation() {
        let mut first = RunSummary {
            cancelled: true,
            ..RunSummary::default()
        };
        first.absorb(RunSummary::default());
        assert!(first.cancelled);
    }
}
