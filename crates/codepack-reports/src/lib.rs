//! Insight reports, AI context packs, and the HTML dashboard (BLUEPRINT §A.7).
//!
//! ## Scope boundary (stage S7, `docs/__arch__/ROADMAP.md`)
//!
//! This crate never walks the filesystem itself: it consumes
//! [`codepack_scanner::ExportPlan`]'s already-planned file list ([`context::Inventory`]
//! is built from `ExportPlan.included_files`, never a fresh directory walk), and — for
//! later groups — [`codepack_security::ScanResult`] and [`codepack_diff::DiffSelection`]
//! as already-computed inputs. It never re-implements S2's ignore rules, S3's secret
//! detector, S4's diff selection, or S6's byte/token formatting; it calls into them.
//! A bounded, single-file read (a manifest like `package.json`, or a source file's
//! content for a heuristic report) is not "walking" and stays in scope, matching the
//! precedent set by `codepack-security::scan`'s own scope-boundary doc.
//!
//! No network access, ever (invariant I1) — nothing in this crate's plugin API may
//! perform an HTTP call, now or in a later group. Reports read only from the staging
//! tree (invariant I2): the original source directory is opened only for a handful of
//! documented, read-only existence/metadata checks (e.g. `.git` presence), never
//! written to. Every line of report output that quotes raw file content is redacted
//! via [`context::redact_line`] before being written (invariant I3).
//!
//! **Known, disclosed gap (`.ai/project/12-domain-rules.md`'s "check cancellation
//! inside loops" rule):** [`plugin::run_reports`] checks [`ReportContext::cancel`]
//! only *between* whole jobs, not inside each report's own per-file loop. A single
//! report job on a very large inventory therefore cannot be interrupted mid-job today.
//! This is acceptable for now because no live caller exists yet — this crate isn't
//! wired into an interactive pipeline (that's S9's job) — but the gap must be closed
//! before S9 exposes real, user-triggered cancellation through this crate. When that
//! happens, follow the precedent already established by
//! `codepack_diff::snapshot::snapshot_project` and `codepack_security::scan::scan_project`:
//! check `cancel.is_cancelled()` on every loop iteration and return a dedicated
//! cancelled-error variant rather than silently truncating output.
//!
//! Earlier passes implemented Group G (the shared glue every other group depends on:
//! [`context`], [`plugin`], [`plugins_json`], [`profile`], [`project_profile`]), Group A
//! (the five simplest reports), Group B (the `06_security_scan.{txt,json,sarif}` adapter
//! over `codepack-security`'s own writers), Group D (the manifest-parser reports:
//! `03_dependencies.txt`, `04_scripts.txt`, `09_config.txt`, `10_docker.txt`,
//! `26_dependency_intelligence.md`), Group C (`git2`-based, read-only reports:
//! `05_git_deep.txt`, `21_git_timeline_report.md` — see [`git_support`], not public,
//! and each report's own module doc), and Group E (heuristic/derived reports that
//! synthesize Inventory/manifest data: the shared import-graph primitive in
//! [`graph`], plus `11_routes_and_pages.txt`, `14_dependency_graph.{md,mmd}`,
//! `15_architecture_report.md`, `16_key_files_report.md`, `17_code_quality_report.md`,
//! `18_api_surface_report.md`, `19_frontend_report.md`, `20_backend_report.md`,
//! `22_project_health_report.md`, `23_refactoring_opportunities.md`,
//! `24_architecture_map.md`). This pass adds Group F (the AI bundle:
//! `12_ai_context_pack.md`, `13_runbook.md`, `AI_CONTEXT/`, `AI_PROMPTS/`) and
//! Group G-finish (`REPORT_DASHBOARD.html`; the pure `manifest.json`/`INDEX.md`
//! writer functions in [`metadata`]; the [`i18n`] RU/EN localization pilot, applied to
//! `01_summary.txt`) — the last S7 implementation pass; see `task-checklist.md`.

pub mod catalog;
pub mod context;
mod error;
mod git_support;
pub mod graph;
mod html;
mod humanize;
pub mod i18n;
pub mod metadata;
mod paths;
pub mod plugin;
pub mod plugins_json;
pub mod profile;
pub mod project_profile;
pub mod reports;
#[cfg(test)]
mod test_support;
mod text;
mod wordscan;

pub use context::ReportContext;
pub use error::{ReportError, Result};
pub use metadata::{IndexInput, ManifestInput, write_index_md, write_manifest};
pub use plugin::{ReportJob, RunSummary, run_reports, run_reports_parallel};
pub use plugins_json::write_report_plugins_json;
pub use project_profile::{ProjectProfile, build_project_profile, write_project_profile_json};
pub use reports::{
    group_a_jobs, group_b_jobs, group_c_jobs, group_d_jobs, group_e_jobs, group_f_jobs,
    group_g_finish_jobs, group_h_human_jobs,
};
