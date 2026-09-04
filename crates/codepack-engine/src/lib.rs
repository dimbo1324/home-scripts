//! Orchestrator of the eight-step export pipeline (BLUEPRINT §A.1/§C).
//!
//! ## Scope boundary (this pass, stage S9's Group Z, `task-checklist.md`)
//!
//! Earlier passes implemented pipeline steps 1 ("plan") through 7 ("manifest.json +
//! INDEX.md", first write, `archive_result: None`), plus the shared
//! [`paths::build_export_paths`] path derivation every step needs (Group P+C, Group
//! R+A — see each module's own doc comment). This pass adds step 8 (final archiving:
//! [`codepack_archive::build_final_archives`], wired through the
//! `on_plan_ready`/dashboard-refresh hook this crate owns precisely because it is the
//! one crate depending on both `codepack-archive` and `codepack-reports`),
//! `codepack-storage` wiring ([`storage`]'s hand-written `Snapshot`↔`New*`/`Stored*`
//! conversions, since neither crate depends on the other), staging cleanup, and
//! [`orchestrator::run_export`] — the top-level function that sequences all eight
//! steps and is this crate's one real public entry point for a caller.
//!
//! This crate depends on every other domain crate in the workspace
//! (`codepack-scanner`/`-security`/`-diff`/`-reports`/`-storage`/`-archive`/`-tokens`)
//! plus `git2` (step 4's read-only queries) and `encoding_rs` (step 5's decode
//! fallback chain) — the widest dependency surface in the workspace, by design: it is
//! the one crate whose entire job is combining every earlier stage's output into one
//! run. It never depends on Tauri or the frontend (invariant I8); it never writes into
//! the source project folder (invariant I2); every long-running loop checks the
//! caller-supplied [`codepack_core::CancellationToken`] inside the loop, not only
//! between steps.

mod analytics;
mod budget;
mod copy;
mod error;
mod git_report;
mod ignored_dirs;
mod layout;
mod manifest;
mod orchestrator;
mod paths;
mod plan;
mod relpath;
mod scan_cache;
mod storage;
mod structure;
mod text_dump;
mod timestamp;

pub use analytics::{AnalyticsOutcome, run_analytics};
pub use copy::copy_project;
pub use error::{EngineError, Result};
pub use git_report::write_git_report;
pub use manifest::write_manifest_and_index;
pub use orchestrator::{ExportOutcome, run_export};
pub use paths::{build_export_paths, build_export_paths_for_format, sanitize_name};
pub use plan::{PlanOutcome, plan_export, run_export_plan};
pub use structure::write_structure_report;
pub use text_dump::write_text_dump;
