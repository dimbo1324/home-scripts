//! SQLite storage for export history, snapshots, findings, and migrations
//! (BLUEPRINT §D).
//!
//! ## Scope boundary (stage S5, `docs/__arch__/ROADMAP.md`)
//!
//! This crate has no dependency on any other `codepack-*` crate. [`open`] takes a
//! plain `&Path` for the database file — resolving *where* that file lives (e.g. via
//! `codepack_core::paths::AppPaths::db_file()`/`legacy_history_file()`) is a future
//! caller's job (stage S9's engine), not this crate's; it stays decoupled the same
//! way `codepack-diff`'s `snapshot_project` takes a caller-supplied ignored-directory
//! set instead of reaching for another crate's constants.
//!
//! It never depends on `codepack-scanner`/`codepack-security`/`codepack-diff` either:
//! rather than importing their `Finding`/`Snapshot`/`SnapshotFile` types, it defines
//! its own local `New*` structs ([`types`]) that a future caller (stage S9's engine)
//! populates by copying fields out of those crates' real output — never via a `From`
//! impl living here, which would create a forbidden reverse dependency.
//!
//! This crate never computes a snapshot, a finding, or an export plan; it only
//! persists and retrieves already-computed values. Findings arrive pre-redacted
//! (invariant I3, `docs/architecture/invariants.md`) — `message_redacted` is stored
//! verbatim, with zero redaction or "improvement" logic performed here.
//!
//! Invariant I6 (`docs/architecture/invariants.md`): [`record_export_run`] always
//! inserts an `export_run` row, but a `snapshot`/`snapshot_file` row is inserted only
//! when the caller passes `Some`, and this crate never issues an `UPDATE` against
//! either table — a cancelled or failed run can therefore never overwrite a
//! previously recorded baseline.

mod baseline;
mod error;
mod history;
pub mod import;
mod migrations;
mod project;
mod retention;
mod run;
pub mod scan_cache;
mod types;

pub use baseline::latest_snapshot;
pub use error::{Result, StorageError};
pub use history::{ExportRunRecord, list_export_runs};
pub use import::{ImportReport, import_legacy_history};
pub use migrations::open;
pub use project::{find_or_create_project, find_project_id};
pub use retention::cleanup_old_runs;
pub use run::record_export_run;
pub use rusqlite::Connection;
pub use scan_cache::{load_scan_cache, prune_scan_cache, store_scan_cache};
pub use types::{
    NewArchivePart, NewExportRun, NewFinding, NewRunFile, NewSnapshot, NewSnapshotFile,
    StoredSnapshot, StoredSnapshotFile,
};
