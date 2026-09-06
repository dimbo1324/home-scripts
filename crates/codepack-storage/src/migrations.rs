//! Embedded, numbered SQL migrations plus the runner that applies them (BLUEPRINT
//! §D.2/§D.3). No external migration framework: each migration is a plain SQL string
//! recorded as a row in `schema_version` once applied, inside its own transaction.
//! Running the runner again against an already-migrated database is a safe no-op.
//!
//! `PRAGMA foreign_keys`/`journal_mode` are **not** part of the migration SQL: SQLite
//! does not persist `foreign_keys` across connections, and both pragmas must be
//! (re)applied on every connection open, not only once at schema-creation time.

use std::path::Path;

use rusqlite::{Connection, TransactionBehavior};

use crate::error::Result;
use crate::types::unix_timestamp;

const MIGRATION_0001_INITIAL_SCHEMA: &str = r"
CREATE TABLE schema_version (
    version     INTEGER NOT NULL,
    applied_at  INTEGER NOT NULL
);

CREATE TABLE project (
    id              INTEGER PRIMARY KEY,
    root_path       TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    primary_stack   TEXT,
    created_at      INTEGER NOT NULL,
    last_export_at  INTEGER
);

CREATE TABLE export_run (
    id              INTEGER PRIMARY KEY,
    project_id      INTEGER NOT NULL REFERENCES project(id) ON DELETE CASCADE,
    started_at      INTEGER NOT NULL,
    finished_at     INTEGER,
    profile         TEXT,
    safe_mode       TEXT,
    diff_mode       TEXT,
    files_copied    INTEGER,
    bytes_total     INTEGER,
    tokens_est      INTEGER,
    redacted_count  INTEGER,
    cancelled       INTEGER NOT NULL,
    result_path     TEXT
);
CREATE INDEX idx_export_run_project_started ON export_run(project_id, started_at);

CREATE TABLE run_file (
    id          INTEGER PRIMARY KEY,
    run_id      INTEGER NOT NULL REFERENCES export_run(id) ON DELETE CASCADE,
    rel_path    TEXT NOT NULL,
    size_bytes  INTEGER,
    loc         INTEGER,
    status      TEXT,
    group_name  TEXT
);

CREATE TABLE finding (
    id                INTEGER PRIMARY KEY,
    run_id            INTEGER NOT NULL REFERENCES export_run(id) ON DELETE CASCADE,
    type              TEXT NOT NULL,
    severity          TEXT NOT NULL,
    confidence        TEXT NOT NULL,
    rule_id           TEXT NOT NULL,
    file              TEXT NOT NULL,
    line              INTEGER,
    message_redacted  TEXT NOT NULL
);
CREATE INDEX idx_finding_run_severity ON finding(run_id, severity);

CREATE TABLE archive_part (
    id                INTEGER PRIMARY KEY,
    run_id            INTEGER NOT NULL REFERENCES export_run(id) ON DELETE CASCADE,
    part_index        INTEGER NOT NULL,
    archive_name      TEXT NOT NULL,
    compressed_bytes  INTEGER,
    groups            TEXT
);

CREATE TABLE snapshot (
    id          INTEGER PRIMARY KEY,
    project_id  INTEGER NOT NULL REFERENCES project(id) ON DELETE CASCADE,
    run_id      INTEGER REFERENCES export_run(id) ON DELETE CASCADE,
    created_at  INTEGER NOT NULL,
    file_count  INTEGER NOT NULL,
    bytes_total INTEGER NOT NULL
);

CREATE TABLE snapshot_file (
    id          INTEGER PRIMARY KEY,
    snapshot_id INTEGER NOT NULL REFERENCES snapshot(id) ON DELETE CASCADE,
    rel_path    TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    size_bytes  INTEGER NOT NULL,
    loc         INTEGER NOT NULL,
    mtime_ns    INTEGER
);
CREATE INDEX idx_snapshot_file_snapshot_relpath ON snapshot_file(snapshot_id, rel_path);
";

/// The content-addressed scan cache.
///
/// `key` is opaque here on purpose: `codepack-security` builds it from the file's bytes
/// together with everything about the running build that decides what those bytes mean,
/// so this table never has to know what a detector is. `findings_json` is that file's
/// content-derived findings, already redacted when they were produced (invariant I3) —
/// nothing in this table holds a secret value.
///
/// No foreign key to `project`: identical bytes are identical bytes, and a dependency
/// shared between two projects is exactly the case worth not scanning twice.
const MIGRATION_0002_FILE_SCAN_CACHE: &str = r"
CREATE TABLE file_scan_cache (
    key           TEXT PRIMARY KEY,
    findings_json TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    used_at       INTEGER NOT NULL
);
CREATE INDEX idx_file_scan_cache_used_at ON file_scan_cache(used_at);
";

const MIGRATIONS: &[(i64, &str)] = &[
    (1, MIGRATION_0001_INITIAL_SCHEMA),
    (2, MIGRATION_0002_FILE_SCAN_CACHE),
];

/// Opens (creating if necessary) the SQLite database at `path`, applies the
/// connection-level pragmas, and runs every migration that has not yet been recorded
/// in `schema_version`.
pub fn open(path: &Path) -> Result<Connection> {
    let mut conn = Connection::open(path)?;
    apply_pragmas(&conn)?;
    migrate(&mut conn)?;
    Ok(conn)
}

pub(crate) fn apply_pragmas(conn: &Connection) -> Result<()> {
    // First, before anything that can block. SQLite allows only one writer at a time
    // even under WAL; without a busy timeout a contended statement fails immediately
    // with `SQLITE_BUSY` instead of waiting its turn. Setting it last — as this did
    // until 2026-09-06 — left the two pragmas below unprotected, and switching the
    // journal mode takes a lock of its own.
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.pragma_update(None, "foreign_keys", true)?;
    enable_wal(conn)
}

/// Switches the database to WAL, waiting out other connections doing the same.
///
/// `PRAGMA journal_mode = WAL` needs an exclusive lock and — unlike an ordinary
/// statement — does **not** go through the busy handler, so `busy_timeout` does not
/// cover it: with another connection on the database it fails immediately with
/// `SQLITE_BUSY`. Several processes opening a brand-new database at the same moment is
/// exactly when that happens, and it is the same first-run moment the migration race
/// above lives in (both found 2026-09-06).
///
/// The mode is a property of the *file* and persists, so the winner switches it once and
/// everyone else sees `wal` on the next read and stops. `:memory:` databases always
/// report `memory` and cannot be switched, which counts as done rather than as a failure.
fn enable_wal(conn: &Connection) -> Result<()> {
    const ATTEMPTS: u32 = 50;
    const PAUSE: std::time::Duration = std::time::Duration::from_millis(20);

    for attempt in 0..ATTEMPTS {
        let mode: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        if mode.eq_ignore_ascii_case("wal") || mode.eq_ignore_ascii_case("memory") {
            return Ok(());
        }
        match conn.pragma_update(None, "journal_mode", "WAL") {
            Ok(()) => return Ok(()),
            Err(error) if is_busy(&error) && attempt + 1 < ATTEMPTS => std::thread::sleep(PAUSE),
            Err(error) => return Err(error.into()),
        }
    }
    // Every attempt was busy and the mode never became WAL. Journalling still works —
    // the database is simply in rollback mode — so this is not worth refusing to open
    // for, and saying so would mean inventing an error the caller cannot act on.
    Ok(())
}

fn is_busy(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::DatabaseBusy,
                ..
            },
            _
        )
    )
}

/// Applies whatever has not been applied yet, correctly when two connections do it at
/// once.
///
/// The version must be read under the *same* lock that applies the migration. It was not
/// until 2026-09-06: the read happened outside any transaction and `Connection::
/// transaction` is DEFERRED, which takes the write lock only at the first write. So two
/// connections opening a fresh database both read version 0, both then ran `CREATE
/// TABLE`, and whichever lost the race failed with "table schema_version already exists"
/// — on CI, where the desktop suite opens one database from several test threads, and
/// equally for a user running the app and the CLI for the first time at the same moment.
///
/// `TransactionBehavior::Immediate` takes the write lock up front, so the second
/// connection waits at `transaction_with_behavior`, and then reads the version the first
/// one committed. The cheap unlocked read before the loop keeps the common case — an
/// already-migrated database, which is every open after the first — from serialising on
/// that lock at all.
pub(crate) fn migrate(conn: &mut Connection) -> Result<()> {
    let latest = MIGRATIONS.last().map_or(0, |(version, _)| *version);
    if current_version(conn)? >= latest {
        return Ok(());
    }

    for (version, sql) in MIGRATIONS {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Re-read inside the lock: another connection may have applied this while we
        // waited for it.
        if current_version(&tx)? >= *version {
            tx.rollback()?;
            continue;
        }
        tx.execute_batch(sql)?;
        tx.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (?1, ?2)",
            rusqlite::params![version, unix_timestamp()],
        )?;
        tx.commit()?;
    }
    Ok(())
}

fn current_version(conn: &Connection) -> Result<i64> {
    let schema_version_table_exists: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_version'",
        [],
        |row| row.get(0),
    )?;
    if schema_version_table_exists == 0 {
        return Ok(0);
    }
    conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |row| row.get(0),
    )
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table_names(conn: &Connection) -> Vec<String> {
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .unwrap();
        stmt.query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .map(|value| value.unwrap())
            .collect()
    }

    fn index_names(conn: &Connection) -> Vec<String> {
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'index' ORDER BY name")
            .unwrap();
        stmt.query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .map(|value| value.unwrap())
            .collect()
    }

    #[test]
    fn fresh_database_reaches_the_current_schema_version_with_every_table_and_index() {
        let dir = tempfile::tempdir().unwrap();
        let conn = open(&dir.path().join("codepack.db")).unwrap();

        let version: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get(0)
            })
            .unwrap();
        // Every migration in `MIGRATIONS` has been applied. Asserted against the table
        // rather than against a literal, so adding one cannot leave this test passing
        // while claiming a version the database does not have.
        assert_eq!(version, MIGRATIONS.last().unwrap().0);

        let tables = table_names(&conn);
        for expected in [
            "archive_part",
            "export_run",
            "finding",
            "project",
            "run_file",
            "schema_version",
            "snapshot",
            "snapshot_file",
        ] {
            assert!(
                tables.contains(&expected.to_string()),
                "missing table {expected}"
            );
        }

        let indexes = index_names(&conn);
        for expected in [
            "idx_export_run_project_started",
            "idx_finding_run_severity",
            "idx_snapshot_file_snapshot_relpath",
        ] {
            assert!(
                indexes.contains(&expected.to_string()),
                "missing index {expected}"
            );
        }
    }

    #[test]
    fn foreign_keys_pragma_is_on_and_journal_mode_is_wal_for_on_disk_files() {
        let dir = tempfile::tempdir().unwrap();
        let conn = open(&dir.path().join("codepack.db")).unwrap();

        let foreign_keys: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(foreign_keys, 1);

        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(journal_mode.to_lowercase(), "wal");
    }

    #[test]
    fn running_migrations_twice_is_a_safe_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("codepack.db");
        {
            let _conn = open(&db_path).unwrap();
        }
        // Reopening the same file re-runs `migrate` against an already-migrated
        // database; it must not error and must not duplicate `schema_version` rows.
        let conn = open(&db_path).unwrap();
        let row_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_version", [], |row| row.get(0))
            .unwrap();
        // One row per migration and no more: a second open must record nothing.
        assert_eq!(row_count, MIGRATIONS.len() as i64);
    }
}
