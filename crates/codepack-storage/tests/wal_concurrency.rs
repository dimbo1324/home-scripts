//! WAL concurrency guarantees. Deliberately uses real on-disk temp files for every
//! connection here, never `:memory:` — an in-memory SQLite database is private to its
//! own connection and cannot demonstrate WAL's cross-connection behavior at all.

use std::thread;

use codepack_storage::{NewExportRun, find_or_create_project, open, record_export_run};

#[test]
fn wal_allows_a_concurrent_read_while_another_connection_holds_an_uncommitted_write() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("codepack.db");

    let mut conn_a = open(&db_path).unwrap();
    let project_id = find_or_create_project(&conn_a, "/repo", "Repo", None).unwrap();

    let tx = conn_a.transaction().unwrap();
    tx.execute(
        "INSERT INTO project (root_path, name, primary_stack, created_at, last_export_at)
         VALUES (?1, ?2, ?3, ?4, NULL)",
        rusqlite::params![
            "/repo/uncommitted",
            "Uncommitted",
            Option::<&str>::None,
            1_i64
        ],
    )
    .unwrap();

    // conn_b is a second, real on-disk connection. Under WAL this read must succeed
    // (readers never block on a writer); it must not surface `SQLITE_BUSY`.
    let conn_b = open(&db_path).unwrap();
    let visible_before_commit: i64 = conn_b
        .query_row("SELECT COUNT(*) FROM project", [], |row| row.get(0))
        .unwrap();
    // The uncommitted insert must not be visible to another connection yet.
    assert_eq!(visible_before_commit, 1);

    tx.commit().unwrap();

    let visible_after_commit: i64 = conn_b
        .query_row("SELECT COUNT(*) FROM project", [], |row| row.get(0))
        .unwrap();
    assert_eq!(visible_after_commit, 2);

    // project_id is still the row created before the transaction started.
    let name: String = conn_b
        .query_row(
            "SELECT name FROM project WHERE id = ?1",
            rusqlite::params![project_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(name, "Repo");
}

#[test]
fn two_threads_recording_export_runs_concurrently_stay_consistent() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("codepack.db");

    let project_id = {
        let conn = open(&db_path).unwrap();
        find_or_create_project(&conn, "/repo", "Repo", None).unwrap()
    };

    const THREADS: i64 = 4;
    const RUNS_PER_THREAD: i64 = 25;

    let mut handles = Vec::new();
    for thread_index in 0..THREADS {
        let db_path = db_path.clone();
        handles.push(thread::spawn(move || {
            let mut conn = open(&db_path).unwrap();
            for run_index in 0..RUNS_PER_THREAD {
                let started_at = thread_index * 1_000_000 + run_index;
                record_export_run(
                    &mut conn,
                    NewExportRun {
                        project_id,
                        started_at,
                        finished_at: Some(started_at),
                        profile: None,
                        safe_mode: None,
                        diff_mode: None,
                        files_copied: None,
                        bytes_total: None,
                        tokens_est: None,
                        redacted_count: None,
                        cancelled: false,
                        result_path: None,
                    },
                    &[],
                    &[],
                    &[],
                    None,
                )
                .unwrap();
            }
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }

    let conn = open(&db_path).unwrap();
    let total_runs: i64 = conn
        .query_row("SELECT COUNT(*) FROM export_run", [], |row| row.get(0))
        .unwrap();
    assert_eq!(total_runs, THREADS * RUNS_PER_THREAD);

    let mut stmt = conn.prepare("PRAGMA foreign_key_check").unwrap();
    let violations: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .map(|value| value.unwrap())
        .collect();
    assert!(
        violations.is_empty(),
        "foreign_key_check violations: {violations:?}"
    );
}

/// Several connections opening a database that does not exist yet.
///
/// The case that had no coverage: every other test here opens the database once on the
/// main thread first, so the migration is already applied by the time any thread runs.
/// A first open done by two connections at once used to fail with "table schema_version
/// already exists" — the version was read outside the lock that applied the migration.
/// It reached CI on 2026-09-06 as a flaky desktop test, and it is equally what a user
/// starting the app and the CLI together on a new machine would have hit.
///
/// A barrier rather than hoping the threads overlap: without it the first thread usually
/// finishes migrating before the others start, which is precisely the passing case.
#[test]
fn several_connections_may_create_the_same_database_at_once() {
    use std::sync::{Arc, Barrier};

    const THREADS: usize = 8;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("fresh.db");
    assert!(
        !db_path.exists(),
        "the race is about creating it, not opening it"
    );

    let barrier = Arc::new(Barrier::new(THREADS));
    let mut handles = Vec::new();
    for _ in 0..THREADS {
        let db_path = db_path.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            open(&db_path).map(|_| ())
        }));
    }

    let failures: Vec<String> = handles
        .into_iter()
        .filter_map(|handle| handle.join().unwrap().err())
        .map(|error| error.to_string())
        .collect();
    assert!(
        failures.is_empty(),
        "opening one fresh database from {THREADS} threads failed: {failures:?}"
    );

    // And the schema is whole, not half-applied by whichever thread won.
    let conn = open(&db_path).unwrap();
    let tables: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN
             ('schema_version', 'file_scan_cache')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        tables, 2,
        "both migrations must have been applied exactly once"
    );
    let versions: i64 = conn
        .query_row("SELECT COUNT(*) FROM schema_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        versions, 2,
        "a migration must be recorded once, not once per thread"
    );
}
