//! Persistence for the content-addressed scan cache.
//!
//! This module stores and retrieves opaque strings. It does not know what a key is
//! derived from, what a finding is, or when an entry stops being valid — that is
//! `codepack-security`'s business, and keeping it there is what lets this crate go on
//! depending on no other `codepack-*` crate.
//!
//! Entries carry no secret: the findings were redacted when they were produced
//! (invariant I3), and the key is a hash, not the content.
//!
//! ## Read once, write once
//!
//! The shape of the API is dictated by the scan being parallel and a `Connection` not
//! being `Sync`: worker threads cannot query. So the whole table is read up front, and
//! everything the run learned — new entries, and which existing ones were used — goes
//! back in a single transaction at the end. That is also the only shape SQLite likes,
//! since it admits one writer at a time.

use rusqlite::Connection;

use crate::error::Result;
use crate::types::unix_timestamp;

/// How many keys one `UPDATE` refreshes.
///
/// SQLite's default ceiling on host parameters is 999; a hundred keys per statement stays
/// far below it while turning tens of thousands of round trips into a few hundred.
const TOUCH_BATCH: usize = 100;

/// Every entry, as `(key, findings_json)`.
pub fn load_scan_cache(conn: &Connection) -> Result<Vec<(String, String)>> {
    let mut stmt = conn.prepare("SELECT key, findings_json FROM file_scan_cache")?;
    let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
    let mut entries = Vec::new();
    for row in rows {
        entries.push(row?);
    }
    Ok(entries)
}

/// Writes new entries and refreshes the stamps of the ones that were used, in one
/// transaction.
///
/// An upsert that leaves `created_at` alone, not `INSERT OR REPLACE`. Replacing the row
/// reset `created_at` to now, which made the column mean "last seen" while the schema
/// says it means "first seen" (audit No. 19). `used_at` already carries "last seen", and
/// pruning is keyed on it, so the old row's `created_at` was the only thing being lost.
///
/// The findings are still rewritten on conflict. A key covers the bytes, the detector
/// fingerprint and the options, so the same key means the same verdict and the write is a
/// no-op in content — but making that an assumption the storage layer enforces would turn
/// a bug elsewhere into a stale row nothing could correct.
///
/// The used keys are refreshed in batches of [`TOUCH_BATCH`] rather than one statement
/// each.
pub fn store_scan_cache(
    conn: &mut Connection,
    new_entries: &[(String, String)],
    used_keys: &[String],
) -> Result<()> {
    if new_entries.is_empty() && used_keys.is_empty() {
        return Ok(());
    }
    let now = unix_timestamp();
    let tx = conn.transaction()?;
    {
        let mut insert = tx.prepare(
            "INSERT INTO file_scan_cache (key, findings_json, created_at, used_at)
             VALUES (?1, ?2, ?3, ?3)
             ON CONFLICT(key) DO UPDATE SET
                 findings_json = excluded.findings_json,
                 used_at = excluded.used_at",
        )?;
        for (key, findings_json) in new_entries {
            insert.execute(rusqlite::params![key, findings_json, now])?;
        }

        for batch in used_keys.chunks(TOUCH_BATCH) {
            // The placeholder list has to match the batch, so the statement is built per
            // batch rather than prepared once. Only the last batch differs in size, so in
            // practice this prepares twice.
            let placeholders = (2..batch.len() + 2)
                .map(|index| format!("?{index}"))
                .collect::<Vec<_>>()
                .join(", ");
            let sql =
                format!("UPDATE file_scan_cache SET used_at = ?1 WHERE key IN ({placeholders})");
            let mut parameters: Vec<&dyn rusqlite::ToSql> = Vec::with_capacity(batch.len() + 1);
            parameters.push(&now);
            for key in batch {
                parameters.push(key);
            }
            tx.execute(&sql, parameters.as_slice())?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// Drops the least recently used entries until at most `keep` remain, returning how many
/// rows went.
///
/// A cache with no ceiling grows for the life of the installation. Least-recently-used
/// is the right axis: a dependency scanned on every run should outlive a file touched
/// once, which is not what "oldest first" would give.
pub fn prune_scan_cache(conn: &Connection, keep: u32) -> Result<usize> {
    let removed = conn.execute(
        "DELETE FROM file_scan_cache
          WHERE key IN (
              SELECT key FROM file_scan_cache
               ORDER BY used_at DESC, rowid DESC
               LIMIT -1 OFFSET ?1
          )",
        rusqlite::params![keep],
    )?;
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn database() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let conn = crate::migrations::open(&dir.path().join("codepack.db")).unwrap();
        (dir, conn)
    }

    fn entries(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(key, json)| ((*key).to_string(), (*json).to_string()))
            .collect()
    }

    fn stamps(conn: &Connection, key: &str) -> (i64, i64) {
        conn.query_row(
            "SELECT created_at, used_at FROM file_scan_cache WHERE key = ?1",
            [key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
    }

    /// `created_at` means "first seen", which is what the schema says and what pruning
    /// reasoning depends on. `INSERT OR REPLACE` used to reset it on every run, quietly
    /// turning it into a second copy of `used_at` (audit No. 19).
    #[test]
    fn rewriting_an_entry_keeps_the_date_it_was_first_seen() {
        let (_dir, mut conn) = database();
        store_scan_cache(&mut conn, &entries(&[("a", "[]")]), &[]).unwrap();
        let (first_created, _) = stamps(&conn, "a");

        // A distinguishable later stamp, written directly: `unix_timestamp()` has
        // one-second resolution, so two calls in one test would very likely agree.
        conn.execute(
            "UPDATE file_scan_cache SET created_at = ?1, used_at = ?1 WHERE key = 'a'",
            [first_created - 3600],
        )
        .unwrap();

        store_scan_cache(&mut conn, &entries(&[("a", "[1]")]), &[]).unwrap();

        let (created, used) = stamps(&conn, "a");
        assert_eq!(created, first_created - 3600, "created_at must not move");
        assert!(used >= first_created, "used_at must move forward");
    }

    /// Refreshing used keys is batched, so the batch boundary has to be right: a count
    /// either side of it, and one exactly on it, must all land.
    #[test]
    fn every_used_key_is_refreshed_across_batch_boundaries() {
        let (_dir, mut conn) = database();
        let count = TOUCH_BATCH * 2 + 1;
        let pairs: Vec<(String, String)> = (0..count)
            .map(|index| (format!("k{index}"), "[]".to_string()))
            .collect();
        store_scan_cache(&mut conn, &pairs, &[]).unwrap();

        conn.execute("UPDATE file_scan_cache SET used_at = 0", [])
            .unwrap();
        let keys: Vec<String> = pairs.iter().map(|(key, _)| key.clone()).collect();
        store_scan_cache(&mut conn, &[], &keys).unwrap();

        let stale: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM file_scan_cache WHERE used_at = 0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stale, 0, "every key in every batch must be refreshed");
    }

    #[test]
    fn a_fresh_cache_is_empty() {
        let (_dir, conn) = database();
        assert!(load_scan_cache(&conn).unwrap().is_empty());
    }

    #[test]
    fn what_is_stored_comes_back() {
        let (_dir, mut conn) = database();
        store_scan_cache(&mut conn, &entries(&[("a", "[]"), ("b", "[1]")]), &[]).unwrap();

        let mut loaded = load_scan_cache(&conn).unwrap();
        loaded.sort();
        assert_eq!(loaded, entries(&[("a", "[]"), ("b", "[1]")]));
    }

    /// The same bytes under the same build key the same, so a second run rewrites the
    /// row rather than colliding with it.
    #[test]
    fn storing_the_same_key_twice_replaces_rather_than_duplicates() {
        let (_dir, mut conn) = database();
        store_scan_cache(&mut conn, &entries(&[("a", "[]")]), &[]).unwrap();
        store_scan_cache(&mut conn, &entries(&[("a", "[2]")]), &[]).unwrap();

        let loaded = load_scan_cache(&conn).unwrap();
        assert_eq!(loaded, entries(&[("a", "[2]")]));
    }

    #[test]
    fn an_empty_write_is_a_no_op_rather_than_an_error() {
        let (_dir, mut conn) = database();
        store_scan_cache(&mut conn, &[], &[]).unwrap();
        assert!(load_scan_cache(&conn).unwrap().is_empty());
    }

    /// Least-recently-*used*, not least recently written: a dependency scanned on every
    /// run has to outlive a file touched once, and "oldest first" would evict it.
    #[test]
    fn pruning_keeps_what_was_used_and_drops_the_rest() {
        let (_dir, mut conn) = database();
        store_scan_cache(
            &mut conn,
            &entries(&[("old", "[]"), ("kept", "[]"), ("also-old", "[]")]),
            &[],
        )
        .unwrap();

        // A later run touches one of them, which is what "in use" means here.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        store_scan_cache(&mut conn, &[], &["kept".to_string()]).unwrap();

        let removed = prune_scan_cache(&conn, 1).unwrap();
        assert_eq!(removed, 2);

        let loaded = load_scan_cache(&conn).unwrap();
        assert_eq!(loaded, entries(&[("kept", "[]")]));
    }

    #[test]
    fn pruning_below_the_ceiling_removes_nothing() {
        let (_dir, mut conn) = database();
        store_scan_cache(&mut conn, &entries(&[("a", "[]"), ("b", "[]")]), &[]).unwrap();
        assert_eq!(prune_scan_cache(&conn, 10).unwrap(), 0);
        assert_eq!(load_scan_cache(&conn).unwrap().len(), 2);
    }

    /// Touching a key that is not there is not an error: the run that used it may have
    /// been racing a prune, and failing an export over a cache miss would be absurd.
    #[test]
    fn touching_an_absent_key_is_harmless() {
        let (_dir, mut conn) = database();
        store_scan_cache(&mut conn, &[], &["never-stored".to_string()]).unwrap();
        assert!(load_scan_cache(&conn).unwrap().is_empty());
    }

    /// The cache is content-addressed and shared, so it deliberately has no project
    /// foreign key — two projects vendoring the same dependency scan it once.
    #[test]
    fn entries_outlive_the_project_tables() {
        let (_dir, mut conn) = database();
        store_scan_cache(&mut conn, &entries(&[("shared", "[]")]), &[]).unwrap();
        conn.execute("DELETE FROM project", []).unwrap();
        assert_eq!(load_scan_cache(&conn).unwrap().len(), 1);
    }

    /// `keep = 0` empties the cache. Pinned because "0 means no limit" is the equally
    /// plausible reading, and the two differ by the whole table.
    #[test]
    fn pruning_to_zero_empties_the_cache() {
        let (_dir, mut conn) = database();
        store_scan_cache(&mut conn, &entries(&[("a", "[]"), ("b", "[]")]), &[]).unwrap();

        assert_eq!(prune_scan_cache(&conn, 0).unwrap(), 2);
        assert!(load_scan_cache(&conn).unwrap().is_empty());
    }

    /// A stored value is opaque to this layer: it is whatever `codepack-security` encoded,
    /// and this crate must not parse, validate or normalise it. A round trip of something
    /// that is not JSON at all proves the boundary holds.
    #[test]
    fn the_stored_value_is_opaque_to_the_storage_layer() {
        let (_dir, mut conn) = database();
        let odd = "not json at all — {\"unbalanced\": ";
        store_scan_cache(&mut conn, &[("k".to_string(), odd.to_string())], &[]).unwrap();

        let loaded = load_scan_cache(&conn).unwrap();
        assert_eq!(loaded, vec![("k".to_string(), odd.to_string())]);
    }

    /// Keys are hex digests in practice, but nothing here depends on that. A key with
    /// punctuation must round-trip rather than being mangled by the query.
    #[test]
    fn an_unusual_key_round_trips_unchanged() {
        let (_dir, mut conn) = database();
        let key = "a'b\"c%d_e--f";
        store_scan_cache(&mut conn, &[(key.to_string(), "[]".to_string())], &[]).unwrap();

        let loaded = load_scan_cache(&conn).unwrap();
        assert_eq!(loaded, vec![(key.to_string(), "[]".to_string())]);
    }
}
