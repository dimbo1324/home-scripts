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
/// `INSERT OR REPLACE` because a key that is already there describes the same bytes
/// under the same build: rewriting it changes no content and refreshes the stamps.
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
            "INSERT OR REPLACE INTO file_scan_cache (key, findings_json, created_at, used_at)
             VALUES (?1, ?2, ?3, ?3)",
        )?;
        for (key, findings_json) in new_entries {
            insert.execute(rusqlite::params![key, findings_json, now])?;
        }
        let mut touch = tx.prepare("UPDATE file_scan_cache SET used_at = ?2 WHERE key = ?1")?;
        for key in used_keys {
            touch.execute(rusqlite::params![key, now])?;
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
}
