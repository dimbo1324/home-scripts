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
