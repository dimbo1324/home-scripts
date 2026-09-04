//! The scan cache the pipeline hands to `codepack-security`, backed by SQLite.
//!
//! This is the crate that legitimately depends on both, so this is where the two meet:
//! `codepack-security` decides what may be reused and under which key,
//! `codepack-storage` keeps the rows, and neither knows about the other.
//!
//! ## Why the whole table is read up front
//!
//! Scanning runs on a rayon pool and a `rusqlite::Connection` is not `Sync`, so a worker
//! thread cannot query. The table is therefore loaded into a map before the pass and
//! consulted from memory; everything learned during the pass — entries that were not
//! there, and keys that were used — is buffered and written once afterwards.
//!
//! Entries are small (most files contain nothing, and their entry says so in two
//! characters), and the ceiling below bounds the rest.

use std::collections::HashMap;
use std::sync::Mutex;

use codepack_security::cache::{self, CachedFinding, FileScanCache};
use codepack_storage::Connection;

use crate::error::Result;

/// How many entries survive a prune. Chosen to comfortably cover a large repository's
/// file count several times over while keeping the load cost trivial.
const MAX_ENTRIES: u32 = 50_000;

pub(crate) struct SqliteScanCache {
    entries: HashMap<String, Vec<CachedFinding>>,
    /// Newly scanned content, `(key, findings_json)`, waiting to be written.
    pending: Mutex<Vec<(String, String)>>,
    /// Keys that were served from `entries`, so pruning keeps what is in use.
    used: Mutex<Vec<String>>,
}

impl SqliteScanCache {
    /// Reads the cache into memory.
    ///
    /// A row whose JSON no longer parses is skipped rather than fatal: it was written by
    /// a different build, and the worst it can cost is one file being scanned again.
    pub(crate) fn load(conn: &Connection) -> Result<Self> {
        let mut entries = HashMap::new();
        for (key, json) in codepack_storage::scan_cache::load_scan_cache(conn)? {
            if let Some(findings) = cache::decode(&json) {
                entries.insert(key, findings);
            }
        }
        Ok(Self {
            entries,
            pending: Mutex::new(Vec::new()),
            used: Mutex::new(Vec::new()),
        })
    }

    /// Writes everything this run learned, then trims the cache back to its ceiling.
    pub(crate) fn flush(self, conn: &mut Connection) -> Result<()> {
        let pending = into_inner(self.pending);
        let used = into_inner(self.used);
        codepack_storage::scan_cache::store_scan_cache(conn, &pending, &used)?;
        codepack_storage::scan_cache::prune_scan_cache(conn, MAX_ENTRIES)?;
        Ok(())
    }
}

/// Takes a mutex's value, treating poisoning as recoverable.
///
/// A panic on a worker thread must not turn a cache — an optimisation, by definition
/// discardable — into a failure of the export it was meant to speed up.
fn into_inner<T>(lock: Mutex<T>) -> T {
    lock.into_inner().unwrap_or_else(|error| error.into_inner())
}

impl FileScanCache for SqliteScanCache {
    fn lookup(&self, key: &str) -> Option<Vec<CachedFinding>> {
        let found = self.entries.get(key)?;
        if let Ok(mut used) = self.used.lock() {
            used.push(key.to_string());
        }
        Some(found.clone())
    }

    fn store(&self, key: &str, findings: &[CachedFinding]) {
        // A finding that cannot be serialised is simply not cached; the scan already
        // produced the real answer, and this path exists only to make the next run
        // faster.
        let Some(json) = cache::encode(findings) else {
            return;
        };
        if let Ok(mut pending) = self.pending.lock() {
            pending.push((key.to_string(), json));
        }
    }
}
