//! Bounded, best-effort text/JSON reads from the staging tree. Every function here
//! reads a single, caller-named file — it never walks a directory (that stays
//! `codepack-scanner`'s job; see the crate-scope doc in `lib.rs`).

use std::path::Path;

/// Legacy `read_text_safely`, minus multi-encoding detection (`TRY_ENCODINGS`'s
/// `cp1251`/`cp866`/`utf-16` fallbacks): decoding a non-UTF-8 legacy-encoded source
/// file is out of scope for this pass's heuristic reports (`07_todo_fixme`,
/// `08_code_metrics` both already treat their output as heuristic, per BLUEPRINT
/// §A.7). UTF-8 is tried first; `String::from_utf8_lossy` is the final fallback,
/// matching legacy's intent (never fail, always return *some* text) without pulling in
/// an encoding-detection crate. Revisiting this for exact legacy-encoding parity is
/// noted as deferred scope, not a silent gap.
///
/// Returns `None` when the file cannot be stat'd, exceeds `max_bytes`, or its first
/// sample looks binary ([`codepack_scanner::looks_binary`]).
pub(crate) fn read_text_lossy(path: &Path, max_bytes: Option<u64>) -> Option<String> {
    let metadata = std::fs::metadata(path).ok()?;
    let size = metadata.len();
    if size == 0 {
        return Some(String::new());
    }
    if let Some(limit) = max_bytes
        && size > limit
    {
        return None;
    }

    let raw = std::fs::read(path).ok()?;
    let sample_len = raw.len().min(codepack_scanner::BINARY_SAMPLE_BYTES);
    if codepack_scanner::looks_binary(&raw[..sample_len]) {
        return None;
    }
    Some(String::from_utf8_lossy(&raw).into_owned())
}

/// The largest file [`safe_read_json`] will read.
///
/// Every caller is reading a project manifest — `package.json`, `composer.json`, a lock
/// file. None of those is tens of megabytes, and something that is, is not the file the
/// caller thinks it found. Reading it whole into memory and then parsing it into a
/// `serde_json::Value` costs several times its size again (audit No. 15).
const MAX_JSON_BYTES: u64 = 16 * 1024 * 1024;

/// Legacy `safe_read_json`: any I/O or parse failure yields `Value::Null` rather than
/// propagating — callers treat a missing/unreadable manifest as "no data available",
/// not a report failure. A file past [`MAX_JSON_BYTES`] is treated the same way, which
/// is why the ceiling needs no separate error path.
pub(crate) fn safe_read_json(path: &Path) -> serde_json::Value {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.len() > MAX_JSON_BYTES => return serde_json::Value::Null,
        // An unreadable stat is not a reason to refuse; the read below reports it.
        _ => {}
    }
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or(serde_json::Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A manifest larger than any real one is treated exactly like an unreadable file:
    /// no data, no report failure (audit No. 15).
    #[test]
    fn an_absurdly_large_json_file_reads_as_no_data_rather_than_being_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package.json");
        let padding = " ".repeat(usize::try_from(MAX_JSON_BYTES).unwrap() + 1);
        // Valid JSON, so nothing but the ceiling can be what refuses it.
        std::fs::write(&path, format!("{{\"name\":\"x\"}}{padding}")).unwrap();

        assert_eq!(safe_read_json(&path), serde_json::Value::Null);
    }

    #[test]
    fn an_ordinary_manifest_still_parses() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package.json");
        std::fs::write(&path, r#"{"name":"demo"}"#).unwrap();

        assert_eq!(safe_read_json(&path)["name"], "demo");
    }

    #[test]
    fn read_text_lossy_returns_empty_for_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.txt");
        std::fs::write(&path, b"").unwrap();
        assert_eq!(read_text_lossy(&path, None), Some(String::new()));
    }

    #[test]
    fn read_text_lossy_rejects_oversized_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.txt");
        std::fs::write(&path, vec![b'a'; 100]).unwrap();
        assert_eq!(read_text_lossy(&path, Some(10)), None);
    }

    #[test]
    fn read_text_lossy_rejects_binary_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bin.dat");
        std::fs::write(&path, [0u8, 1, 2, 3]).unwrap();
        assert_eq!(read_text_lossy(&path, None), None);
    }

    #[test]
    fn read_text_lossy_reads_plain_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hello.txt");
        std::fs::write(&path, b"hello world").unwrap();
        assert_eq!(
            read_text_lossy(&path, None),
            Some("hello world".to_string())
        );
    }

    #[test]
    fn safe_read_json_returns_null_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.json");
        assert_eq!(safe_read_json(&path), serde_json::Value::Null);
    }

    #[test]
    fn safe_read_json_parses_valid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.json");
        std::fs::write(&path, br#"{"a": 1}"#).unwrap();
        assert_eq!(safe_read_json(&path), serde_json::json!({"a": 1}));
    }
}
