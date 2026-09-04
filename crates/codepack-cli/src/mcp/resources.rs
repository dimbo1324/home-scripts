//! The reports of a bundle this session produced, offered as MCP resources.
//!
//! ## Why they exist
//!
//! Before this, an agent that called `codepack_export` got a summary and a path, and
//! then had to leave the protocol to read anything — shelling out, or asking the user.
//! The thirty reports the export just wrote are exactly what it wanted, so it can now
//! read them over the same pipe.
//!
//! ## Why only what this server wrote
//!
//! `resources/read` takes a URI from the client, and a server that opened whatever URI
//! it was handed would be a file-reading service wearing a scanner's name — reachable by
//! anything that can speak to the pipe, including a prompt-injected model. So the
//! registry is the authority: a URI is readable only because a `codepack_export` call in
//! *this* session registered it, and anything else is refused without touching the disk.
//!
//! The registry is per-process and is not persisted. A new session starts empty, which
//! is the honest state: it has produced nothing yet.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

use serde_json::{Value, json};

/// Extensions worth offering. Every one is a text artifact a model can read; an archive
/// or an image would only be a path it cannot use.
const OFFERED: [&str; 6] = ["json", "md", "txt", "sarif", "html", "mmd"];

/// Ceiling on how many files one bundle contributes, so a pathological export cannot
/// turn `resources/list` into a directory dump.
const MAX_RESOURCES: usize = 500;

static REGISTRY: LazyLock<Mutex<BTreeMap<String, PathBuf>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

fn registry() -> std::sync::MutexGuard<'static, BTreeMap<String, PathBuf>> {
    REGISTRY.lock().unwrap_or_else(|error| error.into_inner())
}

/// A URI naming one artifact of one bundle.
///
/// `codepack://` rather than `file://`: these are not arbitrary files, they are this
/// session's own output, and a scheme of their own says so — a client cannot mistake the
/// list for permission to ask for anything else on the disk.
fn uri_for(staging: &Path, file: &Path) -> Option<String> {
    let relative = file.strip_prefix(staging).ok()?;
    let mut parts = Vec::new();
    for component in relative.components() {
        parts.push(component.as_os_str().to_string_lossy().into_owned());
    }
    Some(format!("codepack://bundle/{}", parts.join("/")))
}

fn is_offered(path: &Path) -> bool {
    path.extension()
        .map(|value| value.to_string_lossy().to_lowercase())
        .is_some_and(|extension| OFFERED.contains(&extension.as_str()))
}

fn mime_for(path: &Path) -> &'static str {
    match path
        .extension()
        .map(|value| value.to_string_lossy().to_lowercase())
        .unwrap_or_default()
        .as_str()
    {
        "json" | "sarif" => "application/json",
        "md" => "text/markdown",
        "html" => "text/html",
        _ => "text/plain",
    }
}

/// Collects the artifact files of a bundle: the reports tree, plus the manifest-level
/// files sitting at its root.
///
/// The copied project itself is deliberately not walked. Those are the user's own source
/// files, they are already on the agent's disk, and listing several thousand of them
/// would bury the thirty that are this tool's actual output.
fn collect(staging: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();

    if let Ok(entries) = std::fs::read_dir(staging) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && is_offered(&path) {
                found.push(path);
            }
        }
    }
    collect_recursively(&staging.join("reports"), &mut found);

    found.sort();
    found.truncate(MAX_RESOURCES);
    found
}

fn collect_recursively(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_recursively(&path, found);
        } else if is_offered(&path) {
            found.push(path);
        }
    }
}

/// Replaces the registry with the artifacts of the bundle at `staging`.
///
/// Replaces rather than adds: the resources describe *the* bundle this session last
/// produced, and leaving an earlier export's reports listed beside a newer one's would
/// let an agent read a stale answer while believing it read the current one.
pub(crate) fn register_bundle(staging: &Path) {
    let mut entries = BTreeMap::new();
    for file in collect(staging) {
        if let Some(uri) = uri_for(staging, &file) {
            entries.insert(uri, file);
        }
    }
    *registry() = entries;
}

/// Everything currently readable, in `resources/list` shape.
pub(crate) fn list() -> Vec<Value> {
    registry()
        .iter()
        .map(|(uri, path)| {
            json!({
                "uri": uri,
                "name": path
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_else(|| uri.clone()),
                "mimeType": mime_for(path),
            })
        })
        .collect()
}

/// The contents of one registered resource, in `resources/read` shape.
///
/// `Err` for a URI that is not registered — which is the answer for every path on the
/// machine except this session's own output, and is given without reading anything.
pub(crate) fn read(uri: &str) -> std::result::Result<Value, String> {
    let path = registry().get(uri).cloned().ok_or_else(|| {
        format!(
            "{uri} is not one of this session's resources. Only the reports of a bundle \
             produced by codepack_export in this session can be read, and \
             resources/list names them."
        )
    })?;

    let text = std::fs::read_to_string(&path)
        .map_err(|error| format!("{uri} is registered but could not be read: {error}"))?;
    Ok(json!({
        "contents": [{
            "uri": uri,
            "mimeType": mime_for(&path),
            "text": text,
        }]
    }))
}
