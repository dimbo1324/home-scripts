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

/// Where a registered artifact actually is.
///
/// Both cases are real. A run that keeps its staging folder leaves the reports on disk;
/// the default run deletes it as soon as the archive is written, and then the bundle
/// *is* the archive — which is the case the first version of this module missed, so
/// `resources/list` came back empty after every ordinary export.
#[derive(Debug, Clone)]
enum Location {
    OnDisk(PathBuf),
    InArchive { archive: PathBuf, entry: String },
}

static REGISTRY: LazyLock<Mutex<BTreeMap<String, Location>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

fn registry() -> std::sync::MutexGuard<'static, BTreeMap<String, Location>> {
    REGISTRY.lock().unwrap_or_else(|error| error.into_inner())
}

impl Location {
    fn name(&self) -> String {
        match self {
            Location::OnDisk(path) => path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default(),
            Location::InArchive { entry, .. } => {
                entry.rsplit('/').next().unwrap_or(entry).to_string()
            }
        }
    }

    fn mime(&self) -> &'static str {
        match self {
            Location::OnDisk(path) => mime_for(path),
            Location::InArchive { entry, .. } => mime_for(Path::new(entry)),
        }
    }

    fn read(&self) -> std::result::Result<String, String> {
        match self {
            Location::OnDisk(path) => {
                std::fs::read_to_string(path).map_err(|error| error.to_string())
            }
            Location::InArchive { archive, entry } => read_archive_entry(archive, entry),
        }
    }
}

/// Reads one member of a produced archive.
///
/// Only ever called with an entry name this module itself recorded from that archive's
/// own directory, so nothing here is a path a client chose.
fn read_archive_entry(archive: &Path, entry: &str) -> std::result::Result<String, String> {
    codepack_archive::read_zip_entry_to_string(archive, entry).map_err(|error| error.to_string())
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

/// Whether a path names an artifact this module offers: an entry at the bundle's root,
/// or anything under its `reports` tree.
///
/// The copied project is what this excludes. Those are the user's own source files, they
/// are already on the agent's disk, and listing several thousand of them would bury the
/// thirty that are this tool's output.
fn is_bundle_artifact(relative: &str) -> bool {
    let normalised = relative.replace('\\', "/");
    let is_report = normalised.starts_with("reports/");
    let at_root = !normalised.trim_end_matches('/').contains('/');
    (is_report || at_root) && is_offered(Path::new(&normalised))
}

/// Replaces the registry with the artifacts of the bundle just produced.
///
/// `staging` is where the run assembled it and `archive` is what it wrote; whichever
/// still exists is what gets registered. The default run deletes the staging folder as
/// soon as the archive is written, so the archive is the usual answer.
///
/// Replaces rather than adds: the resources describe *the* bundle this session last
/// produced, and leaving an earlier export's reports listed beside a newer one's would
/// let an agent read a stale answer while believing it read the current one.
pub(crate) fn register_bundle(staging: &Path, archive: Option<&Path>) {
    let mut entries = BTreeMap::new();

    if staging.is_dir() {
        for file in collect(staging) {
            if let Some(uri) = uri_for(staging, &file) {
                entries.insert(uri, Location::OnDisk(file));
            }
        }
    }

    if entries.is_empty()
        && let Some(archive) = archive
    {
        entries = archive_entries(archive);
    }

    *registry() = entries;
}

/// The artifact members of a produced archive, as a registry.
///
/// A failure to open it registers nothing: an agent is told the bundle has no readable
/// resources, which is true, rather than being handed URIs that cannot be read.
fn archive_entries(archive: &Path) -> BTreeMap<String, Location> {
    let mut entries = BTreeMap::new();
    let Ok(names) = codepack_archive::list_zip_entries(archive) else {
        return entries;
    };

    for name in names {
        if !is_bundle_artifact(&name) {
            continue;
        }
        entries.insert(
            format!("codepack://bundle/{}", name.replace('\\', "/")),
            Location::InArchive {
                archive: archive.to_path_buf(),
                entry: name,
            },
        );
        if entries.len() >= MAX_RESOURCES {
            break;
        }
    }
    entries
}

/// Everything currently readable, in `resources/list` shape.
pub(crate) fn list() -> Vec<Value> {
    registry()
        .iter()
        .map(|(uri, location)| {
            let name = location.name();
            json!({
                "uri": uri,
                "name": if name.is_empty() { uri.clone() } else { name },
                "mimeType": location.mime(),
            })
        })
        .collect()
}

/// The contents of one registered resource, in `resources/read` shape.
///
/// `Err` for a URI that is not registered — which is the answer for every path on the
/// machine except this session's own output, and is given without reading anything.
pub(crate) fn read(uri: &str) -> std::result::Result<Value, String> {
    let location = registry().get(uri).cloned().ok_or_else(|| {
        format!(
            "{uri} is not one of this session's resources. Only the reports of a bundle \
             produced by codepack_export in this session can be read, and \
             resources/list names them."
        )
    })?;

    let text = location
        .read()
        .map_err(|error| format!("{uri} is registered but could not be read: {error}"))?;
    Ok(json!({
        "contents": [{
            "uri": uri,
            "mimeType": location.mime(),
            "text": text,
        }]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registry is process-wide, so these tests take a lock rather than racing each
    /// other into one another's fixtures.
    static SERIALISE: Mutex<()> = Mutex::new(());

    fn guard() -> std::sync::MutexGuard<'static, ()> {
        SERIALISE.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn bundle() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("manifest.json"), "{\"ok\":true}").unwrap();
        std::fs::write(dir.path().join("INDEX.md"), "# index\n").unwrap();
        // Not an artifact a model can read; a path to it would be no use.
        std::fs::write(dir.path().join("bundle.zip"), [0u8, 1, 2]).unwrap();

        let insights = dir.path().join("reports").join("insights");
        std::fs::create_dir_all(&insights).unwrap();
        std::fs::write(insights.join("06_security_scan.json"), "{}").unwrap();
        std::fs::write(insights.join("01_summary.txt"), "summary\n").unwrap();

        // The copied project is deliberately not walked: those are the user's own files.
        let project = dir.path().join("project").join("src");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("notes.md"), "private\n").unwrap();

        dir
    }

    fn uris() -> Vec<String> {
        list()
            .into_iter()
            .map(|entry| entry["uri"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn a_bundle_s_reports_become_readable_and_nothing_else_does() {
        let _lock = guard();
        let dir = bundle();
        register_bundle(dir.path(), None);

        let listed = uris();
        assert!(listed.contains(&"codepack://bundle/manifest.json".to_string()));
        assert!(listed.contains(&"codepack://bundle/INDEX.md".to_string()));
        assert!(
            listed
                .contains(&"codepack://bundle/reports/insights/06_security_scan.json".to_string())
        );
        // An archive is not a text artifact.
        assert!(!listed.iter().any(|uri| uri.ends_with("bundle.zip")));
        // And the user's own source tree is not this tool's output.
        assert!(!listed.iter().any(|uri| uri.contains("/project/")));
    }

    #[test]
    fn a_registered_resource_reads_back_with_its_type() {
        let _lock = guard();
        let dir = bundle();
        register_bundle(dir.path(), None);

        let read_back = read("codepack://bundle/reports/insights/01_summary.txt").unwrap();
        let entry = &read_back["contents"][0];
        assert_eq!(entry["text"], "summary\n");
        assert_eq!(entry["mimeType"], "text/plain");

        let json = read("codepack://bundle/manifest.json").unwrap();
        assert_eq!(json["contents"][0]["mimeType"], "application/json");
    }

    /// The security property: a URI this session did not produce is refused, and refused
    /// without touching the disk.
    #[test]
    fn an_unregistered_uri_is_refused() {
        let _lock = guard();
        let dir = bundle();
        register_bundle(dir.path(), None);

        for uri in [
            "file:///etc/passwd",
            "codepack://bundle/../../secrets.txt",
            "codepack://bundle/project/src/notes.md",
            "not even a uri",
        ] {
            let error = read(uri).unwrap_err();
            assert!(
                error.contains("not one of this session's resources"),
                "{uri}: {error}"
            );
        }
    }

    /// An earlier export's reports must not sit beside a newer one's, or an agent reads a
    /// stale answer believing it read the current one.
    #[test]
    fn registering_a_second_bundle_replaces_the_first() {
        let _lock = guard();
        let first = bundle();
        register_bundle(first.path(), None);
        assert!(read("codepack://bundle/INDEX.md").is_ok());

        let second = tempfile::tempdir().unwrap();
        std::fs::write(second.path().join("manifest.json"), "{}").unwrap();
        register_bundle(second.path(), None);

        assert!(read("codepack://bundle/INDEX.md").is_err());
        assert!(read("codepack://bundle/manifest.json").is_ok());
    }

    #[test]
    fn a_directory_that_is_not_a_bundle_registers_nothing() {
        let _lock = guard();
        let empty = tempfile::tempdir().unwrap();
        register_bundle(empty.path(), None);
        assert!(list().is_empty());
    }

    #[test]
    fn a_registered_file_that_has_since_gone_says_so() {
        let _lock = guard();
        let dir = bundle();
        register_bundle(dir.path(), None);
        std::fs::remove_file(dir.path().join("INDEX.md")).unwrap();

        let error = read("codepack://bundle/INDEX.md").unwrap_err();
        assert!(error.contains("could not be read"), "{error}");
    }

    #[test]
    fn every_listed_entry_carries_a_name_and_a_type() {
        let _lock = guard();
        let dir = bundle();
        register_bundle(dir.path(), None);

        for entry in list() {
            assert!(entry["uri"].as_str().is_some_and(|uri| !uri.is_empty()));
            assert!(entry["name"].as_str().is_some_and(|name| !name.is_empty()));
            assert!(
                entry["mimeType"]
                    .as_str()
                    .is_some_and(|mime| !mime.is_empty())
            );
        }
    }

    #[test]
    fn types_follow_the_extension() {
        assert_eq!(mime_for(Path::new("a.json")), "application/json");
        assert_eq!(mime_for(Path::new("a.sarif")), "application/json");
        assert_eq!(mime_for(Path::new("a.md")), "text/markdown");
        assert_eq!(mime_for(Path::new("a.html")), "text/html");
        assert_eq!(mime_for(Path::new("a.txt")), "text/plain");
        assert_eq!(mime_for(Path::new("a.mmd")), "text/plain");
    }

    // --- Reading a bundle that is only an archive -------------------------------------
    //
    // The case the first version of this module missed: an ordinary export deletes its
    // staging folder as soon as the archive is written, so by the time the tool
    // registers anything there is nothing on disk to register. Found by running the
    // server for real, not by a test.

    /// Builds a zip shaped like a produced bundle.
    fn bundle_archive(dir: &Path) -> std::path::PathBuf {
        use std::io::Write as _;

        let path = dir.join("demo_export.zip");
        let file = std::fs::File::create(&path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default();

        for (name, body) in [
            ("manifest.json", "{\"archives\":{}}"),
            (
                "reports/insights/06_security_scan.json",
                "{\"findings\":[]}",
            ),
            ("reports/insights/01_summary.txt", "summary\n"),
            // The copied project: the user's own files, deliberately not offered.
            ("project/src/notes.md", "private\n"),
            // Not a text artifact.
            ("reports/insights/diagram.png", "\0"),
        ] {
            zip.start_file(name, options).unwrap();
            zip.write_all(body.as_bytes()).unwrap();
        }
        zip.finish().unwrap();
        path
    }

    #[test]
    fn an_archive_is_registered_when_the_staging_folder_is_gone() {
        let _lock = guard();
        let dir = tempfile::tempdir().unwrap();
        let archive = bundle_archive(dir.path());
        // The staging folder the run used, already deleted — the default case.
        let staging = dir.path().join("staging-that-was-cleaned-up");

        register_bundle(&staging, Some(&archive));

        let listed = uris();
        assert!(
            listed.contains(&"codepack://bundle/manifest.json".to_string()),
            "{listed:?}"
        );
        assert!(
            listed
                .contains(&"codepack://bundle/reports/insights/06_security_scan.json".to_string())
        );
        assert!(!listed.iter().any(|uri| uri.contains("/project/")));
        assert!(!listed.iter().any(|uri| uri.ends_with(".png")));
    }

    #[test]
    fn an_archived_resource_reads_back_without_unpacking() {
        let _lock = guard();
        let dir = tempfile::tempdir().unwrap();
        let archive = bundle_archive(dir.path());
        register_bundle(&dir.path().join("gone"), Some(&archive));

        let read_back = read("codepack://bundle/reports/insights/01_summary.txt").unwrap();
        assert_eq!(read_back["contents"][0]["text"], "summary\n");
        assert_eq!(read_back["contents"][0]["mimeType"], "text/plain");

        // Nothing was extracted to do it.
        assert!(!dir.path().join("reports").exists());
    }

    /// A kept staging folder is still preferred: it is the same bundle, and reading a
    /// file is cheaper than opening an archive for every request.
    #[test]
    fn a_staging_folder_wins_over_the_archive_when_it_is_still_there() {
        let _lock = guard();
        let staging = bundle();
        let dir = tempfile::tempdir().unwrap();
        let archive = bundle_archive(dir.path());

        register_bundle(staging.path(), Some(&archive));

        // `INDEX.md` exists only in the staging fixture, so its presence identifies the
        // source that was used.
        assert!(read("codepack://bundle/INDEX.md").is_ok());
    }

    #[test]
    fn an_archive_that_cannot_be_opened_registers_nothing() {
        let _lock = guard();
        let dir = tempfile::tempdir().unwrap();
        let broken = dir.path().join("not-a-zip.zip");
        std::fs::write(&broken, b"this is not a zip").unwrap();

        register_bundle(&dir.path().join("gone"), Some(&broken));
        assert!(
            list().is_empty(),
            "an unreadable archive must not produce URIs"
        );
    }

    #[test]
    fn an_export_that_produced_no_archive_registers_nothing() {
        let _lock = guard();
        let dir = tempfile::tempdir().unwrap();
        register_bundle(&dir.path().join("gone"), None);
        assert!(list().is_empty());
    }

    #[test]
    fn only_root_and_report_artifacts_are_offered() {
        assert!(is_bundle_artifact("manifest.json"));
        assert!(is_bundle_artifact("INDEX.md"));
        assert!(is_bundle_artifact("reports/insights/01_summary.txt"));
        assert!(!is_bundle_artifact("project/src/main.rs"));
        assert!(!is_bundle_artifact("reports/insights/diagram.png"));
        assert!(!is_bundle_artifact("bundle.zip"));
    }
}
