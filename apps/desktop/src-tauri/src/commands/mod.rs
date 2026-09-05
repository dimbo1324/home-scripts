//! The command surface the webview may call.
//!
//! Every function here is the *only* way the frontend can reach the filesystem, the
//! database or the engine — the webview itself is granted no `fs` permission at all
//! (`capabilities/default.json`). That is ROADMAP §3's isolation requirement, enforced
//! by capability rather than by convention.
//!
//! Each module owns one area, and each command is a thin adapter: resolve inputs, call
//! the already-tested core crate, shape the result into a [`crate::dto`] type. Logic
//! that belongs to the domain stays in the domain crates, so the GUI and the CLI cannot
//! drift apart in what an export actually means.

pub mod ai;
pub mod app_info;
pub mod export;
pub mod history;
pub mod project;
pub mod sanitize;
pub mod settings;
pub mod watch;
pub mod window;

use std::path::{Path, PathBuf};

use crate::error::{CommandError, CommandResult};

/// Validates a path the frontend supplied and turns it into an absolute directory.
///
/// The frontend only ever sends back a path the native picker produced, but "only ever"
/// is a statement about today's UI, not about the boundary. A command is a public entry
/// point: it validates what it is given.
pub fn resolve_project_root(path: &str) -> CommandResult<PathBuf> {
    let raw = Path::new(path);
    if raw.as_os_str().is_empty() {
        return Err(CommandError::new("no project directory was given"));
    }

    let resolved = raw
        .canonicalize()
        .map_err(|_| CommandError::new(format!("cannot open project directory: {path}")))?;

    if !resolved.is_dir() {
        return Err(CommandError::new(format!(
            "not a directory: {}",
            resolved.display()
        )));
    }
    Ok(resolved)
}

/// Checks that a path really is an export this installation produced.
///
/// The paired rule to [`resolve_project_root`], and for the reason this module already
/// states about project paths: "the frontend only ever sends back a path the native
/// picker produced, but 'only ever' is a statement about today's UI, not about the
/// boundary". Six commands took a `result_path` straight from the webview and used it to
/// unpack archives and hand files to the OS opener — which is the whole of the isolation
/// the capability file is there to provide, given away by the commands meant to hold it.
///
/// The check is against a *fact* rather than a shape: the history database records the
/// `result_path` of every run, so a path is acceptable exactly when a run produced it.
/// No amount of string cleverness can forge that.
///
/// Comparison is on canonicalised paths, so `.`-segments, a different case on Windows and
/// a short 8.3 spelling all resolve to the same answer.
pub fn resolve_export_result(result_path: &str) -> CommandResult<PathBuf> {
    let raw = Path::new(result_path);
    if raw.as_os_str().is_empty() {
        return Err(CommandError::new("no export result was given"));
    }
    let resolved = raw.canonicalize().map_err(|_| {
        CommandError::new(format!(
            "the export result is no longer where it was recorded: {result_path}"
        ))
    })?;

    let connection = open_database()?;
    let runs =
        codepack_storage::list_export_runs(&connection, None, 0).map_err(CommandError::new)?;
    let known = runs.iter().any(|run| {
        run.result_path
            .as_deref()
            .and_then(|recorded| Path::new(recorded).canonicalize().ok())
            .is_some_and(|recorded| recorded == resolved)
    });

    if !known {
        return Err(CommandError::new(format!(
            "{} is not an export this installation produced, so it will not be opened",
            resolved.display()
        )));
    }
    Ok(resolved)
}

/// Opens the history database, creating it and its parent directory if needed.
///
/// The path comes from `AppPaths`, never from the frontend: which database an export is
/// recorded in is not a decision the webview gets to make.
pub fn open_database() -> CommandResult<codepack_storage::Connection> {
    let paths = codepack_core::AppPaths::resolve()?;
    let db_file = paths.db_file();
    if let Some(parent) = db_file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(codepack_storage::open(&db_file)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_existing_directory_resolves_to_an_absolute_path() {
        let dir = tempfile::tempdir().unwrap();
        let resolved = resolve_project_root(&dir.path().display().to_string()).unwrap();
        assert!(resolved.is_absolute());
        assert!(resolved.is_dir());
    }

    #[test]
    fn an_empty_path_is_rejected_with_a_readable_message() {
        let error = resolve_project_root("").unwrap_err();
        assert!(error.message.contains("no project directory"));
    }

    #[test]
    fn a_missing_directory_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope");
        let error = resolve_project_root(&missing.display().to_string()).unwrap_err();
        assert!(error.message.contains("cannot open project directory"));
    }

    #[test]
    fn a_file_is_rejected_because_a_project_is_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("main.rs");
        std::fs::write(&file, "fn main() {}").unwrap();

        let error = resolve_project_root(&file.display().to_string()).unwrap_err();
        assert!(
            error.message.contains("not a directory"),
            "unexpected message: {}",
            error.message
        );
    }
}

#[cfg(test)]
mod export_result_tests {
    use super::*;

    /// The point of the check: a path the webview invents is refused, however well formed
    /// it looks. A freshly created temporary file cannot be in anyone's export history.
    #[test]
    fn a_path_no_run_produced_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let stranger = dir.path().join("bundle.zip");
        std::fs::write(&stranger, b"not a real export").unwrap();

        let error = resolve_export_result(&stranger.display().to_string())
            .expect_err("an unrecorded path must not be opened");
        assert!(
            format!("{error:?}").contains("not an export this installation produced"),
            "{error:?}"
        );
    }

    #[test]
    fn an_empty_or_missing_path_is_refused_before_the_database_is_touched() {
        assert!(resolve_export_result("").is_err());
        let dir = tempfile::tempdir().unwrap();
        assert!(
            resolve_export_result(&dir.path().join("absent.zip").display().to_string()).is_err()
        );
    }
}
