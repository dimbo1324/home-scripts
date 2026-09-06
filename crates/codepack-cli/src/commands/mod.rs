//! One module per command, plus the setup they share.

pub(crate) mod completions;
pub(crate) mod doctor;
pub(crate) mod explain;
pub(crate) mod export;
pub(crate) mod handoff;
pub(crate) mod history;
pub(crate) mod init;
pub(crate) mod preview;
pub(crate) mod sanitize;
pub(crate) mod scan;
pub(crate) mod settings_file;
pub(crate) mod verify;

use std::path::{Path, PathBuf};

use codepack_core::AppPaths;
use codepack_core::config::Config;

use crate::cli::ProjectArgs;
use crate::error::{CliError, Result};
use crate::settings::{self, ResolutionTrace};

/// Everything a project-reading command needs, resolved once.
pub(crate) struct ProjectContext {
    pub root: PathBuf,
    pub config: Config,
    pub trace: ResolutionTrace,
}

/// Canonicalizes the project path and resolves configuration from all four layers.
///
/// The path is canonicalized because it lands in `manifest.json`, in the export history
/// and in the database's project identity: `.` and an absolute path must name the same
/// project, or every relative invocation creates a new history line.
pub(crate) fn prepare(args: &ProjectArgs) -> Result<ProjectContext> {
    let root = resolve_project_root(&args.path)?;
    let app_paths = AppPaths::resolve()?;
    let global = codepack_core::config::load(&app_paths);

    // A profile can only be applied if the user's profiles file can be read. A broken
    // one is an error rather than "no profiles", matching `codepack-core::profiles`.
    let user_profiles = if args.profile.is_some() {
        codepack_core::profiles::load(&app_paths.user_profiles_file())?.file
    } else {
        codepack_core::profiles::UserProfilesFile::default()
    };

    // Loaded only when `--budget` actually named a model. Reading the override file
    // otherwise would turn a malformed one into an error for every command, including
    // the ones that never consult a context window.
    let model_limits = match args.budget {
        Some(settings::BudgetSpec::Model(_)) => {
            codepack_tokens::ModelContextLimits::load_or_default(&app_paths.model_limits_file())
                .map_err(|error| CliError::message(error.to_string()))?
        }
        _ => codepack_tokens::ModelContextLimits::default(),
    };

    let (config, trace) = settings::resolve(
        global,
        &root,
        &args.overrides(),
        &user_profiles,
        &model_limits,
    )?;
    Ok(ProjectContext {
        root,
        config,
        trace,
    })
}

impl ProjectContext {
    /// The trace, cloned for serialization. A command reports where its settings came
    /// from so a user can see why an export behaved the way it did.
    pub(crate) fn resolution_for_output(&self) -> ResolutionTrace {
        self.trace.clone()
    }
}

/// Turns a user-supplied path into an absolute, existing project directory.
pub(crate) fn resolve_project_root(path: &Path) -> Result<PathBuf> {
    if !path.exists() {
        return Err(CliError::message(format!(
            "{} does not exist",
            path.display()
        )));
    }
    if !path.is_dir() {
        return Err(CliError::NotADirectory {
            path: path.to_path_buf(),
        });
    }
    canonicalize_existing(path)
}

/// `std::fs::canonicalize` returns a `\\?\`-prefixed path on Windows, which is correct
/// but leaks into every artifact and error message the user reads. Strip that prefix
/// when it is safe to do so; everywhere else this is plain canonicalization.
pub(crate) fn canonicalize_existing(path: &Path) -> Result<PathBuf> {
    codepack_core::canonicalize_existing(path).map_err(|source| CliError::Read {
        path: path.to_path_buf(),
        source,
    })
}

/// Opens the history database, creating its directory if needed.
pub(crate) fn open_history_db() -> Result<codepack_storage::Connection> {
    let app_paths = AppPaths::resolve()?;
    let db_file = app_paths.db_file();
    if let Some(parent) = db_file.parent() {
        std::fs::create_dir_all(parent).map_err(|source| CliError::Read {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    Ok(codepack_storage::open(&db_file)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_path_is_rejected_by_name() {
        let error = resolve_project_root(Path::new("definitely-not-here-9f3b")).unwrap_err();
        assert!(error.to_string().contains("definitely-not-here-9f3b"));
    }

    #[test]
    fn a_file_is_not_a_project() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.txt");
        std::fs::write(&file, "x").unwrap();
        assert!(matches!(
            resolve_project_root(&file),
            Err(CliError::NotADirectory { .. })
        ));
    }

    #[test]
    fn the_root_comes_back_absolute_so_project_identity_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let resolved = resolve_project_root(dir.path()).unwrap();
        assert!(resolved.is_absolute());
    }

    #[test]
    fn windows_verbatim_prefixes_do_not_leak_into_user_facing_paths() {
        let dir = tempfile::tempdir().unwrap();
        let resolved = resolve_project_root(dir.path()).unwrap();
        assert!(
            !resolved.to_string_lossy().starts_with(r"\\?\"),
            "a verbatim path would appear in manifest.json and in every message: {}",
            resolved.display()
        );
    }
}
