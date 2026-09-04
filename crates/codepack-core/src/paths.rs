use std::path::{Path, PathBuf};

use crate::error::{CoreError, Result};

const APP_NAME: &str = "codepack";
const LEGACY_SETTINGS_FILE_NAME: &str = ".project_exporter_desktop.json";
const LEGACY_PROFILES_FILE_NAME: &str = ".project_exporter_profiles.json";
const MODEL_LIMITS_FILE_NAME: &str = "model_limits.json";
const LEGACY_HISTORY_FILE_NAME: &str = ".project_exporter_history.json";
const SETTINGS_FILE_NAME: &str = "settings.json";
const DB_FILE_NAME: &str = "codepack.db";

/// Which OS layout to resolve application directories for (BLUEPRINT §D.4).
///
/// TODO(cross-platform): `Mac` and `Linux` are commented out, not removed. Owner decision
/// 2026-07-26 (`docs/__arch__/open-questions.md`) narrows the build scope to Windows
/// 10/11; BLUEPRINT §B.4 still declares cross-platform a product goal, so the layouts
/// stay here as the specification of what has to come back. Restoring them means
/// uncommenting the variants, the `current_os` detection, the `layout` arms, the
/// `resolve_base_dirs` arms, and the two layout tests — they were commented together and
/// belong together. Also rename `layout`'s `_home_dir` back to `home_dir` and delete the
/// paragraph above it explaining the underscore, which becomes false at that point.
///
/// Note what this does *not* do: it does not stop the crate compiling elsewhere. On a
/// non-Windows host `AppPaths::resolve()` now returns `NoAppDirectories` at runtime,
/// because `current_os` claims Windows and the Windows arm demands `APPDATA`. The CLI
/// suite will not catch that either, since it injects `APPDATA`/`LOCALAPPDATA` on every
/// platform. So restoring cross-platform support starts from a wrong *runtime*, not from a
/// compile error — which is worth knowing alongside Q21.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Os {
    Windows,
    // Mac,
    // Linux,
}

fn current_os() -> Os {
    // TODO(cross-platform): restore real detection along with the `Os` variants:
    //
    //   if cfg!(target_os = "windows") {
    //       Os::Windows
    //   } else if cfg!(target_os = "macos") {
    //       Os::Mac
    //   } else {
    //       Os::Linux
    //   }
    Os::Windows
}

/// `_home_dir` is unused while only the Windows layout exists — the macOS and Linux log
/// directories are the ones derived from the home directory. It keeps its place in the
/// signature so restoring those arms is a comment change, not an API change.
fn layout(
    os: Os,
    _home_dir: &Path,
    config_dir: &Path,
    data_local_dir: &Path,
) -> (PathBuf, PathBuf) {
    let settings_dir = config_dir.join(APP_NAME);
    let log_dir = match os {
        Os::Windows => data_local_dir.join(APP_NAME).join("logs"),
        // TODO(cross-platform):
        // Os::Mac => _home_dir.join("Library").join("Logs").join(APP_NAME),
        // Os::Linux => _home_dir.join(".local").join("state").join(APP_NAME),
    };
    (settings_dir, log_dir)
}

pub(crate) fn home_dir_from_env() -> Option<PathBuf> {
    // `HOME` stays in the chain after `USERPROFILE`: it is what Git Bash and MSYS set on
    // Windows, so a developer running the CLI from that shell still resolves a home
    // directory. This is not the cross-platform branch — that one was the `else`.
    //
    // TODO(cross-platform): restore the non-Windows branch:
    //
    //   } else {
    //       std::env::var_os("HOME").map(PathBuf::from)
    //   }
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
}

fn resolve_base_dirs() -> Result<(PathBuf, PathBuf, PathBuf)> {
    let home_dir = home_dir_from_env().ok_or(CoreError::NoAppDirectories)?;
    let (config_dir, data_local_dir) = match current_os() {
        Os::Windows => {
            let roaming = std::env::var_os("APPDATA")
                .map(PathBuf::from)
                .ok_or(CoreError::NoAppDirectories)?;
            let local = std::env::var_os("LOCALAPPDATA")
                .map(PathBuf::from)
                .ok_or(CoreError::NoAppDirectories)?;
            (roaming, local)
        } // TODO(cross-platform):
          // Os::Mac => (
          //     home_dir.join("Library").join("Application Support"),
          //     PathBuf::new(),
          // ),
          // Os::Linux => {
          //     let config = std::env::var_os("XDG_CONFIG_HOME")
          //         .map(PathBuf::from)
          //         .unwrap_or_else(|| home_dir.join(".config"));
          //     (config, PathBuf::new())
          // }
    };
    Ok((home_dir, config_dir, data_local_dir))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPaths {
    home_dir: PathBuf,
    settings_dir: PathBuf,
    log_dir: PathBuf,
}

impl AppPaths {
    pub fn resolve() -> Result<Self> {
        let (home_dir, config_dir, data_local_dir) = resolve_base_dirs()?;
        let (settings_dir, log_dir) = layout(current_os(), &home_dir, &config_dir, &data_local_dir);
        Ok(Self {
            home_dir,
            settings_dir,
            log_dir,
        })
    }

    pub fn for_root(root: &Path) -> Self {
        let home_dir = root.join("home");
        let config_dir = root.join("config");
        let data_local_dir = root.join("data_local");
        let (settings_dir, log_dir) = layout(current_os(), &home_dir, &config_dir, &data_local_dir);
        Self {
            home_dir,
            settings_dir,
            log_dir,
        }
    }

    pub fn settings_dir(&self) -> &Path {
        &self.settings_dir
    }

    pub fn log_dir(&self) -> &Path {
        &self.log_dir
    }

    pub fn settings_file(&self) -> PathBuf {
        self.settings_dir.join(SETTINGS_FILE_NAME)
    }

    pub fn legacy_settings_file(&self) -> PathBuf {
        self.home_dir.join(LEGACY_SETTINGS_FILE_NAME)
    }

    /// Mirrors legacy's `HISTORY_FILE = SETTINGS_FILE.with_name(".project_exporter_history.json")`
    /// (`export_history.py`): a flat JSON file sitting next to the legacy settings
    /// file in the user's home directory, read-only from this crate's perspective —
    /// `codepack-storage` (S5) imports it once, explicitly, into SQLite.
    pub fn legacy_history_file(&self) -> PathBuf {
        self.home_dir.join(LEGACY_HISTORY_FILE_NAME)
    }

    pub fn db_file(&self) -> PathBuf {
        self.settings_dir.join(DB_FILE_NAME)
    }

    /// Legacy's `USER_EXPORT_PROFILES_FILE` (`export_profiles.py`): the second settings
    /// file, holding user-defined export profiles. It stays in the home directory
    /// beside the legacy settings file rather than moving into `settings_dir`, because
    /// it is the very file existing installations already have — relocating it would
    /// orphan every profile a user has saved.
    pub fn user_profiles_file(&self) -> PathBuf {
        self.home_dir.join(LEGACY_PROFILES_FILE_NAME)
    }

    /// Optional override for the model context-window table
    /// ([`codepack_tokens::ModelContextLimits::load_or_default`], BLUEPRINT §B.2). Lives
    /// in `settings_dir`, not the home directory: it is new, so there is no legacy
    /// location to stay compatible with, and it is application data rather than
    /// something the user is expected to find by accident.
    pub fn model_limits_file(&self) -> PathBuf {
        self.settings_dir.join(MODEL_LIMITS_FILE_NAME)
    }
}

/// `std::fs::canonicalize` returns a `\\?\`-prefixed path on Windows, which is correct
/// but leaks into every artifact and error message a user reads. Strip that prefix when
/// it is safe to do so; everywhere else this is plain canonicalization.
///
/// The prefix stays on a UNC path (`\\?\UNC\...`), where removing it would produce a
/// path that no longer names the same thing.
pub fn canonicalize_existing(path: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
    let canonical = std::fs::canonicalize(path)?;
    let text = canonical.to_string_lossy();
    let stripped = text
        .strip_prefix(r"\\?\")
        .filter(|rest| !rest.starts_with("UNC\\"))
        .map(std::path::PathBuf::from);
    Ok(stripped.unwrap_or(canonical))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_layout_matches_blueprint_d4() {
        let (settings_dir, log_dir) = layout(
            Os::Windows,
            Path::new("C:/Users/dev"),
            Path::new("C:/Users/dev/AppData/Roaming"),
            Path::new("C:/Users/dev/AppData/Local"),
        );
        assert_eq!(
            settings_dir,
            Path::new("C:/Users/dev/AppData/Roaming/codepack")
        );
        assert_eq!(
            log_dir,
            Path::new("C:/Users/dev/AppData/Local/codepack/logs")
        );
    }

    // TODO(cross-platform): these two tests are commented out together with the `Os::Mac`
    // and `Os::Linux` layout arms they cover, so a commented-out branch never looks
    // tested. Restore them in the same change that restores the arms — they are the
    // BLUEPRINT §D.4 specification for those layouts, which is why they are kept verbatim
    // rather than deleted.
    //
    // #[test]
    // fn macos_layout_matches_blueprint_d4() {
    //     let (settings_dir, log_dir) = layout(
    //         Os::Mac,
    //         Path::new("/Users/dev"),
    //         Path::new("/Users/dev/Library/Application Support"),
    //         Path::new(""),
    //     );
    //     assert_eq!(
    //         settings_dir,
    //         Path::new("/Users/dev/Library/Application Support/codepack")
    //     );
    //     assert_eq!(log_dir, Path::new("/Users/dev/Library/Logs/codepack"));
    // }
    //
    // #[test]
    // fn linux_layout_matches_blueprint_d4() {
    //     let (settings_dir, log_dir) = layout(
    //         Os::Linux,
    //         Path::new("/home/dev"),
    //         Path::new("/home/dev/.config"),
    //         Path::new(""),
    //     );
    //     assert_eq!(settings_dir, Path::new("/home/dev/.config/codepack"));
    //     assert_eq!(log_dir, Path::new("/home/dev/.local/state/codepack"));
    // }

    #[test]
    fn for_root_never_leaves_the_given_root() {
        let root = Path::new("/tmp/codepack-test-root");
        let paths = AppPaths::for_root(root);
        assert!(paths.settings_dir().starts_with(root));
        assert!(paths.log_dir().starts_with(root));
        assert!(paths.legacy_settings_file().starts_with(root));
    }

    #[test]
    fn legacy_settings_file_is_a_flat_file_in_home() {
        let paths = AppPaths::for_root(Path::new("/tmp/codepack-test-root"));
        assert_eq!(
            paths.legacy_settings_file().file_name().unwrap(),
            ".project_exporter_desktop.json"
        );
        assert_eq!(
            paths.legacy_settings_file().parent(),
            Some(paths.home_dir.as_path())
        );
    }

    #[test]
    fn settings_file_lives_under_settings_dir() {
        let paths = AppPaths::for_root(Path::new("/tmp/codepack-test-root"));
        assert_eq!(paths.settings_file().parent(), Some(paths.settings_dir()));
        assert_eq!(paths.settings_file().file_name().unwrap(), "settings.json");
    }

    #[test]
    fn legacy_history_file_is_a_flat_file_in_home_next_to_legacy_settings() {
        let paths = AppPaths::for_root(Path::new("/tmp/codepack-test-root"));
        assert_eq!(
            paths.legacy_history_file().file_name().unwrap(),
            ".project_exporter_history.json"
        );
        assert_eq!(
            paths.legacy_history_file().parent(),
            Some(paths.home_dir.as_path())
        );
        assert_eq!(
            paths.legacy_history_file().parent(),
            paths.legacy_settings_file().parent()
        );
    }

    #[test]
    fn db_file_lives_under_settings_dir() {
        let paths = AppPaths::for_root(Path::new("/tmp/codepack-test-root"));
        assert_eq!(paths.db_file().parent(), Some(paths.settings_dir()));
        assert_eq!(paths.db_file().file_name().unwrap(), "codepack.db");
    }

    #[test]
    fn user_profiles_file_sits_beside_the_legacy_settings_file() {
        let paths = AppPaths::for_root(Path::new("/tmp/codepack-test-root"));
        assert_eq!(
            paths.user_profiles_file().parent(),
            paths.legacy_settings_file().parent(),
            "existing installations already have this file in the home directory"
        );
        assert_eq!(
            paths.user_profiles_file().file_name().unwrap(),
            ".project_exporter_profiles.json"
        );
    }

    #[test]
    fn model_limits_file_lives_under_settings_dir() {
        let paths = AppPaths::for_root(Path::new("/tmp/codepack-test-root"));
        assert_eq!(
            paths.model_limits_file().parent(),
            Some(paths.settings_dir())
        );
        assert_eq!(
            paths.model_limits_file().file_name().unwrap(),
            "model_limits.json"
        );
    }
}
