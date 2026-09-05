//! Reading and writing `~/.project_exporter_profiles.json`, ported from
//! `services/export_profiles.py::{ensure_user_profiles_file, load_user_profiles}`.

use std::collections::BTreeMap;
use std::path::Path;

use super::{UserProfile, UserProfilesFile, default_profiles_file};
use crate::error::{CoreError, Result};

/// What [`load`] found, keeping the entries it had to drop visible instead of losing
/// them silently.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LoadedProfiles {
    pub file: UserProfilesFile,
    /// Profile keys that were present but unusable (blank key, or a value that was not
    /// a JSON object). Legacy dropped these with no trace; surfacing them lets a caller
    /// tell the user why a profile they wrote never appeared.
    pub skipped_keys: Vec<String>,
}

/// Creates the file with legacy's two example profiles if it does not exist yet, and
/// reports whether it actually wrote anything.
///
/// Legacy's `ensure_user_profiles_file` let a write failure propagate; so does this.
pub fn ensure_file(path: &Path) -> Result<bool> {
    if path.exists() {
        return Ok(false);
    }
    save(path, &default_profiles_file())?;
    Ok(true)
}

/// Loads the profiles file.
///
/// **Deliberate divergence from legacy.** `load_user_profiles` wrapped the whole read
/// in `except Exception: return {}`, so an unreadable or corrupt file was
/// indistinguishable from "the user has no profiles" — the user's presets would quietly
/// vanish and the export would run with different settings than intended. A missing
/// file still means "no profiles" (that is the genuine first-run case), but a file that
/// exists and cannot be parsed is an error. This follows the precedent
/// `codepack-storage::import_legacy_history` already set for the same class of choice.
///
/// Individual bad entries are still skipped rather than fatal, matching legacy: one
/// malformed profile must not cost the user the other ones. They are reported in
/// [`LoadedProfiles::skipped_keys`].
pub fn load(path: &Path) -> Result<LoadedProfiles> {
    if !path.exists() {
        return Ok(LoadedProfiles::default());
    }

    let text = std::fs::read_to_string(path).map_err(|source| CoreError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let raw: serde_json::Value = serde_json::from_str(&text)
        .map_err(|source| CoreError::invalid_json("user export profiles", &source))?;

    let description = raw
        .get("description")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();

    // Legacy tolerates `profiles` being absent or not an object, treating both as "no
    // profiles" rather than as corruption — that shape is what its own default file
    // degrades to, not a parse failure.
    let mut profiles: BTreeMap<String, UserProfile> = BTreeMap::new();
    let mut skipped_keys: Vec<String> = Vec::new();
    if let Some(map) = raw.get("profiles").and_then(serde_json::Value::as_object) {
        for (key, value) in map {
            let trimmed = key.trim();
            if trimmed.is_empty() || !value.is_object() {
                skipped_keys.push(key.clone());
                continue;
            }
            match serde_json::from_value::<UserProfile>(value.clone()) {
                Ok(profile) => {
                    profiles.insert(trimmed.to_string(), profile);
                }
                Err(_) => skipped_keys.push(key.clone()),
            }
        }
    }

    Ok(LoadedProfiles {
        file: UserProfilesFile {
            description,
            profiles,
        },
        skipped_keys,
    })
}

/// Writes the file with legacy's own formatting (two-space indent, UTF-8, non-escaped
/// non-ASCII), so a file this code writes stays readable and hand-editable.
pub fn save(path: &Path, file: &UserProfilesFile) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| CoreError::Write {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let rendered = serde_json::to_string_pretty(file)
        .map_err(|source| CoreError::invalid_json("user export profiles", &source))?;
    std::fs::write(path, rendered).map_err(|source| CoreError::Write {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn a_missing_file_is_not_an_error_and_yields_no_profiles() {
        let dir = temp();
        let loaded = load(&dir.path().join("absent.json")).unwrap();
        assert!(loaded.file.profiles.is_empty());
        assert!(loaded.skipped_keys.is_empty());
    }

    #[test]
    fn ensure_file_writes_the_legacy_examples_once_and_then_leaves_them_alone() {
        let dir = temp();
        let path = dir.path().join(".project_exporter_profiles.json");

        assert!(
            ensure_file(&path).unwrap(),
            "first call must create the file"
        );
        std::fs::write(&path, r#"{"description":"mine","profiles":{}}"#).unwrap();

        assert!(
            !ensure_file(&path).unwrap(),
            "a second call must not overwrite what the user edited"
        );
        assert_eq!(load(&path).unwrap().file.description, "mine");
    }

    #[test]
    fn a_corrupt_file_is_an_error_rather_than_silently_no_profiles() {
        let dir = temp();
        let path = dir.path().join("profiles.json");
        std::fs::write(&path, "{ not json").unwrap();
        assert!(
            load(&path).is_err(),
            "legacy returned {{}} here, losing the user's presets without a word"
        );
    }

    #[test]
    fn one_bad_entry_is_skipped_and_reported_while_the_rest_load() {
        let dir = temp();
        let path = dir.path().join("profiles.json");
        std::fs::write(
            &path,
            r#"{"profiles":{"good":{"theme":"dark"},"bad":"not an object","  ":{}}}"#,
        )
        .unwrap();

        let loaded = load(&path).unwrap();
        assert_eq!(loaded.file.profiles.len(), 1);
        assert_eq!(loaded.file.profiles["good"].theme.as_deref(), Some("dark"));
        assert_eq!(loaded.skipped_keys.len(), 2);
    }

    #[test]
    fn keys_are_trimmed_as_legacy_trimmed_them() {
        let dir = temp();
        let path = dir.path().join("profiles.json");
        std::fs::write(&path, r#"{"profiles":{"  spaced  ":{"theme":"dark"}}}"#).unwrap();
        assert!(load(&path).unwrap().file.profiles.contains_key("spaced"));
    }

    #[test]
    fn round_trips_through_save_and_load() {
        let dir = temp();
        let path = dir.path().join("profiles.json");
        let original = default_profiles_file();
        save(&path, &original).unwrap();
        assert_eq!(load(&path).unwrap().file, original);
    }
}
