//! Load/save, ported from `config.py`'s `Config.load`/`save`/`export_settings`/
//! `import_settings`.

use std::fs;
use std::path::Path;

use serde_json::Value;

use super::Config;
use super::legacy::migrate_legacy_settings;
use crate::error::{CoreError, Result};
use crate::paths::AppPaths;

/// Loads settings from `paths.settings_file()`. A missing file, invalid JSON, or a
/// known field with the wrong JSON type all fall back to `Config::default()` — matches
/// legacy `Config.load()` in that a bad file never surfaces an error to the caller.
///
/// Not identical to legacy in one respect: legacy's untyped dataclass would happily
/// store a single wrong-typed field (e.g. a string where a bool was expected) and keep
/// every other field from the same file; `serde`'s strict typing means one bad known
/// field here discards the *whole* file, falling back to full defaults. This is a
/// consequence of static typing, not a deliberate parity gap, and is arguably safer —
/// legacy's silent wrong-typed storage could misbehave unpredictably wherever that
/// field was later read as if it were the declared type.
pub fn load(paths: &AppPaths) -> Config {
    let Ok(text) = fs::read_to_string(paths.settings_file()) else {
        return Config::default();
    };
    parse_settings(&text).unwrap_or_default()
}

fn parse_settings(text: &str) -> Option<Config> {
    let mut value: Value = serde_json::from_str(text).ok()?;
    if let Value::Object(data) = &mut value {
        migrate_legacy_settings(data);
    }
    serde_json::from_value(value).ok()
}

/// Writes `config` to `paths.settings_file()`, creating the settings directory if
/// it does not exist yet.
pub fn save(paths: &AppPaths, config: &Config) -> Result<()> {
    write_settings(&paths.settings_file(), config)
}

fn write_settings(path: &Path, config: &Config) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| CoreError::Write {
            path: path.to_path_buf(),
            source,
        })?;
    }
    let json = serde_json::to_string_pretty(config)
        .map_err(|source| CoreError::invalid_json("Config", &source))?;
    fs::write(path, format!("{json}\n")).map_err(|source| CoreError::Write {
        path: path.to_path_buf(),
        source,
    })
}

/// Exports `config` to an arbitrary user-chosen path.
pub fn export_settings(path: &Path, config: &Config) -> Result<()> {
    write_settings(path, config)
}

/// Imports settings from an arbitrary user-chosen path. Unlike `load`, a missing file
/// or invalid content is a genuine error here — matches legacy `Config.import_settings`,
/// which raises rather than silently falling back, because the user explicitly picked
/// this file.
pub fn import_settings(path: &Path) -> Result<Config> {
    let text = fs::read_to_string(path).map_err(|source| CoreError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mut value: Value =
        serde_json::from_str(&text).map_err(|source| CoreError::invalid_json("Config", &source))?;
    if let Value::Object(data) = &mut value {
        migrate_legacy_settings(data);
    }
    serde_json::from_value(value).map_err(|source| CoreError::invalid_json("Config", &source))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `serde_json::Error`'s own `Display` quotes the offending value: `invalid type:
    /// string "sk-live-…", expected a boolean`. That message is printed to stderr and
    /// lands in a CI log, so the value must never be in it (audit No. 11).
    #[test]
    fn a_wrong_typed_setting_is_reported_by_position_not_by_quoting_its_value() {
        let root = tempdir().unwrap();
        let path = root.path().join("settings.json");
        fs::write(
            &path,
            "{
  \"redact_secrets\": \"totally-fake-value-0001\"
}",
        )
        .unwrap();

        let error = import_settings(&path).expect_err("a string is not a boolean");
        let rendered = error.to_string();

        assert!(
            !rendered.contains("totally-fake-value-0001"),
            "the setting's value reached the message: {rendered}"
        );
        assert!(rendered.contains("line"), "{rendered}");
        assert!(rendered.contains("column"), "{rendered}");
    }
    use tempfile::tempdir;

    #[test]
    fn load_returns_default_when_settings_file_is_missing() {
        let root = tempdir().unwrap();
        let paths = AppPaths::for_root(root.path());
        assert_eq!(load(&paths), Config::default());
    }

    #[test]
    fn save_then_load_round_trips() {
        let root = tempdir().unwrap();
        let paths = AppPaths::for_root(root.path());
        let config = Config {
            theme: "dark".to_string(),
            prompt_goals: vec!["write_tests".to_string()],
            ..Config::default()
        };

        save(&paths, &config).unwrap();
        let loaded = load(&paths);
        assert_eq!(loaded, config);
    }

    #[test]
    fn load_falls_back_to_default_on_corrupt_json() {
        let root = tempdir().unwrap();
        let paths = AppPaths::for_root(root.path());
        fs::create_dir_all(paths.settings_dir()).unwrap();
        fs::write(paths.settings_file(), "{ not valid json").unwrap();

        assert_eq!(load(&paths), Config::default());
    }

    #[test]
    fn load_falls_back_to_default_when_a_known_field_has_the_wrong_type() {
        let root = tempdir().unwrap();
        let paths = AppPaths::for_root(root.path());
        fs::create_dir_all(paths.settings_dir()).unwrap();
        fs::write(paths.settings_file(), r#"{"redact_secrets": "definitely"}"#).unwrap();

        assert_eq!(load(&paths), Config::default());
    }

    #[test]
    fn import_settings_errors_on_missing_file() {
        let root = tempdir().unwrap();
        let missing = root.path().join("does-not-exist.json");
        assert!(import_settings(&missing).is_err());
    }

    #[test]
    fn import_settings_errors_on_corrupt_json() {
        let root = tempdir().unwrap();
        let path = root.path().join("settings.json");
        fs::write(&path, "not json at all").unwrap();
        assert!(import_settings(&path).is_err());
    }

    #[test]
    fn export_then_import_round_trips() {
        let root = tempdir().unwrap();
        let path = root.path().join("exported.json");
        let config = Config {
            language: "en".to_string(),
            ..Config::default()
        };

        export_settings(&path, &config).unwrap();
        let imported = import_settings(&path).unwrap();
        assert_eq!(imported, config);
    }
}
