//! Legacy-import tests against checked-in fixtures under `tests/fixtures/` and a
//! JSON-shape contract guard for `Config`.

use std::path::{Path, PathBuf};

use codepack_core::config::{self, Config};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn full_legacy_file_imports_field_by_field() {
    let imported = config::import_settings(&fixture("legacy_settings_full.json")).unwrap();

    assert_eq!(imported.last_root, "/home/dev/project");
    assert!(imported.text_file_size_limit_enabled);
    assert_eq!(imported.max_text_file_mb, 8);
    assert!(imported.keep_staging_folder);
    assert!(!imported.include_project_in_zip);
    assert_eq!(
        imported.extra_ignored_dirs,
        vec!["vendor".to_string(), "tmp".to_string()]
    );
    assert_eq!(imported.export_profile, "security");
    assert_eq!(imported.safe_export_mode, "balanced");
    assert_eq!(imported.zip_part_limit_mb, 256);
    assert_eq!(imported.diff_export_mode, "git_ref");
    assert_eq!(imported.diff_base_ref, "main");
    assert_eq!(imported.diff_target_ref, "feature/x");
    assert!(imported.include_git_patch);
    assert_eq!(
        imported.custom_excluded_files,
        vec!["notes.txt".to_string()]
    );
    assert_eq!(imported.custom_excluded_extensions, vec!["log".to_string()]);
    assert_eq!(imported.always_include_files, vec!["README.md".to_string()]);
    assert_eq!(imported.always_include_dirs, vec!["docs".to_string()]);
    assert!(imported.incremental_export_enabled);
    assert_eq!(
        imported.developer_context,
        "Fix the export pipeline race condition."
    );
    assert_eq!(imported.theme, "dark");
    assert!(imported.watch_enabled);
    assert!(imported.watch_clipboard_auto_update);
    assert_eq!(imported.ui_zoom, 1.25);
    assert_eq!(imported.language, "en");
    assert_eq!(imported.prompt_goals, vec!["bug_hunt".to_string()]);

    // Absent from the legacy file entirely (a field that did not exist pre-rewrite);
    // #[serde(default)] fills it from Config::default().
    assert_eq!(imported.schema_version, config::CONFIG_SCHEMA_VERSION);
}

#[test]
fn missing_flag_file_migrates_using_the_one_real_legacy_rule() {
    let imported = config::import_settings(&fixture("legacy_settings_missing_flag.json")).unwrap();

    // max_text_file_mb (10) differs from the legacy default (5) -> inferred enabled.
    assert!(imported.text_file_size_limit_enabled);
    assert_eq!(imported.max_text_file_mb, 10);
    assert_eq!(imported.last_root, "/home/dev/old-project");
    assert_eq!(imported.theme, "light");

    // Everything else this ancient file never mentioned falls back to Config::default().
    let defaults = Config::default();
    assert_eq!(imported.export_profile, defaults.export_profile);
    assert_eq!(imported.prompt_goals, defaults.prompt_goals);
}

#[test]
fn default_max_text_file_mb_migrates_to_disabled() {
    // Same rule, opposite branch: an ancient file whose max_text_file_mb already
    // matches the (5) default infers the limit was never actually turned on.
    let json = r#"{"last_root": "/x", "max_text_file_mb": 5}"#;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    std::fs::write(&path, json).unwrap();

    let imported = config::import_settings(&path).unwrap();
    assert!(!imported.text_file_size_limit_enabled);
}

#[test]
fn unknown_keys_are_ignored_without_error() {
    let imported = config::import_settings(&fixture("legacy_settings_unknown_keys.json")).unwrap();

    assert_eq!(imported.last_root, "/home/dev/project");
    assert!(!imported.text_file_size_limit_enabled);
    assert_eq!(imported.theme, "dark");
}

#[test]
fn corrupt_file_is_a_hard_error_for_explicit_import() {
    // import_settings is the explicit-user-chosen-file path: it must error, matching
    // legacy Config.import_settings (which raises). The silent-fallback behavior of
    // Config.load() for a corrupt *default* settings location is covered separately in
    // config::io's unit tests.
    let result = config::import_settings(&fixture("legacy_settings_corrupt.json"));
    assert!(result.is_err());
}

/// Contract guard: every one of the 26 legacy fields (plus the new `schema_version`)
/// must be present in the serialized JSON with the expected value type, so a future
/// change cannot silently drop or retype a field without a test failing.
#[test]
fn json_shape_contains_all_expected_keys_with_expected_types() {
    let value = serde_json::to_value(Config::default()).unwrap();
    let object = value.as_object().unwrap();

    let string_fields = [
        "last_root",
        "export_profile",
        "safe_export_mode",
        // Added 2026-07-30 (owner decision). An added optional field with a default
        // does not bump `CONFIG_SCHEMA_VERSION` — that governance is in `config/mod.rs`
        // — but it must be listed here, or this guard stops guarding.
        "archive_format",
        "diff_export_mode",
        "diff_base_ref",
        "diff_target_ref",
        "developer_context",
        "theme",
        "language",
        // Added 2026-08-06 with the S13 handoff door. Same reasoning as the numeric
        // additions below: new fields with `#[serde(default)]`, so an old settings file
        // loads unchanged and takes the defaults.
        "ai_handoff_agent",
        "ai_handoff_question",
    ];
    let bool_fields = [
        "text_file_size_limit_enabled",
        "redact_secrets",
        "keep_staging_folder",
        "include_project_in_zip",
        "include_git_patch",
        "incremental_export_enabled",
        "watch_enabled",
        "watch_clipboard_auto_update",
        "redaction_labels",
        "strict_token_checksums",
    ];
    let number_fields = [
        "schema_version",
        "max_text_file_mb",
        "zip_part_limit_mb",
        "ui_zoom",
        // Added 2026-07-25. `CONFIG_SCHEMA_VERSION`'s own doc states a bump is required
        // only for a change that is *not* "a new field with a `#[serde(default)]`", and
        // both of these are exactly that: old config files load unchanged and take the
        // defaults (50 runs kept, no token budget).
        "history_keep_last_n",
        "token_budget",
    ];
    let array_fields = [
        "extra_ignored_dirs",
        "custom_excluded_files",
        "custom_excluded_extensions",
        "always_include_files",
        "always_include_dirs",
        "prompt_goals",
    ];

    for key in string_fields {
        assert!(
            object.get(key).is_some_and(|v| v.is_string()),
            "{key} should be a string"
        );
    }
    for key in bool_fields {
        assert!(
            object.get(key).is_some_and(|v| v.is_boolean()),
            "{key} should be a bool"
        );
    }
    for key in number_fields {
        assert!(
            object.get(key).is_some_and(|v| v.is_number()),
            "{key} should be a number"
        );
    }
    for key in array_fields {
        assert!(
            object.get(key).is_some_and(|v| v.is_array()),
            "{key} should be an array"
        );
    }

    let expected_key_count =
        string_fields.len() + bool_fields.len() + number_fields.len() + array_fields.len();
    assert_eq!(
        object.len(),
        expected_key_count,
        "unexpected key added or removed from Config"
    );
}
