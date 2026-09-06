//! Global settings, presets and profiles.
//!
//! Presets and profiles are applied **here**, in Rust, rather than by the frontend
//! setting the fields itself. That is deliberate: `codepack_core` already owns what
//! "Claude Code preset" or "minimal profile" means, and the CLI applies it from there.
//! A second implementation in TypeScript would be a second answer to the same question,
//! and the two would eventually disagree — with the GUI quietly exporting something
//! other than the CLI does for the same named preset.

use codepack_core::AppPaths;
use codepack_core::config::{self, Config, ai_presets};
use codepack_core::profiles;

use crate::error::{CommandError, CommandResult};

/// Loads the user's settings file, falling back to defaults when it is absent or
/// unreadable — the same forgiving behaviour `config::load` gives the CLI.
#[tauri::command]
pub fn load_global_settings() -> CommandResult<Config> {
    let paths = AppPaths::resolve()?;
    Ok(config::load(&paths))
}

#[tauri::command]
pub fn save_global_settings(config: Config) -> CommandResult<()> {
    let paths = AppPaths::resolve()?;
    config::save(&paths, &config)?;
    Ok(())
}

/// Applies a built-in AI preset onto `config` and returns the result.
///
/// An unknown name is an error rather than a silent no-op: the frontend only ever sends
/// a name it got from `get_app_info`, so a mismatch means the two sides have drifted,
/// and failing loudly is how that gets noticed.
#[tauri::command]
pub fn apply_preset(config: Config, preset_name: String) -> CommandResult<Config> {
    let wanted = preset_name.trim().to_lowercase();
    let preset = ai_presets()
        .iter()
        .find(|preset| preset.name.to_lowercase() == wanted)
        .ok_or_else(|| {
            let known = ai_presets()
                .iter()
                .map(|preset| preset.name)
                .collect::<Vec<_>>()
                .join(", ");
            CommandError::new(format!(
                "unknown preset `{preset_name}`; available presets: {known}"
            ))
        })?;

    let mut updated = config;
    updated.export_profile = preset.export_profile.to_string();
    updated.safe_export_mode = preset.safe_export_mode.to_string();
    updated.redact_secrets = preset.redact_secrets;
    updated.include_git_patch = preset.include_git_patch;
    updated.diff_export_mode = preset.diff_export_mode.to_string();
    updated.text_file_size_limit_enabled = preset.text_file_size_limit_enabled;
    if let Some(max_text_file_mb) = preset.max_text_file_mb {
        updated.max_text_file_mb = max_text_file_mb;
    }
    Ok(updated)
}

/// Applies a built-in or user-defined export profile.
///
/// Validated before applying, for the reason the CLI documents on its own `--profile`
/// flag: `apply_custom_profile` falls back to `full` for an unknown key, which would
/// *widen* the export while the UI still showed the name the user picked.
#[tauri::command]
pub fn apply_profile(config: Config, profile_name: String) -> CommandResult<Config> {
    let paths = AppPaths::resolve()?;
    let user_profiles = profiles::load(&paths.user_profiles_file())
        .map(|loaded| loaded.file)
        .unwrap_or_default();

    let known = config::EXPORT_PROFILES.contains(&profile_name.as_str())
        || user_profiles.profiles.contains_key(&profile_name);
    if !known {
        let mut names: Vec<String> = config::EXPORT_PROFILES
            .iter()
            .map(|name| (*name).to_string())
            .collect();
        names.extend(user_profiles.profiles.keys().cloned());
        return Err(CommandError::new(format!(
            "unknown profile `{profile_name}`; available profiles: {}",
            names.join(", ")
        )));
    }

    Ok(profiles::apply_custom_profile(
        &config,
        &user_profiles,
        &profile_name,
    ))
}

/// The settings that mean something different on every computer.
///
/// One list, used by both directions: export leaves these out, import keeps the ones this
/// machine already had. Written as a named function rather than a line inside each command
/// so the rule can be tested, and so adding a second machine-specific setting later is one
/// edit rather than two that can disagree.
///
/// Only `last_root` today. It holds the folder the last export ran in — on Windows
/// `C:\Users\<account>\...` — so it is both meaningless elsewhere and a disclosure of the
/// account name. `codepack_core::profiles` already treats it the same way: a profile may
/// not override it.
fn without_machine_fields(mut config: Config) -> (Config, bool) {
    let had_last_root = !config.last_root.is_empty();
    config.last_root = String::new();
    (config, had_last_root)
}

/// [`without_machine_fields`] in the other direction: an imported configuration takes this
/// machine's own values for those settings.
fn keeping_machine_fields(mut incoming: Config, current: &Config) -> Config {
    incoming.last_root = current.last_root.clone();
    incoming
}

/// Writes the current settings to a file the user picked, for another machine to import.
///
/// The two rules here are the CLI's, deliberately: `codepack settings export` clears
/// `last_root` and refuses an existing file without being told to replace it, and a GUI
/// that behaved differently would be a second answer to the same question — the exact
/// thing this module's header warns about for presets.
///
/// The difference is the overwrite: the native save dialog has already asked the user
/// about an existing file by the time this is called, so asking again here would be a
/// second confirmation for one decision. The CLI has no dialog, which is why it has a
/// flag.
#[tauri::command]
pub fn export_global_settings(path: String) -> CommandResult<bool> {
    let paths = AppPaths::resolve()?;
    let (settings, cleared) = without_machine_fields(config::load(&paths));

    config::export_settings(std::path::Path::new(&path), &settings)?;
    Ok(cleared)
}

/// Replaces the current settings with a file the user picked, and returns the result so
/// the screen can show what it now holds without a second round trip.
///
/// `last_root` is kept from this machine rather than taken from the file: it is the one
/// setting that means something different on every computer, so syncing a shared
/// configuration must not make the app forget where the user last worked.
///
/// A missing or malformed file is an error rather than a fall back to defaults. That is
/// `config::import_settings`'s own contract, and it matters here: the user picked this
/// file, so silently loading defaults would look exactly like success.
#[tauri::command]
pub fn import_global_settings(path: String) -> CommandResult<Config> {
    let paths = AppPaths::resolve()?;
    let current = config::load(&paths);

    let incoming = config::import_settings(std::path::Path::new(&path))?;
    let incoming = keeping_machine_fields(incoming, &current);

    config::save(&paths, &incoming)?;
    Ok(incoming)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two front ends must agree about what a shared settings file contains, or a team
    /// using both ends up with two configurations under one name. These pin the rule the
    /// CLI's `settings export/import` follows too (Q42).
    #[test]
    fn an_exported_configuration_drops_the_last_used_folder() {
        let settings = Config {
            last_root: "/home/someone/projects/client-work".to_string(),
            safe_export_mode: "strict".to_string(),
            ..Config::default()
        };

        let (shared, cleared) = without_machine_fields(settings);

        assert!(cleared, "the caller is told, so it can say so on screen");
        assert!(shared.last_root.is_empty());
        // What is worth sharing still travels.
        assert_eq!(shared.safe_export_mode, "strict");
    }

    /// Nothing to clear is not a failure, and must not be reported as a change.
    ///
    /// `Config::default()` is not the empty case: it seeds `last_root` from the home
    /// directory, which is exactly why that field is the one being kept out of a shared
    /// file. So the empty state is written out here rather than assumed.
    #[test]
    fn exporting_a_configuration_with_no_last_folder_reports_nothing_cleared() {
        let settings = Config {
            last_root: String::new(),
            ..Config::default()
        };
        let (_, cleared) = without_machine_fields(settings);
        assert!(!cleared);
    }

    #[test]
    fn importing_keeps_this_machines_last_folder() {
        let current = Config {
            last_root: "/home/me/my-project".to_string(),
            ..Config::default()
        };
        let incoming = Config {
            last_root: String::new(),
            safe_export_mode: "strict".to_string(),
            ..Config::default()
        };

        let merged = keeping_machine_fields(incoming, &current);

        assert_eq!(merged.last_root, "/home/me/my-project");
        assert_eq!(merged.safe_export_mode, "strict");
    }

    /// And a file that happens to carry somebody else's folder cannot impose it — which
    /// is the case that actually matters, since a hand-edited file may contain anything.
    #[test]
    fn a_file_carrying_someone_elses_folder_does_not_override_this_machine() {
        let current = Config {
            last_root: "/home/me/my-project".to_string(),
            ..Config::default()
        };
        let incoming = Config {
            last_root: "/home/someone-else/their-project".to_string(),
            ..Config::default()
        };

        let merged = keeping_machine_fields(incoming, &current);
        assert_eq!(merged.last_root, "/home/me/my-project");
    }

    #[test]
    fn a_preset_sets_the_same_fields_the_cli_sets() {
        // The reason presets are applied in Rust: one definition, two front ends.
        let preset = &ai_presets()[0];
        let updated = apply_preset(Config::default(), preset.name.to_string()).unwrap();

        assert_eq!(updated.export_profile, preset.export_profile);
        assert_eq!(updated.safe_export_mode, preset.safe_export_mode);
        assert_eq!(updated.redact_secrets, preset.redact_secrets);
        assert_eq!(updated.include_git_patch, preset.include_git_patch);
        assert_eq!(updated.diff_export_mode, preset.diff_export_mode);
    }

    #[test]
    fn preset_lookup_is_case_insensitive_like_the_cli() {
        let name = ai_presets()[0].name;
        assert!(apply_preset(Config::default(), name.to_uppercase()).is_ok());
    }

    #[test]
    fn an_unknown_preset_is_rejected_and_the_message_lists_the_real_ones() {
        let error = apply_preset(Config::default(), "clade".to_string()).unwrap_err();
        assert!(error.message.contains("clade"));
        for preset in ai_presets() {
            assert!(
                error.message.contains(preset.name),
                "message should list `{}`: {}",
                preset.name,
                error.message
            );
        }
    }

    #[test]
    fn a_preset_leaves_unrelated_settings_alone() {
        // Applying a preset must not silently reset the user's other choices.
        let before = Config {
            developer_context: "refactor the auth module".to_string(),
            keep_staging_folder: true,
            ..Config::default()
        };
        let after = apply_preset(before.clone(), ai_presets()[0].name.to_string()).unwrap();

        assert_eq!(after.developer_context, before.developer_context);
        assert_eq!(after.keep_staging_folder, before.keep_staging_folder);
    }

    #[test]
    fn every_offered_preset_can_actually_be_applied() {
        // Guards the pairing between `get_app_info`'s list and this lookup.
        for preset in super::super::app_info::get_app_info().presets {
            assert!(
                apply_preset(Config::default(), preset.name.clone()).is_ok(),
                "preset `{}` is offered but cannot be applied",
                preset.name
            );
        }
    }
}
