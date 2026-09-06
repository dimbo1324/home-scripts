//! `codepack settings export|import` — moving one configuration between machines.
//!
//! Named `settings_file`, not `settings`, because [`crate::settings`] already exists and
//! means something else: it resolves the *effective* settings for one run out of flags,
//! the project config and the global file. This module is the command that reads and
//! writes that global file. Two modules called `settings` in one crate compiled only
//! with an aliased import, and an alias would have hidden the ambiguity rather than
//! removed it.
//!
//! ## Why it exists
//!
//! `codepack_core::config::{export_settings, import_settings}` were written, tested, and
//! called by nothing — no command, no screen (audit 2026-09-05 No. 27). The owner's
//! decision was to wire them up rather than delete them, because a team wants one
//! configuration on every machine: the same safe mode, the same ignored directories, the
//! same profile, so two people exporting the same project produce the same bundle
//! (Q42, 2026-09-06).
//!
//! ## `last_root` does not travel
//!
//! It holds the folder the last export ran in — on Windows `C:\Users\<account>\...`. On
//! somebody else's machine that path is meaningless, and it carries an account name to
//! whoever receives the file. Export therefore clears it, and says so rather than doing
//! it quietly; import keeps whatever this machine already had, so syncing a shared
//! configuration does not make everyone's app forget where they last worked. Nothing
//! else is filtered: everything else in `Config` is a real preference somebody may share.
//!
//! The same reasoning the profiles system already applies — `codepack_core::profiles`
//! leaves `last_root`, `ui_zoom` and `language` out of what a profile may override.

use std::path::Path;

use serde::Serialize;

use crate::cli::{SettingsArgs, SettingsCommand};
use crate::error::{CliError, Result};
use crate::exit::Outcome;
use crate::output::{self, Format};

#[derive(Debug, Serialize)]
pub(crate) struct SettingsReport {
    /// `export` or `import`.
    pub action: &'static str,
    /// The file written or read, as the user gave it.
    pub path: String,
    /// True when `last_root` was cleared on the way out. Reported rather than assumed,
    /// so a reader of `--json` can see the export is not a byte copy of their file.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub last_root_cleared: bool,
    /// How many settings the imported file changed. Zero is a real answer — importing a
    /// file that matches what is already there is not a failure, and saying "0 changed"
    /// is more useful than silence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed: Option<usize>,
}

pub(crate) fn run(args: &SettingsArgs, format: Format) -> Result<Outcome> {
    let report = match &args.command {
        SettingsCommand::Export(export) => export_to(&export.path, export.force)?,
        SettingsCommand::Import(import) => import_from(&import.path)?,
    };

    if format.is_json() {
        output::emit_json("settings", &report)?;
    } else {
        print_human(&report);
    }
    Ok(Outcome::Success)
}

/// Writes the current global settings to `path`.
///
/// Refuses an existing file without `--force`, the same rule `init --hook` applies to a
/// hook it did not write. A configuration people have edited is worth exactly as much as
/// a hook they have edited, and the command that overwrites it silently is the one they
/// stop trusting.
fn export_to(path: &Path, force: bool) -> Result<SettingsReport> {
    if path.exists() && !force {
        return Err(CliError::message(format!(
            "{} already exists. Re-run with --force to replace it.",
            path.display()
        )));
    }

    let app_paths = codepack_core::AppPaths::resolve()?;
    let mut config = codepack_core::config::load(&app_paths);

    let last_root_cleared = !config.last_root.is_empty();
    config.last_root = String::new();

    codepack_core::config::export_settings(path, &config)?;
    Ok(SettingsReport {
        action: "export",
        path: path.display().to_string(),
        last_root_cleared,
        changed: None,
    })
}

/// Replaces the global settings with the contents of `path`.
///
/// No `--force`: replacing the settings is the whole meaning of the word "import", and a
/// flag required for a command's only function trains people to pass it without reading.
/// What the command does instead is *say what changed*, so an unexpected import is
/// visible immediately rather than discovered at the next export.
///
/// The file is parsed and validated before anything is written — `import_settings` errors
/// on a missing or malformed file rather than falling back to defaults, deliberately,
/// because the user named this file on purpose.
fn import_from(path: &Path) -> Result<SettingsReport> {
    let mut incoming = codepack_core::config::import_settings(path)?;

    let app_paths = codepack_core::AppPaths::resolve()?;
    let current = codepack_core::config::load(&app_paths);

    // `last_root` stays this machine's, for the same reason export leaves it behind: it
    // names a folder on one computer. Without this, syncing a team configuration would
    // make everyone's app forget where they last worked — and it showed up the first time
    // the round trip was actually run, as a fourth "changed setting" nobody had edited.
    incoming.last_root = current.last_root.clone();

    let changed = count_differences(&current, &incoming);

    codepack_core::config::save(&app_paths, &incoming)?;
    Ok(SettingsReport {
        action: "import",
        path: path.display().to_string(),
        last_root_cleared: false,
        changed: Some(changed),
    })
}

/// How many top-level settings differ between two configurations.
///
/// Compared through their JSON rather than field by field: `Config` has thirty-odd
/// fields and a hand-written comparison would be one more place to forget a new one —
/// which for a "what changed" report means quietly under-reporting.
fn count_differences(
    before: &codepack_core::config::Config,
    after: &codepack_core::config::Config,
) -> usize {
    let (Ok(before), Ok(after)) = (serde_json::to_value(before), serde_json::to_value(after))
    else {
        // Serialisation cannot fail for this type, and if it somehow did, the import has
        // still happened — reporting an unknown count is better than failing after the
        // write.
        return 0;
    };
    let (Some(before), Some(after)) = (before.as_object(), after.as_object()) else {
        return 0;
    };

    after
        .iter()
        .filter(|(key, value)| before.get(*key) != Some(*value))
        .count()
}

fn print_human(report: &SettingsReport) {
    match report.action {
        "export" => {
            output::line(format!("Settings written to {}", report.path));
            if report.last_root_cleared {
                output::line(
                    "Note:      the last-used folder was left out — it names a path on \
                     this machine and would be wrong on another.",
                );
            }
        }
        _ => {
            output::line(format!("Settings imported from {}", report.path));
            match report.changed {
                Some(0) => output::line("Nothing changed: the file matched the current settings."),
                Some(count) => output::line(format!("  {count} setting(s) changed")),
                None => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codepack_core::config::Config;

    #[test]
    fn an_identical_configuration_reports_no_differences() {
        let config = Config::default();
        assert_eq!(count_differences(&config, &config), 0);
    }

    #[test]
    fn each_changed_field_is_counted_once() {
        let before = Config::default();
        let after = Config {
            redact_secrets: !before.redact_secrets,
            export_profile: "quick".to_string(),
            ..before.clone()
        };
        assert_eq!(count_differences(&before, &after), 2);
    }

    /// A list changing counts as one setting, not one per element — the report is about
    /// settings a person recognises, not about JSON nodes.
    #[test]
    fn a_changed_list_counts_as_one_setting() {
        let before = Config::default();
        let after = Config {
            extra_ignored_dirs: vec!["vendor".to_string(), "third_party".to_string()],
            ..before.clone()
        };
        assert_eq!(count_differences(&before, &after), 1);
    }
}
