//! `codepack doctor` — what this installation can see and do.
//!
//! Read-only, and never fails on a finding: its whole job is to answer questions before
//! something goes wrong, so a missing optional piece is reported, not raised.

use codepack_core::AppPaths;
use codepack_core::config::ai_presets;
use serde::Serialize;

use crate::error::Result;
use crate::exit::Outcome;
use crate::output::{self, Format};

#[derive(Debug, Serialize)]
pub(crate) struct DoctorReport {
    pub version: &'static str,
    pub json_schema_version: u32,
    pub paths: Paths,
    pub presets: Vec<PresetInfo>,
    pub profiles: Vec<String>,
    pub project_config_file: &'static str,
    /// Stated explicitly rather than implied: this is the product's central promise,
    /// and someone auditing the tool should be able to read it from its own output.
    pub network_access: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct Paths {
    pub settings_file: String,
    pub settings_file_exists: bool,
    pub database: String,
    pub database_exists: bool,
    /// Set only while a database from before the 2026-09-06 move is still sitting in the
    /// old place, so `database` above names a file that does not exist yet.
    ///
    /// An added field rather than a changed one: a consumer of `doctor --json` that has
    /// never heard of it reads exactly what it read before. It disappears — as `null` —
    /// the moment the database is opened, because opening it performs the move.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_superseded: Option<String>,
    pub user_profiles_file: String,
    pub user_profiles_file_exists: bool,
    pub(crate) model_limits_file: String,
    pub(crate) model_limits_file_exists: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct PresetInfo {
    pub name: &'static str,
    pub description: &'static str,
    pub export_profile: &'static str,
    pub safe_export_mode: &'static str,
}

pub(crate) fn run(format: Format) -> Result<Outcome> {
    let report = build()?;
    if format.is_json() {
        output::emit_json("doctor", &report)?;
    } else {
        print_human(&report);
    }
    Ok(Outcome::Success)
}

fn build() -> Result<DoctorReport> {
    let app_paths = AppPaths::resolve()?;
    let settings_file = app_paths.settings_file();
    let database = app_paths.db_file();
    let superseded = Some(app_paths.superseded_db_file()).filter(|old| *old != database);
    let user_profiles_file = app_paths.user_profiles_file();
    let model_limits_file = app_paths.model_limits_file();

    // A profiles file that exists but is corrupt is reported as "no profiles" here
    // rather than failing: `doctor` is what a user runs *because* something is wrong,
    // so it must survive a broken file long enough to show them the path to it.
    let profiles = codepack_core::profiles::load(&user_profiles_file)
        .map(|loaded| loaded.file.profiles.keys().cloned().collect())
        .unwrap_or_default();

    Ok(DoctorReport {
        version: env!("CARGO_PKG_VERSION"),
        json_schema_version: crate::output::JSON_SCHEMA_VERSION,
        paths: Paths {
            settings_file_exists: settings_file.is_file(),
            settings_file: settings_file.display().to_string(),
            database_exists: database.is_file(),
            database: database.display().to_string(),
            // `doctor` is read-only by contract, so it reports the pending move rather
            // than performing it. Without this a user upgrading on Linux would be told a
            // path, look there, and find nothing.
            database_superseded: superseded
                .filter(|path| path.is_file())
                .map(|path| path.display().to_string()),
            user_profiles_file_exists: user_profiles_file.is_file(),
            user_profiles_file: user_profiles_file.display().to_string(),
            model_limits_file_exists: model_limits_file.is_file(),
            model_limits_file: model_limits_file.display().to_string(),
        },
        presets: ai_presets()
            .iter()
            .map(|preset| PresetInfo {
                name: preset.name,
                description: preset.description,
                export_profile: preset.export_profile,
                safe_export_mode: preset.safe_export_mode,
            })
            .collect(),
        profiles,
        project_config_file: codepack_core::config::PROJECT_CONFIG_FILE_NAME,
        network_access: "never; all analysis is local",
    })
}

fn print_human(report: &DoctorReport) {
    output::line(format!(
        "codepack {} (json schema v{})",
        report.version, report.json_schema_version
    ));
    output::line(format!("Network:  {}", report.network_access));
    output::line("");

    output::line("Paths:");
    for (label, path, exists) in [
        (
            "settings",
            &report.paths.settings_file,
            report.paths.settings_file_exists,
        ),
        (
            "history",
            &report.paths.database,
            report.paths.database_exists,
        ),
        (
            "profiles",
            &report.paths.user_profiles_file,
            report.paths.user_profiles_file_exists,
        ),
        (
            "model limits",
            &report.paths.model_limits_file,
            report.paths.model_limits_file_exists,
        ),
    ] {
        let mark = if exists { "present" } else { "absent" };
        output::line(format!("  {label:<13} {path} ({mark})"));
    }

    if let Some(superseded) = &report.paths.database_superseded {
        output::line(format!(
            "  {:<13} {superseded} (moves here on first use)",
            "history (old)"
        ));
    }

    output::line("");
    output::line(format!("Project config: {}", report.project_config_file));

    output::line("");
    output::line("Presets:");
    for preset in &report.presets {
        output::line(format!(
            "  {:<18} {} [{}, {}]",
            preset.name, preset.description, preset.export_profile, preset.safe_export_mode
        ));
    }

    output::line("");
    if report.profiles.is_empty() {
        output::line("Custom profiles: none");
    } else {
        output::line(format!("Custom profiles: {}", report.profiles.join(", ")));
    }
}
