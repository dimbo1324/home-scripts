//! `.codepack.toml` — per-project configuration, committed alongside the code
//! (BLUEPRINT §B.7, open question Q6, closed by owner decision 2026-07-25).
//!
//! The point of this file is that a **team** shares one set of export rules, the same
//! way it shares `.editorconfig` or `.gitignore`. The global settings file is per
//! machine and per user; this one travels with the repository.
//!
//! ## Why this lives in `codepack-core`
//!
//! It was introduced in S10 inside `codepack-cli`, which was right while the CLI was the
//! only front end. S11 added a second one, and a per-project format read by two programs
//! is a contract, not a detail of either: if the desktop shell carried its own copy of
//! the field list, a key added here would be silently ignored there, and a team would
//! get different exports from the GUI and from CI for the same committed file. One
//! declaration, both front ends.
//!
//! ## Deliberate choices
//!
//! * **TOML, not JSON.** This file is written by hand. `.exportignore` already
//!   established that per-project rules live in the repository as plain text.
//! * **Every field optional.** The file expresses *overrides*, not a whole `Config`.
//!   A project that only wants `safe_export_mode = "safe"` writes one line, and every
//!   other setting keeps coming from wherever it came from before.
//! * **Unknown keys are an error, not a shrug.** A misspelled `safe_moed` that is
//!   silently ignored means a team believes it is exporting safely when it is not.
//!   That failure is quiet, permanent and exactly the class this product exists to
//!   prevent, so `deny_unknown_fields` is the right side to err on.
//! * **Absent is not the same as empty.** No file means "no project-level opinion",
//!   which is the normal case and never an error.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::Config;

/// The file name looked for in the project root.
pub const PROJECT_CONFIG_FILE_NAME: &str = ".codepack.toml";

/// Why a `.codepack.toml` could not be used.
///
/// Separate from the crate's general `CoreError` so each front end can render it in its
/// own idiom while the *diagnosis* — which file, where in it, and what is wrong — is
/// produced in exactly one place.
#[derive(Debug)]
pub enum ProjectConfigError {
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    Syntax {
        path: PathBuf,
        /// `" at byte N"`, or empty when the parser could not locate the problem.
        span: String,
        message: String,
    },
}

impl std::fmt::Display for ProjectConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(formatter, "cannot read {}: {source}", path.display())
            }
            Self::Syntax {
                path,
                span,
                message,
            } => write!(
                formatter,
                "{} is not valid{span}: {message}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ProjectConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::Syntax { .. } => None,
        }
    }
}

/// Overrides a project can declare for itself.
///
/// The set is deliberately narrower than [`Config`]: it carries what a *team* would
/// agree on about exporting this repository, and omits per-user and per-machine settings
/// (`theme`, `ui_zoom`, `language`, `last_root`, watch behaviour). Committing those to a
/// shared repository would mean one developer's window scale overriding everyone else's.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    pub export_profile: Option<String>,
    pub safe_export_mode: Option<String>,
    pub diff_export_mode: Option<String>,
    pub diff_base_ref: Option<String>,
    pub diff_target_ref: Option<String>,
    pub redact_secrets: Option<bool>,
    pub include_git_patch: Option<bool>,
    pub include_project_in_zip: Option<bool>,
    pub keep_staging_folder: Option<bool>,
    pub text_file_size_limit_enabled: Option<bool>,
    pub max_text_file_mb: Option<u32>,
    pub zip_part_limit_mb: Option<u32>,
    pub token_budget: Option<u64>,
    pub history_keep_last_n: Option<u32>,
    pub extra_ignored_dirs: Option<Vec<String>>,
    pub custom_excluded_files: Option<Vec<String>>,
    pub custom_excluded_extensions: Option<Vec<String>>,
    pub always_include_files: Option<Vec<String>>,
    pub always_include_dirs: Option<Vec<String>>,
    pub developer_context: Option<String>,
    /// Stable per-secret redaction labels. A team decision rather than a personal one:
    /// it changes what every bundle produced from this repository looks like, and the
    /// people reading those bundles have to agree on what `<REDACTED:s1>` means.
    pub redaction_labels: Option<bool>,
    /// Whether a failed vendor checksum weakens a provider finding. A team decision:
    /// it changes what this repository's pipeline will and will not fail on.
    pub strict_token_checksums: Option<bool>,
}

impl ProjectConfig {
    /// Reads `.codepack.toml` from `project_root`. A missing file yields `None`.
    pub fn load(
        project_root: &Path,
    ) -> std::result::Result<Option<(PathBuf, Self)>, ProjectConfigError> {
        let path = project_root.join(PROJECT_CONFIG_FILE_NAME);
        if !path.is_file() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(&path).map_err(|source| ProjectConfigError::Read {
            path: path.clone(),
            source,
        })?;
        let parsed: Self = toml::from_str(&text).map_err(|error| {
            let span = match error.span() {
                Some(range) => format!(" at byte {}", range.start),
                None => String::new(),
            };
            ProjectConfigError::Syntax {
                path: path.clone(),
                span,
                message: error.message().to_string(),
            }
        })?;
        Ok(Some((path, parsed)))
    }

    /// Applies every field this file actually sets onto `config`, leaving the rest.
    pub fn apply_to(&self, config: &mut Config) {
        macro_rules! set {
            ($($field:ident),* $(,)?) => {
                $(
                    if let Some(value) = self.$field.clone() {
                        config.$field = value;
                    }
                )*
            };
        }
        set!(
            export_profile,
            safe_export_mode,
            diff_export_mode,
            diff_base_ref,
            diff_target_ref,
            redact_secrets,
            include_git_patch,
            include_project_in_zip,
            keep_staging_folder,
            text_file_size_limit_enabled,
            max_text_file_mb,
            zip_part_limit_mb,
            token_budget,
            history_keep_last_n,
            extra_ignored_dirs,
            custom_excluded_files,
            custom_excluded_extensions,
            always_include_files,
            always_include_dirs,
            developer_context,
            redaction_labels,
            strict_token_checksums,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project_with(contents: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(PROJECT_CONFIG_FILE_NAME), contents).unwrap();
        dir
    }

    #[test]
    fn a_project_without_the_file_has_no_opinion_and_that_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(ProjectConfig::load(dir.path()).unwrap().is_none());
    }

    #[test]
    fn a_single_line_file_overrides_only_that_field() {
        let dir = project_with("safe_export_mode = \"full\"\n");
        let (_, project) = ProjectConfig::load(dir.path()).unwrap().unwrap();

        let mut config = Config::default();
        let before = config.clone();
        project.apply_to(&mut config);

        assert_eq!(config.safe_export_mode, "full");
        assert_eq!(config.export_profile, before.export_profile);
        assert_eq!(config.redact_secrets, before.redact_secrets);
    }

    #[test]
    fn a_misspelled_key_is_rejected_and_the_message_names_it() {
        // The failure this file's strictness exists to prevent: a team believing it
        // exports safely because a typo was silently ignored.
        let dir = project_with("safe_moed = \"full\"\n");
        let error = ProjectConfig::load(dir.path()).unwrap_err();
        let rendered = error.to_string();

        assert!(rendered.contains(PROJECT_CONFIG_FILE_NAME), "{rendered}");
        assert!(rendered.contains("safe_moed"), "{rendered}");
    }

    #[test]
    fn every_field_can_be_set_and_reaches_the_config() {
        // Guards the `apply_to` macro list against a field being declared but never
        // wired — which would look exactly like the typo case above from the user's
        // side, while passing `deny_unknown_fields`.
        let dir = project_with(
            r#"
export_profile = "minimal"
safe_export_mode = "full"
diff_export_mode = "uncommitted"
diff_base_ref = "develop"
diff_target_ref = "feature"
redact_secrets = false
include_git_patch = true
include_project_in_zip = false
keep_staging_folder = true
text_file_size_limit_enabled = true
max_text_file_mb = 7
zip_part_limit_mb = 64
token_budget = 200000
history_keep_last_n = 5
extra_ignored_dirs = ["vendor"]
custom_excluded_files = ["notes.txt"]
custom_excluded_extensions = ["log"]
always_include_files = ["Makefile"]
always_include_dirs = ["docs"]
developer_context = "refactor auth"
"#,
        );
        let (_, project) = ProjectConfig::load(dir.path()).unwrap().unwrap();
        let mut config = Config::default();
        project.apply_to(&mut config);

        assert_eq!(config.export_profile, "minimal");
        assert_eq!(config.safe_export_mode, "full");
        assert_eq!(config.diff_export_mode, "uncommitted");
        assert_eq!(config.diff_base_ref, "develop");
        assert_eq!(config.diff_target_ref, "feature");
        assert!(!config.redact_secrets);
        assert!(config.include_git_patch);
        assert!(!config.include_project_in_zip);
        assert!(config.keep_staging_folder);
        assert!(config.text_file_size_limit_enabled);
        assert_eq!(config.max_text_file_mb, 7);
        assert_eq!(config.zip_part_limit_mb, 64);
        assert_eq!(config.token_budget, 200_000);
        assert_eq!(config.history_keep_last_n, 5);
        assert_eq!(config.extra_ignored_dirs, vec!["vendor".to_string()]);
        assert_eq!(config.custom_excluded_files, vec!["notes.txt".to_string()]);
        assert_eq!(config.custom_excluded_extensions, vec!["log".to_string()]);
        assert_eq!(config.always_include_files, vec!["Makefile".to_string()]);
        assert_eq!(config.always_include_dirs, vec!["docs".to_string()]);
        assert_eq!(config.developer_context, "refactor auth");
    }

    #[test]
    fn an_empty_file_is_valid_and_changes_nothing() {
        let dir = project_with("");
        let (_, project) = ProjectConfig::load(dir.path()).unwrap().unwrap();
        assert_eq!(project, ProjectConfig::default());

        let mut config = Config::default();
        project.apply_to(&mut config);
        assert_eq!(config, Config::default());
    }

    #[test]
    fn broken_toml_syntax_reports_where_it_broke() {
        let dir = project_with("safe_export_mode = \n");
        let rendered = ProjectConfig::load(dir.path()).unwrap_err().to_string();
        assert!(rendered.contains(PROJECT_CONFIG_FILE_NAME), "{rendered}");
    }

    #[test]
    fn per_machine_settings_are_deliberately_not_accepted() {
        // Committing these to a shared repository would mean one developer's window
        // scale or language overriding everyone else's.
        for key in ["theme", "ui_zoom", "language", "last_root", "watch_enabled"] {
            let dir = project_with(&format!("{key} = \"x\"\n"));
            assert!(
                ProjectConfig::load(dir.path()).is_err(),
                "`{key}` should not be accepted in a committed project file"
            );
        }
    }
}
