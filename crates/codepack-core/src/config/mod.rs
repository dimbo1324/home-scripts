//! `Config`: every setting from the legacy `config.py` `Config` dataclass, ported
//! field-for-field (BLUEPRINT §A.3). Declaration order matches the legacy field order
//! so JSON output shape is stable and reviewable against the legacy reference.
//!
//! Raw field values are **not** semantically clamped or validated on assignment
//! (matching legacy behavior, where `normalized_*`/`effective_*` accessor methods do
//! that on read — see `normalize.rs`). `max_text_file_mb`/`zip_part_limit_mb` are `u32`
//! rather than legacy's unconstrained `int`, which does reject a negative value at the
//! JSON-deserialization boundary (falling back to `Config::default()` — see
//! `io.rs::load`'s doc comment) rather than storing and only normalizing it on read;
//! that boundary check is a consequence of static typing, not deliberately replicated
//! per-field validation.

mod io;
mod legacy;
mod normalize;
mod presets;
mod project;
mod valid_sets;

pub use legacy::migrate_legacy_settings;
pub use normalize::{DEFAULT_UI_ZOOM, UI_ZOOM_MAX, UI_ZOOM_MIN};
pub use presets::{AiPreset, ai_presets};
pub use project::{PROJECT_CONFIG_FILE_NAME, ProjectConfig, ProjectConfigError};
pub use valid_sets::{
    ARCHIVE_FORMATS, DEFAULT_ARCHIVE_FORMAT, DEFAULT_DIFF_EXPORT_MODE, DEFAULT_EXPORT_PROFILE,
    DEFAULT_LANGUAGE, DEFAULT_LOCAL_AI_AGENT, DEFAULT_SAFE_EXPORT_MODE, DEFAULT_THEME,
    DIFF_EXPORT_MODES, EXPORT_PROFILES, IMPLEMENTED_ARCHIVE_FORMATS, LANGUAGES, LOCAL_AI_AGENTS,
    SAFE_EXPORT_MODES, THEMES,
};

use serde::{Deserialize, Serialize};

/// Bumped when `Config`'s on-disk JSON shape changes in a way that is not simply
/// "a new field with a `#[serde(default)]`" (invariant I5's spirit, applied to a
/// brand-new artifact from day one).
pub const CONFIG_SCHEMA_VERSION: u32 = 1;

/// Reports have always been English; the setting exists to allow another, not to change
/// what an existing installation produces.
pub const DEFAULT_ARTIFACT_LANGUAGE: &str = "en";

/// What an artifact should say a root directory is.
///
/// A free function beside [`Config`] rather than a method on it: the callers are in four
/// different crates, and they all need the same answer from the same two inputs. Keeping
/// it here means the substitution is written once and reads the same everywhere.
pub fn disclosed_root(config: &Config, root: &std::path::Path, project_name: &str) -> String {
    if config.disclose_absolute_paths {
        return root.display().to_string();
    }
    // The project's own name, not an empty string or a literal placeholder: the field
    // stays useful for telling two bundles apart while carrying nothing about the machine.
    format!("<{project_name}>")
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub schema_version: u32,
    pub last_root: String,
    pub text_file_size_limit_enabled: bool,
    pub max_text_file_mb: u32,
    pub redact_secrets: bool,
    pub keep_staging_folder: bool,
    pub include_project_in_zip: bool,
    pub extra_ignored_dirs: Vec<String>,
    pub export_profile: String,
    pub safe_export_mode: String,
    pub zip_part_limit_mb: u32,
    /// Container the final bundle is written as: `zip` (default, and what every
    /// earlier version produced), `7z`, or `rar` (declared, not implemented).
    pub archive_format: String,
    pub diff_export_mode: String,
    pub diff_base_ref: String,
    pub diff_target_ref: String,
    pub include_git_patch: bool,
    pub custom_excluded_files: Vec<String>,
    pub custom_excluded_extensions: Vec<String>,
    pub always_include_files: Vec<String>,
    pub always_include_dirs: Vec<String>,
    pub incremental_export_enabled: bool,
    pub developer_context: String,
    pub theme: String,
    pub watch_enabled: bool,
    pub watch_clipboard_auto_update: bool,
    /// Whether artifacts may name the absolute paths of the machine that produced them.
    ///
    /// `source_root` and `copied_root` reach `PROJECT_PROFILE.json`, `manifest.json`,
    /// `02_git.txt` and `12_ai_context_pack.md`. On Windows those read
    /// `C:\Users\<account name>\…`, so a bundle handed to someone else carries the
    /// account name, the shape of the working directories, and sometimes an employer's or
    /// a client's name in the project path (audit No. 21). None of that is a secret in the
    /// I3 sense, but a tool whose promise is safe handoff should not be the thing that
    /// discloses it.
    ///
    /// Defaults to `false` since the owner decision of 2026-09-06 (Q40): the product is
    /// used by a team that passes bundles between machines, and the right default for a
    /// tool whose output leaves the computer by definition is not to name the computer.
    /// It shipped as `true` first so that turning it on moved no artifact and no golden
    /// reference; flipping it was the decision, not the mechanism.
    ///
    /// The fields keep their key and their type either way — only the value changes, to
    /// the project's own name. That is why no `schema_version` moved: see the Q40 entry
    /// in `docs/__arch__/open-questions.md` for the argument, which turns on the fact
    /// that an absolute path from somebody else's machine was never resolvable by a
    /// consumer anyway.
    pub disclose_absolute_paths: bool,
    pub ui_zoom: f64,
    pub language: String,
    pub prompt_goals: Vec<String>,
    /// How many export runs to keep per project (`codepack-storage`'s retention).
    /// Legacy's own `MAX_HISTORY_ITEMS = 50` was a global, non-configurable cap; this
    /// keeps the number but makes it per-project and configurable (decision Q10,
    /// 2026-07-25). `0` disables pruning entirely.
    pub history_keep_last_n: u32,
    /// Token budget for BLUEPRINT §B.3 "fit to budget". `0` means no budget, which is
    /// the default and the only behavior legacy ever had.
    pub token_budget: u64,
    /// Which local coding agent the handoff file is addressed to (stage S13's offline
    /// path). One of [`valid_sets::LOCAL_AI_AGENTS`].
    pub ai_handoff_agent: String,
    /// The question a handoff file carries when the user does not type a new one.
    /// Stored because people reuse the same prompt across exports; empty means the
    /// handoff's own general-purpose default is used.
    pub ai_handoff_question: String,
    /// Replace redacted secrets with a stable per-secret label (`<REDACTED:s1>`) rather
    /// than a single indistinguishable placeholder.
    ///
    /// `false` by default, and deliberately: with it off, every artifact this product
    /// writes is byte-identical to what it wrote before the option existed, so no
    /// golden reference moves and no `schema_version` changes. On, the two surfaces an
    /// assistant actually reads keep the *structure* of the secrets — which occurrences
    /// are the same value — without any of them carrying the value itself.
    pub redaction_labels: bool,
    /// Let a vendor token whose built-in checksum does not recompute be reported as a
    /// weaker finding than its shape alone would suggest.
    ///
    /// `false` by default, and that default is a safety property rather than caution:
    /// the checksum recipe is reverse-engineered from a vendor's own tooling, not
    /// published, so a mistake in it would quietly demote *real* tokens — a recall loss
    /// in the one detector this product exists for, which invariant I9 forbids trading
    /// away. On, a documentation sample stops reading as a live credential. See
    /// `codepack_security::patterns::checksum`.
    pub strict_token_checksums: bool,
    /// The language the *artifacts* are written in — separate from `language`, which is
    /// the interface's (BLUEPRINT §A.10 against §B.6).
    ///
    /// Two settings because they answer to two people. The interface language belongs to
    /// whoever runs the tool; the artifact language belongs to whoever will read the
    /// bundle, who is often somebody else and is sometimes a model. Folding them into one
    /// field would also have made `Config::default()` — whose interface language is `ru` —
    /// silently switch every report to Russian.
    ///
    /// `en` by default, which is what every report has always been.
    pub artifact_language: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            last_root: default_last_root(),
            text_file_size_limit_enabled: false,
            max_text_file_mb: 5,
            redact_secrets: true,
            keep_staging_folder: false,
            include_project_in_zip: true,
            extra_ignored_dirs: Vec::new(),
            export_profile: DEFAULT_EXPORT_PROFILE.to_string(),
            safe_export_mode: DEFAULT_SAFE_EXPORT_MODE.to_string(),
            zip_part_limit_mb: 512,
            archive_format: DEFAULT_ARCHIVE_FORMAT.to_string(),
            diff_export_mode: DEFAULT_DIFF_EXPORT_MODE.to_string(),
            diff_base_ref: "HEAD".to_string(),
            diff_target_ref: String::new(),
            include_git_patch: false,
            custom_excluded_files: Vec::new(),
            custom_excluded_extensions: Vec::new(),
            always_include_files: Vec::new(),
            always_include_dirs: Vec::new(),
            incremental_export_enabled: false,
            developer_context: String::new(),
            theme: DEFAULT_THEME.to_string(),
            watch_enabled: false,
            watch_clipboard_auto_update: false,
            disclose_absolute_paths: false,
            ui_zoom: DEFAULT_UI_ZOOM,
            language: DEFAULT_LANGUAGE.to_string(),
            prompt_goals: default_prompt_goals(),
            history_keep_last_n: 50,
            token_budget: 0,
            ai_handoff_agent: DEFAULT_LOCAL_AI_AGENT.to_string(),
            ai_handoff_question: String::new(),
            redaction_labels: false,
            strict_token_checksums: false,
            artifact_language: DEFAULT_ARTIFACT_LANGUAGE.to_string(),
        }
    }
}

/// Legacy default was `str(Path.home())`; falls back to an empty string when the
/// platform genuinely has no resolvable home directory (matching legacy's lack of a
/// normalizer for this field — the raw value is kept as-is either way).
fn default_last_root() -> String {
    crate::paths::home_dir_from_env()
        .map(|home| home.display().to_string())
        .unwrap_or_default()
}

fn default_prompt_goals() -> Vec<String> {
    vec![
        "architecture_review".to_string(),
        "bug_hunt".to_string(),
        "write_tests".to_string(),
    ]
}

pub use io::{export_settings, import_settings, load, save};

#[cfg(test)]
mod disclosure_tests {
    use super::*;

    /// The default does not name the machine (Q40, 2026-09-06). An installation that
    /// never opens the settings hands out bundles that carry no account name, which is
    /// the right default for a tool whose output leaves the computer by definition.
    ///
    /// The setting shipped as `true` first so that adding it moved no artifact; flipping
    /// it was the owner's decision, not a side effect of building the mechanism.
    #[test]
    fn the_default_does_not_name_the_machine() {
        let config = Config::default();
        assert!(!config.disclose_absolute_paths);
        assert_eq!(
            disclosed_root(&config, std::path::Path::new("/home/dev/work"), "work"),
            "<work>"
        );
    }

    /// Turning it on is still possible and still means what it says — the setting is a
    /// choice, not a deprecation. Somebody debugging their own export wants the path.
    #[test]
    fn turning_it_on_writes_the_real_path() {
        let config = Config {
            disclose_absolute_paths: true,
            ..Config::default()
        };
        assert_eq!(
            disclosed_root(&config, std::path::Path::new("/home/dev/work"), "work"),
            std::path::Path::new("/home/dev/work").display().to_string()
        );
    }

    /// With it off the field keeps its type and its place — only the value stops naming
    /// the machine. The account name is the thing being kept out of a shared bundle.
    #[test]
    fn turning_it_off_replaces_the_path_with_the_project_name() {
        let config = Config {
            disclose_absolute_paths: false,
            ..Config::default()
        };
        let answer = disclosed_root(
            &config,
            std::path::Path::new(r"C:\Users\dana\Documents\acme-client"),
            "acme-client",
        );

        assert_eq!(answer, "<acme-client>");
        assert!(
            !answer.contains("dana"),
            "the account name must not survive"
        );
        assert!(!answer.contains("Users"));
    }

    /// A project whose name cannot be derived still yields something well-formed rather
    /// than leaking the path as a fallback.
    #[test]
    fn an_empty_project_name_does_not_fall_back_to_the_path() {
        let config = Config {
            disclose_absolute_paths: false,
            ..Config::default()
        };
        assert_eq!(
            disclosed_root(&config, std::path::Path::new("/home/dana/x"), ""),
            "<>"
        );
    }
}
