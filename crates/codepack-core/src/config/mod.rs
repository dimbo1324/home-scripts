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
