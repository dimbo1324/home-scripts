//! The serialized shapes the commands return.
//!
//! Each struct here has a hand-written counterpart in
//! `apps/desktop/ui/src/lib/api/types.ts`. There is no code generation between them: the
//! surface is small, and the alternative — a build-time schema exporter — is a
//! dependency and a build step to maintain for a boundary that changes rarely. The
//! field names are `serde`'s defaults (snake_case), so both sides read identically and
//! nothing renames anything in between.
//!
//! `types.ts` is the contract. When these change, that file changes in the same commit.

use serde::{Deserialize, Serialize};

// --- Local AI handoff (stage S13, offline path) -----------------------------------

/// A coding agent this build can address a handoff to.
#[derive(Debug, Clone, Serialize)]
pub struct LocalAgentInfo {
    pub id: String,
    pub display_name: String,
    /// The command to run inside the bundle directory.
    pub command: String,
}

/// What a prepared handoff left behind, and what to do with it.
#[derive(Debug, Clone, Serialize)]
pub struct HandoffResult {
    /// The file that was written.
    pub path: String,
    /// Where to start the agent.
    pub working_dir: String,
    /// The command to run there.
    pub command: String,
    pub agent_name: String,
}

// --- Application metadata ---------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct PresetInfo {
    pub name: String,
    pub description: String,
    pub export_profile: String,
    pub safe_mode: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileInfo {
    pub key: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppInfo {
    pub version: String,
    pub presets: Vec<PresetInfo>,
    pub profiles: Vec<ProfileInfo>,
    pub project_config_file_name: String,
    /// A fixed, human-readable statement of invariant I1, shown in the UI. Sent from the
    /// backend rather than hardcoded in the frontend so it states what the *binary*
    /// does, not what the page author believed it did.
    pub network_access: String,
}

// --- Project resolution -----------------------------------------------------------

/// Where each part of the resolved configuration came from, so a user can tell why an
/// export is about to run in `safe` mode. Mirrors the CLI's own `ResolutionTrace`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ResolutionTrace {
    pub project_config: Option<String>,
    pub preset: Option<String>,
    pub profile: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectContext {
    pub root: String,
    pub config: codepack_core::config::Config,
    pub resolution: ResolutionTrace,
}

// --- Preview ----------------------------------------------------------------------

/// One node of the preview tree.
///
/// Directories are synthetic: the export plan is a flat list of files, and the tree is
/// assembled from their paths. A directory's status is aggregated from its descendants
/// so a collapsed folder still shows that something inside it needs attention.
#[derive(Debug, Clone, Serialize)]
pub struct TreeNode {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub status: String,
    pub reason: Option<String>,
    pub severity: Option<String>,
    pub size: Option<u64>,
    pub children: Option<Vec<TreeNode>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreviewReport {
    pub project: String,
    pub profile: String,
    pub safe_mode: String,
    pub diff_mode: String,
    pub included_files: usize,
    pub excluded_files: usize,
    pub skipped_dirs: usize,
    pub estimated_bytes: u64,
    pub estimated_bytes_human: String,
    pub estimated_tokens: u64,
    pub dropped_by_budget: usize,
    pub sensitive_count: usize,
    pub tree: TreeNode,
}

// --- Security scan ----------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub kind: String,
    pub severity: String,
    pub confidence: String,
    pub file: String,
    pub line: Option<usize>,
    pub rule: String,
    /// Already redacted by `codepack-security` before it reaches this struct
    /// (invariant I3) — nothing here re-derives or "improves" it.
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanSummary {
    pub sensitive_files: usize,
    pub potential_secrets: usize,
    pub risky_code: usize,
    pub total_findings: usize,
    /// Findings at `critical` severity. Surfaced separately because it is the single
    /// number that should stop someone from sharing a bundle.
    pub critical: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub project: String,
    pub safe_mode: String,
    pub scanned_files: usize,
    pub summary: ScanSummary,
    pub findings: Vec<Finding>,
}

// --- Export -----------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct ExportReport {
    pub run_id: i64,
    pub project: String,
    pub profile: String,
    pub safe_mode: String,
    pub diff_mode: String,
    pub successful: bool,
    pub cancelled: bool,
    pub files_copied: u32,
    pub files_skipped: u32,
    pub errors: u32,
    pub result_path: Option<String>,
    pub archives: Vec<String>,
    pub staging_dir: String,
    pub critical_findings: usize,
}

/// A `export:progress` event. `step` is populated only on step boundaries, so the UI can
/// show "5/8: text dump" separately from the stream of log lines.
#[derive(Debug, Clone, Serialize)]
pub struct ExportProgressEvent {
    pub run_id: String,
    pub message: Option<String>,
    pub step: Option<String>,
    pub step_finished: bool,
}

/// A `export:finished` event. Exactly one of `report`/`error` is set.
#[derive(Debug, Clone, Serialize)]
pub struct ExportFinishedEvent {
    pub run_id: String,
    pub report: Option<ExportReport>,
    pub error: Option<String>,
}

/// A `watch:changed` event.
#[derive(Debug, Clone, Serialize)]
pub struct WatchChangedEvent {
    pub changed_paths: Vec<String>,
    /// True when more paths changed than one notification carries, so `changed_paths` is
    /// a sample rather than the whole story. The UI says so instead of showing a partial
    /// list as if it were complete.
    pub truncated: bool,
}

// --- History ----------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct HistoryEntry {
    pub run_id: i64,
    pub project_name: String,
    pub project_root: String,
    pub started_at: i64,
    pub started_at_utc: String,
    pub successful: bool,
    pub cancelled: bool,
    pub profile: Option<String>,
    pub safe_mode: Option<String>,
    pub diff_mode: Option<String>,
    pub files_copied: Option<i64>,
    pub bytes_total: Option<i64>,
    pub tokens_est: Option<i64>,
    pub redacted_count: Option<i64>,
    pub result_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HistoryReport {
    pub project: Option<String>,
    pub runs: Vec<HistoryEntry>,
}

// --- Analytics --------------------------------------------------------------------

/// The subset of `PROJECT_PROFILE.json` the Analytics page shows.
///
/// `Deserialize` as well as `Serialize`: this is read back from a bundle that a past
/// export wrote, so the same declaration serves both directions and cannot drift.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectProfileSummary {
    pub project_type: String,
    pub detected_stack: Vec<String>,
    pub risk_level: String,
    pub risk_reasons: Vec<String>,
    pub files: usize,
    pub folders: usize,
    pub total_size_bytes: u64,
}

// --- Sterile copy -------------------------------------------------------------------

/// The aggregate counts from `codepack_sanitize::SterileCopySummary`, reshaped with
/// `serde`'s default field names so `types.ts` reads it unchanged.
#[derive(Debug, Clone, Serialize)]
pub struct SanitizeSummary {
    pub total_files: usize,
    pub stripped_and_formatted: usize,
    pub stripped_only_no_formatter_found: usize,
    pub skipped_unsupported_language: usize,
    pub skipped_sensitive_or_redacted: usize,
    pub errors: usize,
}

/// One file's disposition. `outcome` is the same fixed label
/// `codepack_sanitize::FileOutcome::label()` already gives the CLI's `--json` output, so
/// the two front ends agree on the vocabulary without either depending on the other.
#[derive(Debug, Clone, Serialize)]
pub struct SanitizeFileOutcome {
    pub path: String,
    pub outcome: &'static str,
    /// A stable token the frontend translates. `detail` keeps the English prose for
    /// anything that wants the raw wording (a log, a copied line).
    pub detail_kind: &'static str,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SanitizeReport {
    pub source: String,
    pub destination: String,
    pub safety_mode: String,
    /// Present only when the run was asked for a `.7z`. Reported separately from
    /// `destination` because when the user asked for an archive only, the destination
    /// was a scratch folder that no longer exists.
    pub archive: Option<SanitizeArchive>,
    pub summary: SanitizeSummary,
    pub files: Vec<SanitizeFileOutcome>,
}

/// The `.7z` a sterile copy produced. `bytes` stays a number — formatting is the
/// frontend's job, and byte-based reporting is preserved everywhere (invariant I4).
#[derive(Debug, Clone, Serialize)]
pub struct SanitizeArchive {
    pub path: String,
    /// The container actually written — the file name may have chosen it.
    pub format: String,
    pub file_count: usize,
    pub bytes: u64,
}

/// A `sanitize:finished` event. Exactly one of `report`/`error` is set.
///
/// There is no `sanitize:progress` counterpart to `export:progress`:
/// `codepack_sanitize::run_sterile_copy` processes every file in one `rayon` sweep and
/// reports no intermediate progress today, so nothing would ever be sent on such a
/// channel. Adding one that never fires would be a UI promise the backend cannot keep.
#[derive(Debug, Clone, Serialize)]
pub struct SanitizeFinishedEvent {
    pub run_id: String,
    pub report: Option<SanitizeReport>,
    pub error: Option<String>,
}

// --- Explain ------------------------------------------------------------------------

/// Why one file did, or did not, end up in an export.
///
/// A straight rendering of `codepack_engine::explain::FileExplanation`, which is the
/// same value the CLI's `explain` command reports — the two surfaces cannot disagree
/// about a file because there is only one answer.
#[derive(Debug, Clone, Serialize)]
pub struct FileExplanation {
    pub file: String,
    pub profile: String,
    pub safe_mode: String,
    pub diff_mode: String,
    pub verdict: String,
    pub reason: String,
    pub group: Option<String>,
    pub severity: Option<String>,
    pub size: Option<u64>,
    pub size_human: Option<String>,
    pub skipped_directory: Option<String>,
    pub exists_on_disk: bool,
}
