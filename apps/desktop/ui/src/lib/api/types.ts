// Hand-written mirrors of the `serde`-serialized structs `apps/desktop/src-tauri`
// returns from its `#[tauri::command]` functions.
//
// No schema-generation dependency (`tauri-specta` etc.) is used: the command surface
// is small enough that keeping one file in sync by hand, the same way
// `codepack-cli`'s `--json` consumers keep their own parsers in sync with its Rust
// structs, costs less than a new build-time dependency. Field names and casing match
// the Rust side exactly (`serde`'s default, snake_case) — no renaming layer.

export interface Config {
  schema_version: number;
  last_root: string;
  text_file_size_limit_enabled: boolean;
  max_text_file_mb: number;
  redact_secrets: boolean;
  keep_staging_folder: boolean;
  include_project_in_zip: boolean;
  extra_ignored_dirs: string[];
  export_profile: string;
  safe_export_mode: string;
  zip_part_limit_mb: number;
  diff_export_mode: string;
  /** `zip` (default), `7z`, or `rar` (reserved, not implemented). */
  archive_format: string;
  diff_base_ref: string;
  diff_target_ref: string;
  include_git_patch: boolean;
  custom_excluded_files: string[];
  custom_excluded_extensions: string[];
  always_include_files: string[];
  always_include_dirs: string[];
  incremental_export_enabled: boolean;
  developer_context: string;
  theme: "light" | "dark" | "system";
  watch_enabled: boolean;
  watch_clipboard_auto_update: boolean;
  ui_zoom: number;
  language: "ru" | "en";
  prompt_goals: string[];
  history_keep_last_n: number;
  token_budget: number;
  /** Which local coding agent a handoff file is addressed to. */
  ai_handoff_agent: string;
  /** The question a handoff carries when none is typed. */
  ai_handoff_question: string;
  /** Replace `<REDACTED>` with a stable per-secret label (`<REDACTED:s1>`). Off by
   * default, and off means every artifact is byte-identical to what it always was. */
  redaction_labels: boolean;
  strict_token_checksums: boolean;
  artifact_language: string;
}

/** A coding agent on this machine that a bundle can be handed to (stage S13). */
export interface LocalAgentInfo {
  id: string;
  display_name: string;
  command: string;
}

/** What `prepare_handoff` wrote, and how to use it. */
export interface HandoffResult {
  path: string;
  working_dir: string;
  command: string;
  agent_name: string;
}

export interface PresetInfo {
  name: string;
  description: string;
  export_profile: string;
  safe_export_mode: string;
}

export interface ProfileInfo {
  key: string;
  label: string;
}

export interface AppInfo {
  version: string;
  presets: PresetInfo[];
  profiles: ProfileInfo[];
  project_config_file_name: string;
  network_access: string;
}

/** What `open_project` resolved, and where each value came from. */
export interface ProjectContext {
  root: string;
  config: Config;
  resolution: ResolutionTrace;
}

export interface ResolutionTrace {
  project_config: string | null;
  preset: string | null;
  profile: string | null;
}

export type FileStatus = "included" | "excluded" | "warning";

/** One node of the preview tree. Directories are synthetic — the plan only lists
 * files — and carry an aggregated status: `warning` if any descendant is a warning,
 * else `excluded` if any descendant is excluded and none included, else `included`. */
export interface TreeNode {
  name: string;
  path: string;
  is_dir: boolean;
  status: FileStatus;
  reason: string | null;
  severity: string | null;
  size: number | null;
  children: TreeNode[] | null;
}

export interface PreviewReport {
  project: string;
  profile: string;
  safe_mode: string;
  diff_mode: string;
  included_files: number;
  excluded_files: number;
  skipped_dirs: number;
  estimated_bytes: number;
  estimated_bytes_human: string;
  estimated_tokens: number;
  dropped_by_budget: number;
  sensitive_count: number;
  tree: TreeNode;
}

export type FindingKind = "sensitive_file" | "potential_secret" | "risky_code";

export interface Finding {
  kind: FindingKind;
  severity: string;
  confidence: string;
  file: string;
  line: number | null;
  rule: string;
  message: string;
}

export interface ScanSummary {
  sensitive_files: number;
  potential_secrets: number;
  risky_code: number;
  total_findings: number;
  critical: number;
}

/** Why one file did, or did not, end up in an export. The same answer `codepack
 * explain` gives at the terminal — one implementation, in the engine. */
export interface FileExplanation {
  file: string;
  profile: string;
  safe_mode: string;
  diff_mode: string;
  /** `included`, `excluded`, `not_in_diff`, or `not_planned`. */
  verdict: string;
  reason: string;
  group: string | null;
  severity: string | null;
  size: number | null;
  size_human: string | null;
  skipped_directory: string | null;
  exists_on_disk: boolean;
}

export interface ScanReport {
  project: string;
  safe_mode: string;
  scanned_files: number;
  summary: ScanSummary;
  findings: Finding[];
}

export interface ExportReport {
  run_id: number;
  project: string;
  profile: string;
  safe_mode: string;
  diff_mode: string;
  successful: boolean;
  cancelled: boolean;
  files_copied: number;
  files_skipped: number;
  errors: number;
  result_path: string | null;
  archives: string[];
  staging_dir: string;
  critical_findings: number;
}

/** A `export:progress` event payload. `step` is set only on step boundaries. */
export interface ExportProgressEvent {
  run_id: string;
  message: string | null;
  step: string | null;
  step_finished: boolean;
}

export interface ExportFinishedEvent {
  run_id: string;
  report: ExportReport | null;
  /** Set instead of `report` when the run errored before producing one. */
  error: string | null;
}

export interface HistoryEntry {
  run_id: number;
  project_name: string;
  project_root: string;
  started_at: number;
  started_at_utc: string;
  successful: boolean;
  cancelled: boolean;
  profile: string | null;
  safe_mode: string | null;
  diff_mode: string | null;
  files_copied: number | null;
  bytes_total: number | null;
  tokens_est: number | null;
  redacted_count: number | null;
  result_path: string | null;
}

export interface HistoryReport {
  project: string | null;
  runs: HistoryEntry[];
}

export interface ProjectProfileSummary {
  project_type: string;
  detected_stack: string[];
  risk_level: string;
  risk_reasons: string[];
  files: number;
  folders: number;
  total_size_bytes: number;
}

/** A structured, redacted error the backend could not turn into a normal result.
 * Every Tauri command that can fail rejects its promise with this shape, never with
 * a bare string, so the frontend can render a consistent error surface. */
export interface CommandError {
  message: string;
}

// --- Sterile copy ------------------------------------------------------------------

export type SanitizeOutcome =
  | "stripped_and_formatted"
  | "stripped_only_no_formatter_found"
  | "skipped_unsupported_language"
  | "skipped_sensitive_or_redacted"
  | "error";

export interface SanitizeSummary {
  total_files: number;
  stripped_and_formatted: number;
  stripped_only_no_formatter_found: number;
  skipped_unsupported_language: number;
  skipped_sensitive_or_redacted: number;
  errors: number;
}

export interface SanitizeFileOutcome {
  path: string;
  outcome: SanitizeOutcome;
  /** Stable token for the reason, translated by the UI. `detail` keeps the backend's
   * own English wording for anything that wants the raw text. */
  detail_kind: SanitizeDetailKind;
  detail: string | null;
}

export type SanitizeDetailKind =
  "formatted_by" | "no_formatter" | "unsupported_language" | "sensitive" | "error";

/** The `.7z` a run produced, when one was asked for. `bytes` is a number, not a
 * formatted string: byte-based reporting is preserved everywhere (invariant I4) and the
 * formatting is this layer's job. */
export interface SanitizeArchive {
  path: string;
  /** The container actually written — the file name may have chosen it. */
  format: string;
  file_count: number;
  bytes: number;
}

export interface SanitizeReport {
  source: string;
  destination: string;
  safety_mode: string;
  archive: SanitizeArchive | null;
  summary: SanitizeSummary;
  files: SanitizeFileOutcome[];
}

/** A `sanitize:finished` event payload. Exactly one of `report`/`error` is set. There is
 * no `sanitize:progress` counterpart to `ExportProgressEvent`: the backend runs the
 * whole file pass in one sweep and reports no intermediate progress today. */
export interface SanitizeFinishedEvent {
  run_id: string;
  report: SanitizeReport | null;
  error: string | null;
}
