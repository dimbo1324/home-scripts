// The single choke point through which the frontend talks to the Rust backend.
//
// Invariant (`docs/__arch__/ROADMAP.md` §3: "изоляция — UI не имеет прямого доступа к ФС"): no
// other module in this package may import `@tauri-apps/api/core` or a filesystem
// plugin directly. Every file operation the UI needs — picking a folder, reading a
// project, writing an archive — is a named function here, backed by a
// `#[tauri::command]`, never a raw `invoke()` call scattered through page code.
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import { openPath, revealItemInDir } from "@tauri-apps/plugin-opener";

import type {
  AppInfo,
  Config,
  ExportFinishedEvent,
  ExportProgressEvent,
  FileExplanation,
  HistoryReport,
  PreviewReport,
  ProjectContext,
  HandoffResult,
  LocalAgentInfo,
  ProjectProfileSummary,
  SanitizeFinishedEvent,
  ScanReport,
} from "./types";

/** Opens the native folder picker. `null` means the user cancelled — not an error. */
export async function pickProjectDirectory(): Promise<string | null> {
  const selected = await openDialog({ directory: true, multiple: false });
  return typeof selected === "string" ? selected : null;
}

/** Opens the native "save as" dialog for the sterile copy's archive. `null` means the
 * user cancelled — not an error. The extension is appended by the dialog when the user
 * types a bare name, so the backend never has to guess at one. */
export async function pickArchiveDestination(
  defaultName: string,
  extension: string,
): Promise<string | null> {
  const selected = await saveDialog({
    defaultPath: defaultName,
    filters: [{ name: `${extension.toUpperCase()} archive`, extensions: [extension] }],
  });
  return typeof selected === "string" ? selected : null;
}

export type DragDropPhase = "enter" | "leave" | "drop";

/** Paths dragged onto and dropped on the window.
 *
 * The webview receives only the path string; it still cannot read what is there, so this
 * changes nothing about the isolation invariant — the path goes straight back to
 * `open_project`, exactly as a path from the folder picker does. `handler` is called with
 * whatever was dropped, including files, because the backend is the side that knows what
 * a valid project root is.
 *
 * `over` is dropped rather than forwarded: it fires on every mouse move, and the only
 * thing the UI does with the drag is show one overlay. */
export function onWindowDragDrop(
  handler: (phase: DragDropPhase, paths: string[]) => void,
): Promise<UnlistenFn> {
  return getCurrentWebview().onDragDropEvent((event) => {
    const payload = event.payload;
    if (payload.type === "enter") handler("enter", payload.paths);
    else if (payload.type === "leave") handler("leave", []);
    else if (payload.type === "drop") handler("drop", payload.paths);
  });
}

export function getAppInfo(): Promise<AppInfo> {
  return invoke("get_app_info");
}

export function loadGlobalSettings(): Promise<Config> {
  return invoke("load_global_settings");
}

export function saveGlobalSettings(config: Config): Promise<void> {
  return invoke("save_global_settings", { config });
}

/** Applies a built-in AI preset's fields onto `config`, returning the updated copy.
 * Goes through the backend rather than being reimplemented in TypeScript so the GUI
 * can never disagree with the CLI about what a preset actually sets
 * (`codepack_core::config::ai_presets`, the single source of truth for both). */
export function applyPreset(config: Config, presetName: string): Promise<Config> {
  return invoke("apply_preset", { config, presetName });
}

/** Same reasoning as `applyPreset`, for a built-in or user-defined export profile
 * (`codepack_core::profiles::apply_custom_profile`). */
export function applyProfile(config: Config, profileName: string): Promise<Config> {
  return invoke("apply_profile", { config, profileName });
}

/** Resolves defaults -> global settings -> `.codepack.toml` for `path`. The result is
 * the starting point for the session's editable config; nothing here is persisted. */
export function openProject(path: string): Promise<ProjectContext> {
  return invoke("open_project", { path });
}

export function previewProject(
  projectRoot: string,
  config: Config,
  fileOverrides: Record<string, boolean>,
): Promise<PreviewReport> {
  return invoke("preview_project", { projectRoot, config, fileOverrides });
}

export function scanProject(projectRoot: string, config: Config): Promise<ScanReport> {
  return invoke("scan_project", { projectRoot, config });
}

/** Why one file did, or did not, end up in an export. `file` may be absolute, relative
 * to the project, or spelled the way the plan stores it. */
export function explainFile(
  projectRoot: string,
  config: Config,
  file: string,
): Promise<FileExplanation> {
  return invoke("explain_file", { projectRoot, config, file });
}

/** Starts an export on a background thread and returns immediately with a run id.
 * Progress and completion arrive as events (`onExportProgress`/`onExportFinished`),
 * not as this call's return value — an export can run for minutes, and the UI must
 * stay responsive and cancellable while it does. */
export function startExport(
  projectRoot: string,
  outDir: string,
  config: Config,
  fileOverrides: Record<string, boolean>,
): Promise<string> {
  return invoke("start_export", { projectRoot, outDir, config, fileOverrides });
}

export function cancelExport(runId: string): Promise<void> {
  return invoke("cancel_export", { runId });
}

export function onExportProgress(
  handler: (event: ExportProgressEvent) => void,
): Promise<UnlistenFn> {
  return listen<ExportProgressEvent>("export:progress", (event) => handler(event.payload));
}

export function onExportFinished(
  handler: (event: ExportFinishedEvent) => void,
): Promise<UnlistenFn> {
  return listen<ExportFinishedEvent>("export:finished", (event) => handler(event.payload));
}

export function fetchHistory(projectRoot: string | null, limit: number): Promise<HistoryReport> {
  return invoke("fetch_history", { projectRoot, limit });
}

export function readProjectProfile(resultPath: string): Promise<ProjectProfileSummary> {
  return invoke("read_project_profile", { resultPath });
}

/** Extracts the full report bundle from `resultPath` next to it and opens
 * `REPORT_DASHBOARD.html` with the OS's default handler, so its relative links to
 * the other reports resolve. */
export function openDashboard(resultPath: string): Promise<void> {
  return invoke("open_dashboard", { resultPath });
}

/** Same extraction, but for `PROJECT_OVERVIEW.html` — the plain-language overview
 * (stage S12, BLUEPRINT §B.9). */
export function openProjectOverview(resultPath: string): Promise<void> {
  return invoke("open_project_overview", { resultPath });
}

/** Same extraction, but for `ONBOARDING_GUIDE.md` (stage S12). */
export function openOnboardingGuide(resultPath: string): Promise<void> {
  return invoke("open_onboarding_guide", { resultPath });
}

/** Same extraction, but for `REVIEW_CHECKLIST.md` (stage S12). */
export function openReviewChecklist(resultPath: string): Promise<void> {
  return invoke("open_review_checklist", { resultPath });
}

export function openResultLocation(resultPath: string): Promise<void> {
  return revealItemInDir(resultPath);
}

export function openFile(path: string): Promise<void> {
  return openPath(path);
}

// --- Watch mode ----------------------------------------------------------------

export function startWatch(projectRoot: string, config: Config): Promise<void> {
  return invoke("start_watch", { projectRoot, config });
}

export function stopWatch(): Promise<void> {
  return invoke("stop_watch");
}

export interface WatchChangedEvent {
  changed_paths: string[];
  /** True when more files changed than one notification carries, so `changed_paths` is a
   * sample rather than the whole story. Shown to the user rather than hidden: a partial
   * list presented as complete is worse than an honest count. */
  truncated: boolean;
}

export function onWatchChanged(handler: (event: WatchChangedEvent) => void): Promise<UnlistenFn> {
  return listen<WatchChangedEvent>("watch:changed", (event) => handler(event.payload));
}

// --- Sterile copy ----------------------------------------------------------------

/** Starts a "Sterile copy" run on a background thread and returns immediately with a
 * run id. Unlike `startExport`, there is no progress event — only
 * `onSanitizeFinished` — because `codepack-sanitize` reports no intermediate progress
 * of its own (see `SanitizeFinishedEvent`'s own doc comment in `./types`). */
export function startSanitize(
  sourceRoot: string,
  destinationRoot: string,
  safetyMode: string,
  archivePath: string | null,
  archiveFormat: string | null,
): Promise<string> {
  return invoke("start_sanitize", {
    sourceRoot,
    destinationRoot,
    safetyMode,
    archivePath,
    archiveFormat,
  });
}

export function cancelSanitize(runId: string): Promise<void> {
  return invoke("cancel_sanitize", { runId });
}

export function onSanitizeFinished(
  handler: (event: SanitizeFinishedEvent) => void,
): Promise<UnlistenFn> {
  return listen<SanitizeFinishedEvent>("sanitize:finished", (event) => handler(event.payload));
}

// --- Local AI handoff -------------------------------------------------------------

/** The coding agents this build can address a handoff to. */
export function listLocalAgents(): Promise<LocalAgentInfo[]> {
  return invoke("list_local_agents");
}

/** Writes `AI_HANDOFF.md` into the bundle and returns the command to run beside it.
 * Nothing is sent anywhere and nothing is launched: the agent already runs on this
 * machine and reads the folder itself. */
export function prepareHandoff(
  resultPath: string,
  agentId: string,
  question: string,
): Promise<HandoffResult> {
  return invoke("prepare_handoff", { resultPath, agentId, question });
}

// --- Window chrome ---------------------------------------------------------------

export function setUiZoom(factor: number): Promise<void> {
  return invoke("set_ui_zoom", { factor });
}
