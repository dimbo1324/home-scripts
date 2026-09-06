// The text `watch_clipboard_auto_update` puts on the clipboard when watched files
// change.
//
// Finding 4, 2026-07-27 audit: the setting existed in `Config`, was migrated from legacy
// settings, was written into the manifest, and was shown to the user as a switch — and
// nothing read it to do anything. A toggle that silently does nothing is worse than a
// missing feature: the missing one is visible, the broken one quietly costs trust in
// every other setting.
//
// Kept in its own module, away from `App.svelte`, so the formatting is unit-testable
// without mounting a component.

/// How many paths are listed before the summary switches to a trailing count. Enough to
/// be useful when pasted into a chat, short enough not to swamp a clipboard the user
/// meant for something else.
const MAX_LISTED_PATHS = 20;

/**
 * A short, paste-ready description of what just changed.
 *
 * `projectRoot` is included because the clipboard carries no context of its own: a bare
 * list of relative paths pasted into a chat says nothing about which project produced
 * them.
 */
export function formatWatchSummary(
  changedPaths: readonly string[],
  projectRoot: string | null,
  truncated = false,
): string {
  // `+` rather than an exact figure: past the backend's cap the count is a floor, and
  // pasting a precise-looking number that is not precise is worse than saying so.
  const count = truncated ? `${changedPaths.length}+` : `${changedPaths.length}`;
  const heading =
    projectRoot === null || projectRoot === ""
      ? `${count} file(s) changed`
      : `${count} file(s) changed in ${projectRoot}`;

  if (changedPaths.length === 0) {
    return heading;
  }

  const listed = changedPaths.slice(0, MAX_LISTED_PATHS).map((path) => `- ${path}`);
  const remaining = changedPaths.length - listed.length;
  const lines = remaining > 0 ? [...listed, `- … and ${remaining} more`] : listed;

  return [heading, ...lines].join("\n");
}
