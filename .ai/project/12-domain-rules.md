# Domain Rules and House Style (codepack)

These sharpen the universal rules for this codebase. Stricter wins.

## Rust code structure

- A module over roughly 600 lines (stricter than the universal 1000) becomes a directory
  module, keeping its public surface so external imports still work.
- Crates know nothing about the UI: no `codepack-*` crate depends on Tauri or the
  frontend. The core builds and tests headless — the CLI depends on it.
- Dependencies point strictly downward: `engine` → domain crates → `core`. Reverse and
  circular ones are forbidden.
- Errors: `thiserror` in libraries, `anyhow` only in binaries and `xtask`.
- `unsafe` is forbidden without an explicit owner decision and a justification in code.
- `unwrap()`/`expect()` outside tests need an adjacent comment proving they cannot fail.
- Workspace lints live in the root `Cargo.toml`; crates inherit them with
  `[lints] workspace = true` rather than redefining their own.

## Concurrency and responsiveness

- Long operations (walking, hashing, scanning, archiving) parallelize with `rayon` and
  check the cancellation token **inside** loops, not just between steps.
- Progress and log messages travel over a channel; the UI never blocks.
- Memory must not grow with file size: large files are read streaming.

## Domain constraints

- **Network access is forbidden** in every crate except the stage S13 integration.
  Adding an HTTP client anywhere else is a violation.
- **Symlinks are never followed** while walking — this prevents escaping the tree.
- **Extraction is path-traversal safe**: an entry's target is validated before writing.
- **Secrets are never logged**: a finding's text is redacted before it reaches a log,
  report, history entry, or database row. Raw file content reaches a report only via
  `text::read_text_unredacted`, whose callers are declared with reasons in
  `crates/xtask/src/report_redaction.rs` (gate-checked).
- Constant sets (text and binary extensions, ignored directories, sensitive names and
  suffixes, safety-mode tables) are ported from the legacy version **verbatim**.
  Changing a set is a separate decision, never a side effect of refactoring.

## Tests

- Every domain crate carries golden tests against legacy behavior; per-stack project
  fixtures live in the crate's test data.
- `codepack-security` additionally requires an accuracy corpus test
  (precision / recall / F1). Lowering a threshold to make the gate green is forbidden.
- Tests must not depend on a `git` binary being installed: git work goes through `git2`
  and test repositories are created programmatically.

## Artifact formats

Report file names, JSON manifest structures, and SARIF output are a **contract**.
Changing one requires bumping `schema_version` and recording the decision in
`docs/__arch__/open-questions.md`.

## Assistant workspaces

- `.claude/agents|skills` and `.codex/agents|skills` are name-for-name mirrors; changing
  one side requires the equivalent change on the other in the same task.
- `.claude/settings.json` allowlists routine read and verification commands and denies
  destructive git operations and crate publishing. Extend the allowlist rather than
  routing around it; never remove a deny entry without explicit owner approval.
