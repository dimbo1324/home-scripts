# Changelog

Releases of codepack. Newest first. Dates are the day the version was tagged.

This file is for people who use codepack. The rule-system changelog for the AI assistants
that build it is a separate file, `.ai/CHANGELOG.md`.

## 2.0.0 — 2026-09-06

The first release of the Rust rewrite. The previous product was Project Exporter Desktop
1.0.1 (Python/PySide6, Windows only); this shares its behaviour and none of its code.

### What it does

- **Export.** A source folder becomes an archive plus about thirty reports — structure,
  stack, dependencies, git, security, tokens, an AI context pack and an HTML dashboard.
- **Safety modes.** `safe` (the default), `balanced` and `full` decide what is copied at
  all. Safe mode excludes `.env` files, key material and similarly named files.
- **Secret scanning.** Provider signatures, entropy and structural parsing, with a
  precision/recall corpus test that the build refuses to fall below.
- **Two front ends over one engine.** A desktop app (Tauri + Svelte) and a headless CLI
  with `--json` on every command. Neither shells out to the other.
- **Differential export**, snapshots and history in SQLite.
- **Sterile copy** — strip comments with tree-sitter and reformat with a `PATH` tool into
  a separate destination.
- **Handoff to a local agent**, and an MCP server so an agent can ask for itself.
- **Pre-commit hook** and a GitHub Action.

### Guarantees held by tests

Analysis is entirely local — no crate in the workspace can reach the network. The source
folder is never written to. Secrets never reach a report, a log, the history, the
database or an error message. Symlinks are never followed; extraction is path-traversal
safe and bounded.

### Platforms

Windows 10 and 11, macOS, and Linux: the quality gate runs on all three. **Only Windows
has an installer** — an NSIS `.exe` with a `SHA256SUMS.txt` beside it.

### Not in this release

- Code signing and notarisation. SmartScreen warns about an unknown publisher.
- macOS and Linux installers.
- Auto-update.
- The API path to a hosted model. The offline handoff works; the HTTP client is preserved
  in a package excluded from the build and has no interface yet.
- Mermaid diagram rendering, and `file:line` links in the review checklist.
