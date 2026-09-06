# Project: codepack

A cross-platform desktop application that turns a source folder into a **clean, safe
snapshot**: an archive plus a set of reports fit to hand to an AI assistant **and to a
human** (developer, team, junior, or a non-programmer technical stakeholder).

The core value is **preventing secret leakage** when a project is shared outward. This
is not an archiver and not a README generator: the product is about safe context
handoff with local-only analysis.

## Repository map

Rust workspace under `crates/`:

- `codepack-core` — domain types, configuration, errors, progress and cancellation.
- `codepack-scanner` — tree walking, ignore rules, stack detection, export planning.
- `codepack-security` — export safety modes, secret redaction, the detector.
- `codepack-diff` — differential export and snapshots (via `git2`).
- `codepack-storage` — SQLite: history, snapshots, findings, migrations.
- `codepack-tokens` — bytes and tokens, budget mode.
- `codepack-reports` — insight reports, AI context packs, dashboard.
- `codepack-archive` — archive building (ZIP/7z), splitting, restore.
- `codepack-engine` — orchestrator of the eight-step pipeline.
- `codepack-cli` — headless binary.
- `xtask` — the project's task runner and quality gate.

Other areas:

- `apps/desktop/ui` — Svelte + Vite + TypeScript frontend (pnpm workspace).
- `apps/desktop/src-tauri` — the Tauri shell (crate/binary `codepack-desktop`), a member
  of the same cargo workspace. It calls `codepack-engine` directly rather than shelling
  out to `codepack-cli`: the two front ends sit side by side over the engine
  (BLUEPRINT §C.2), not in a chain. The webview holds **no filesystem permission**
  (`capabilities/default.json`); every file operation is a `#[tauri::command]`, and the
  frontend's only route to the backend is `ui/src/lib/api/client.ts`.
- `dev_tools_scripts_runner.py` (root) — a thin entry shim, nothing else.
- `scripts/` — the Python dev-tools orchestrator. `runner/` is its own logic and
  hand-edited JSON catalog; one directory per script, each with its own `config/*.json`;
  `_toolkit/` is the only thing scripts share. Scripts never import each other.
- `docs/` — see the internal/external split below.
- `.ai/`, `.claude/`, `.codex/` — assistant rules and workspaces.

The full map of state documents is in the progress-tracking module.

## Internal vs external documents

Owner decision 2026-07-30. Two audiences; a document belongs to exactly one.

**Internal — everything in `docs/__arch__/`, written in Russian.** For whoever builds
this, never advertised to a user of the product: `BLUEPRINT.md` (the specification),
`ROADMAP.md` (the plan and what is done), `open-questions.md` (owner decisions),
`codepack-main.zip` (the legacy implementation). Nothing outside that directory links
to them.

**External — written in English.** For whoever picks the product up, including someone
who has never seen this repository: `README.md`, `docs/architecture/overview.md`,
`docs/architecture/invariants.md`. `README.md` is the hub — every external document is
reachable from it, and it must not link to an internal one.

## Language policy

- **English**: `.ai/`, `.claude/`, `.codex/`, `CLAUDE.md`, `AGENTS.md`,
  `task-checklist.md`, code, comments, commit messages, test names, and every external
  document above.
- **Russian**: the internal documents in `docs/__arch__/`. A `**Status.**` line added to
  `ROADMAP.md` is Russian, matching that file.
- **Reports to the owner are Russian.**

Do not mix languages inside a single file. An external document needing a term with no
good Russian equivalent simply uses the English term — those files have no Russian
readers by design.

## Documentation policy

- `docs/__arch__/BLUEPRINT.md` is the product specification; it changes only when the
  product intent changes, and only by owner agreement.
- `docs/__arch__/ROADMAP.md` is the plan and progress record; update it when a stage
  completes.
- New documents are created only on direct request. Exception: `docs/architecture/`,
  `README.md` and `docs/__arch__/ROADMAP.md` must stay accurate when architecture or
  progress changes.

## Product guardrails

- **Privacy is absolute.** Analysis is local; no workspace crate reaches the network.
  S13's API path is the excluded `codepack-ai-api` (Q41).
- **The source is immutable.** Export never writes into the source project folder.
- **Bytes stay.** Byte-based size reporting is preserved everywhere it existed; tokens
  are an addition, never a replacement (owner decision).
- **Parity before novelty.** Within a stage, reproduce the legacy behavior first, then
  add new capability.
- **Stage order is binding** (`docs/__arch__/ROADMAP.md` §1, S0→S14). Skipping ahead requires an owner
  decision recorded in `docs/__arch__/open-questions.md`.
- **Artifact formats are backward compatible**; changing one requires bumping
  `schema_version`.
