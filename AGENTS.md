<!--
GENERATED FILE - DO NOT EDIT.
Source of truth: .ai/universal/*.md and .ai/project/*.md.
Edit a module, then run: cargo xtask sync-agents
-->

# codepack - working notes for Codex

This file is the Codex entry point. It is assembled from the shared rule modules in
`.ai/` so Codex and Claude Code always follow identical rules. Later sections override
earlier ones; an explicit owner instruction in the current conversation overrides
everything.

---

<!-- module: .ai/universal/01-workflow.md -->

# Workflow: Git, Branches, Commits

Purpose: every task follows one predictable git cycle. No exceptions without an
explicit owner instruction in the current conversation.

## Branch discipline

- NEVER develop directly on `main`.
- Start every task from up-to-date `main`:
  `git checkout main` → `git pull --ff-only origin main` → `git checkout -b <branch>`.
- Branch name format: `type/short-task-description`
  (types: `feat`, `fix`, `refactor`, `test`, `chore`, `docs`, `ci`, `perf`, `security`).
- Uninformative branch names (`test`, `fix`, `work`, `final`, `new`) are forbidden.
- Merge into `main` only fast-forward (`git merge --ff-only`) and only after the
  project's full quality gate is green.
- Push to `origin/main` only when the owner explicitly asked for a publish within the
  current task. Work-in-progress branch pushes are allowed (for example, to publish
  the task checklist before starting work).
- Delete the task branch after it is merged.

## Commits

- Message format: `type: short description of what and why`.
- One commit = one logically complete unit. Do not mix a bug fix, a refactor,
  formatting, and new features in a single commit unless they are one inseparable task.
- Forbidden messages: `fix`, `update`, `wip`, `changes`, `final`, `123`.
- Keep commits attributable: include the assistant identity trailer the project already
  uses (check a recent `git log` for the convention).

## Quality gate before merge

- Run the project's checks (see the project commands module) before merging.
- If mandatory checks fail, merging into `main` is forbidden until fixed or the owner
  explicitly decides otherwise.
- Before merging, self-review the diff: changes match the task, no stray files, no
  debug leftovers, no secrets, no accidental unrelated edits.

When unsure whether an action counts as "explicitly requested": ask, or stop after the
branch commit and report instead of pushing.

---

<!-- module: .ai/universal/02-task-checklist.md -->

# Task Checklist and Definition of Done

Purpose: every task is planned before it starts and honestly accounted for after it
ends, in a file any reviewer can read without the conversation.

## task-checklist.md protocol

A file named `task-checklist.md` lives in the repository root and is always tracked by
git (never in `.gitignore`).

Before starting a task:

1. Clear or recreate `task-checklist.md` for the new task.
2. Write the main stages, checks, and expected outcomes as `[ ]` items, grouped into
   short sections (preparation / implementation / verification / completion).
   Moderate detail — stages, not keystrokes.
3. Commit the checklist BEFORE doing the main work.

After finishing the task:

4. Mark every item: `+` done, `-` not done or partially done.
5. Commit the filled checklist together with the completed work.
6. Never hide unfinished items — a `-` with an honest note is correct; a silently
   ignored item is a violation.

## Definition of Done

A task is complete only when ALL of the following hold:

- code written and matching the task, without unrequested scope;
- code formatted; lint and type checks pass;
- tests added or updated where reasonable; existing tests pass;
- project builds; no obvious errors in logs;
- no secrets, no temp files, no accidental changes in unrelated files;
- architecture and state docs updated if the task changed the system's shape;
- task checklist filled with `+`/`-`;
- final report written.

## Final report

The final report is ALWAYS the last step of a task. It states: what was done; which
files and areas changed; which checks ran and their results; dependency, API, database,
or config changes; security, performance, and compatibility risks; and — explicitly and
honestly — anything that was not done or failed.

---

<!-- module: .ai/universal/03-scope-and-code-style.md -->

# Scope Control and Code Style

Purpose: change only what the task requires, and keep code readable without decoration.

## Minimal changes

- Touch only what the current task needs. Forbidden without necessity:
  mass-reformatting other files, renaming things outside the task, changing
  architecture "while at it", rewriting working code without cause, changing UI when
  the task is not about the interface, deleting existing functionality without a
  direct requirement.
- If you discover an unrelated problem, record it separately (report it, or file it per
  the project's process) — do not mix it into the current diff.
- Do not create new documentation (README, `.md`, `.txt`) unless the task requires it
  directly. Exception: the project's designated architecture and progress documents,
  which must be kept current.

## Comments

- No comments by default. Code must be clear through structure and naming.
- A comment is allowed only when the task demands it, or when important logic stays
  non-obvious even with good naming. It explains the non-obvious "why", never restates
  the code.
- Stale, false, or misleading comments are forbidden. No doc comments that merely
  repeat a function name.

## File size

- Regular code files: keep under roughly 1000 lines; split by meaning when approaching
  the limit. Projects may set a stricter limit — the stricter limit wins.
- Application entry points (`main`-type files): under roughly 100 lines; extract
  configuration, startup, and service initialization into modules.
- Exemptions: test files, developer-tool scripts, and any files the project explicitly
  exempts.

## Frontend restraint

- No visual polish (styling, animations, decorative elements, redesign) unless the task
  is explicitly about appearance.
- When a task needs an interface, build the minimum that exercises the business logic
  correctly.
- Never change visual style, interface structure, component behavior, or user flows
  without a direct requirement.

---

<!-- module: .ai/universal/04-architecture-boundaries.md -->

# Architecture Boundaries, Workarounds, Tech Debt

Purpose: respect the project's layering; make every shortcut visible.

## Boundaries

- Follow the project's existing architecture. Forbidden: business logic in UI or
  controllers when a service layer exists; direct storage access in handlers when a
  repository layer exists; bypassing existing services and abstractions without cause;
  circular module dependencies; dumping unrelated logic into catch-all files.
- If the architecture genuinely blocks the task, do not hack around it — propose a
  proper structural change and reflect it in the architecture docs once approved.

## Temporary solutions

- Workarounds are allowed only exceptionally, and every one must be recorded
  explicitly: why it exists, where it lives, its limits and risks, and when it must be
  replaced.
- Hidden workarounds are forbidden. Do not scatter uncontrolled `TODO`/`FIXME` marks;
  important debt gets a task or an entry in the project's tracking process.

## Tech debt

- Debt found during a task that cannot be fixed now is recorded explicitly (in the
  final report at minimum), never disguised as a normal solution.
- Debt touching security, data integrity, performance, or stability is priority debt —
  call it out loudly.

---

<!-- module: .ai/universal/05-security-and-secrets.md -->

# Security, Secrets, Dependencies, Portability

Purpose: nothing sensitive in the repo; every change safe within its area; the project
runs on any machine.

## Secrets — absolute ban

- NEVER put in code, git, tests, docs, or examples: passwords, API keys, tokens,
  private keys, real credentials, cookies, production `.env`, or personal user data.
- Secrets live only in `.env` (untracked), environment variables, secret managers, or
  CI/CD secrets. The repo may contain only a safe `.env.example`.
- A secret that ever reached git is compromised: rotate it; deleting the line in a new
  commit is not enough.

## Security in every task

Check within the area you touch: authorization and access rights, input validation,
injection, XSS and CSRF where applicable, unsafe redirects, file uploads, personal data
handling, public endpoints, token storage and transport, and access to admin functions.
Security is part of every task, not a future task.

## Dependencies

- No new dependency without justification: what for, can it be done without, is it
  maintained, known vulnerabilities, stack compatibility, does it duplicate an existing
  dependency, is it too heavy for the need.
- Never add a heavy library for one small function.
- After changing dependencies: update the lock file and verify the build.
- A new production dependency must be named in the final report.

## Portability

- No machine-specific values in code: local absolute paths, usernames, IDE settings,
  unconfigured local ports, or anything environment-dependent. Such values go to
  configuration.
- The project must remain runnable by someone else using the project's documented tools.

---

<!-- module: .ai/universal/06-quality-and-testing.md -->

# Quality: Tests, Errors, Data, Contracts, Performance

Purpose: changes are verified, honest about failure, and safe to release.

## Tests

- Cover new or changed code where reasonable: the happy path, validation errors, edge
  cases, access rights, service and storage behavior, and regressions for fixed bugs.
- NEVER delete, disable, or weaken tests just to make a build green.
- If tests were not added, say why in the final report.
- Prefer the project's designated check runner over ad-hoc command sequences, and keep
  that runner updated when a task adds an important new part of the system.

## Errors and logging

- Handle errors explicitly. Forbidden: silently swallowed errors, empty catch blocks,
  debug logs left after the task, secrets or personal data in logs, print-style
  debugging instead of real handling.
- Logs must say where it broke, which component, what context matters, and how critical
  it is. Useful, not noisy.

## Database migrations

- Schema changes happen ONLY through migrations.
- Never edit or rename an already-applied migration; never delete migrations without a
  separate decision; never make irreversible changes without risk analysis.
- Verify each migration on a clean database, on an existing database where applicable,
  and together with the code that uses the new structure.

## Contracts

- When a task changes an API or an artifact format, update the contract and generated
  types.
- Never silently change field names, data types, response structure, error codes,
  parameter requiredness, or endpoint behavior.
- Any breaking change must be named explicitly in the final report.

## Performance and releases

- No premature optimization, but no obviously wasteful patterns: N+1 queries, heavy
  per-request computation, render loops, unpaginated large reads, redundant calls,
  blocking operations in responsive paths.
- If a change may affect performance, say so in the final report.
- Every change should be revertible; for risky changes plan the rollback before merging.
- Large new features ship behind a feature flag where the project supports them;
  unfinished functionality must not be reachable by accident; stale flags get removed
  after stabilization.

---

<!-- module: .ai/universal/07-multi-assistant.md -->

# Multi-Assistant Collaboration

Purpose: several AI assistants and humans work in this repository across separate
sessions; git is the coordination surface and the rule modules are shared.

## Coordination through git

- Before non-trivial work, check
  `git log -10 --date=iso-strict --pretty=format:"%h %cd %s"` and
  `git status --short --branch`: recent commits may be another assistant's finished
  work — not yours to redo or second-guess.
- Never rewrite history on another assistant's in-flight branch. Build on top of it or
  ask first.
- Keep commits attributable: include the assistant identity trailer the project already
  uses (see recent `git log` for the convention).

## Shared rule modules

- All assistants obey the same rules from `.ai/universal/` and `.ai/project/`. There is
  exactly one source of truth.
- `CLAUDE.md` imports the modules natively; `AGENTS.md` is GENERATED from them. Never
  hand-edit `AGENTS.md`; edit the module and regenerate (see the project commands
  module for the sync command).
- When a task changes shared behavior (workflow, gates, style, guardrails), change the
  module once — every assistant picks it up. Mirror-maintained per-assistant files
  (`.claude/` and `.codex/`: agents and skills) still need the same edit on both sides
  in the same task.

## Session hygiene for any model

- Re-read plans and rule files from disk instead of trusting memory of a previous
  session — files change between sessions.
- When context is shaky or the task is large, restate the task's acceptance criteria in
  the checklist before coding, and verify against files, not recollection.
- If two rules appear to conflict: the project module wins over the universal module;
  an explicit owner instruction in the current conversation wins over both. Say out
  loud which rule you chose and why.

---

<!-- module: .ai/project/10-project-map.md -->

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

---

<!-- module: .ai/project/11-commands.md -->

# Project Commands and Quality Gates

All commands run from the repository root (Windows: PowerShell or Git Bash).

## The script orchestrator — start here

```powershell
python dev_tools_scripts_runner.py          # interactive menu
python dev_tools_scripts_runner.py list     # machine-readable catalog — use this, not the menu
python dev_tools_scripts_runner.py <name>   # run one directly; `help` prints manuals
```

Cross-platform door to the routine jobs: `quality-gate` (default), `format-code`,
`dev-run`, `build-installer`, `doctor`, `install-hooks`, `clean-project`, `selftest`.
With no arguments and no terminal it runs `quality-gate` rather than blocking on input,
which is what makes it usable by an agent. The scripts wrap the `cargo xtask` commands
below instead of reimplementing them, so both doors reach the same code.

**`clean-project` deletes files.** Dry run by default. Read `config/clean.json`, and
`15-command-reference.md`, before running it for real.

**Standing duty — keep the scripts accurate and portable.** A task that changes how the
project is built, checked, formatted, run, or cleaned updates the matching script *in
that same task*; a script describing a workflow that no longer exists is worse than none.
Run `selftest` after touching anything under `scripts/`. How to add one, and the
portability rules, are in `15-command-reference.md`.

## Main entry point — the xtask runner

```powershell
cargo xtask gate            # full quality gate — the main verification path
cargo xtask gate --quick    # quick gate — the minimum before a push
cargo xtask fmt             # format Rust *and* frontend sources in place
cargo xtask lint            # clippy with warnings denied
cargo xtask test            # workspace tests
cargo xtask deny            # cargo-deny: advisories, bans, licenses, sources
cargo xtask sync-agents     # regenerate AGENTS.md from the .ai/ modules
cargo xtask sync-agents --check   # verify AGENTS.md is in sync
cargo xtask install-hooks   # install the formatting pre-commit hook
cargo xtask package         # build the Windows NSIS installer
cargo xtask doctor          # read-only environment diagnostics
cargo xtask golden          # regenerate the legacy golden references (needs Python)
```

Prefer `gate` over ad-hoc command sequences. `cargo xtask fmt` formats both toolchains;
run `install-hooks` once per clone and commits format themselves after that.

## Where the rest lives

`15-command-reference.md` holds the lookup material: per-layer commands, the Tauri
working-directory trap, how formatting and the pre-commit hook actually work, the
`cargo deny`/`golden` notes, and the platform notes. Kept separate so this module stays
the part that applies to every task.

## Gate policy

- The full gate must be green before merging to `main`; the quick gate is the minimum for
  intermediate pushes. Documentation- and configuration-only changes still run it.
- `sync-agents --check` is part of the gate: drift between `AGENTS.md` and `.ai/` breaks
  the build on purpose.
- Frontend `format`/`typecheck`/`lint` are part of it too. Without
  `apps/desktop/ui/node_modules` they skip with a notice so a Rust-only checkout still
  gates — but with `CI` set they **fail** instead, since a silent skip there would let
  unformatted frontend code through.
- The `scripts/` test suite runs in the full gate (not `--quick`), same skip-or-fail rule.
  It guards a tool that deletes files, so "runs nowhere" is not an option.
- CI runs all three OS legs independently (owner decision 2026-09-06): a green Windows leg
  never hides a red Unix one. Reading a red one: `15-command-reference.md`.

---

<!-- module: .ai/project/12-domain-rules.md -->

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

- **Network access is forbidden** in every workspace crate; no exception since Q41.
  S13's client is in the excluded `codepack-ai-api`.
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

---

<!-- module: .ai/project/13-progress-tracking.md -->

# Project Progress Tracking

Purpose: any assistant, in any session, on any model, can locate exactly where the
project stands and where it is going — **from files, not from memory**. This is the
primary recovery mechanism after a lost conversation.

## Where the truth lives

| Question | File |
|---|---|
| What the product is: logic, formats, math | `docs/__arch__/BLUEPRINT.md` |
| What is planned, in what order, what is done | `docs/__arch__/ROADMAP.md` |
| What is actually built right now | `docs/architecture/overview.md` |
| What must never break | `docs/architecture/invariants.md` |
| Owner decisions and open questions | `docs/__arch__/open-questions.md` |
| What the current or last task was | `task-checklist.md` |
| What actually happened recently | `git log -15 --date=iso-strict --pretty=format:"%h %cd %s"` |
| How the rules themselves changed | `.ai/CHANGELOG.md` |
| How the legacy version worked | `docs/__arch__/codepack-main.zip` |

## Orientation ritual — at the start of EVERY task

In order, without skipping:

1. `git status --short --branch` and
   `git log -15 --date=iso-strict --pretty=format:"%h %cd %s"` — with committer dates,
   not `--oneline`: several commits a day is normal here.
2. `docs/__arch__/ROADMAP.md` §1 and the `**Status.**` lines under each stage: a stage with a status
   line is done; **the first stage without one is next**.
3. `docs/architecture/overview.md` — what exists in the code right now.
4. `task-checklist.md` — what the previous task was and whether it finished cleanly.
5. `docs/__arch__/open-questions.md` — whether a decision changes the plan.
6. Only then plan the new task.

If the task touches behavior that existed in the legacy version, also consult the legacy
reference module.

## Update duties when finishing work

- Completed a stage or a significant slice → add or refresh the `**Status.**` line under
  that stage in `docs/__arch__/ROADMAP.md` (what shipped: crates, modules, commands, tests) and update
  the status column in §1. Write it in Russian to match that file.
- Changed the system's shape (new crate, new layer, new operational job) → update
  `docs/architecture/overview.md`.
- Made or received an owner decision that constrains the future → record it in
  `docs/__arch__/open-questions.md`, not only in the chat.
- Introduced an invariant → record it in `docs/architecture/invariants.md`.
- Changed a rule module → record it in `.ai/CHANGELOG.md` and regenerate `AGENTS.md`.
- Changed what a user can do, install or run → update `README.md`, in English. It is the
  external entry point, and a stale one is the first thing a new user reads.
- Wrote a new document → decide which audience it serves *before* choosing where it
  lives (see the internal/external split in the project map). An internal document goes
  in `docs/__arch__/` and is written in Russian; an external one is English and
  reachable from `README.md`.

## Drift guard

If the plan, the state document, and the code disagree: **the code is the fact, the plan
is the intent**. Reconcile them in the same task or report the mismatch explicitly.
Stale documentation is worse than no documentation.

## Unfinished-task rule

If `task-checklist.md` still holds open `[ ]` items from a previous session, resolve
them first: finish them, or mark them `-` with an honest note. Starting a new task on
top of a silently abandoned one is a violation.

---

<!-- module index: extended -->

# Modules loaded on demand

These rules bind exactly like the inlined ones; only their full text lives
outside this file, to stay within the instruction budget. Read the file itself
when a task touches it — that is an obligation, not a suggestion.

## Rules Evolution: Keeping the Instructions Current

File: `.ai/universal/08-rules-evolution.md`

Never weaken a rule to make a task easier — propose changes instead; autonomous edits may only clarify or correct, never loosen; every change needs a changelog entry and a regenerated entry point.

## Time and Timestamps: Never Take a Date Without Its Moment

File: `.ai/universal/09-time-and-timestamps.md`

Read and report every date at full precision — hours, minutes, seconds, zone. For git use `--date=iso-strict` (`git log --pretty=format:"%h %cd %s"`); `--oneline`, `--date=short` and "2 days ago" never answer *when*.

## Legacy Reference: The Previous Python Implementation

File: `.ai/project/14-legacy-reference.md`

`docs/__arch__/codepack-main.zip` is the behavioral reference for exact constants, artifact formats, and ambiguous behavior — consult it, never copy its Python architecture into Rust.

## Command Reference: Per-Layer Commands and Platform Notes

File: `.ai/project/15-command-reference.md`

Lookup material — per-layer commands, the Tauri working-directory trap, the platform notes, and reading a red CI run. Look here for a specific command; the gate, the orchestrator and the always-apply policies live in `11-commands.md`.
