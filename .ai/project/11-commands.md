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
