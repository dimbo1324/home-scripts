# Command Reference: Per-Layer Commands and Platform Notes

<!-- tier: extended -->

> **Essence.** Lookup material — per-layer commands, the Tauri working-directory trap, and Windows-only platform notes. Read this file when you need a specific command; the gate, the orchestrator, and the policies that always apply live in `11-commands.md`.

Split out of `11-commands.md` on 2026-07-26 so the compiled `AGENTS.md` stays under the
32 KiB of project instructions Codex reads. Nothing was dropped: this is reference you
look up when you need it, while `11-commands.md` keeps everything that applies to every
task. `CLAUDE.md` imports both natively, so Claude sees this in full.

## Direct commands when targeting one layer

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace
pnpm install --frozen-lockfile
pnpm format                        # Prettier, check only
pnpm format:write                  # Prettier, rewrite in place
pnpm --filter @codepack/ui typecheck
pnpm --filter @codepack/ui lint
pnpm --filter @codepack/ui build
```

Frontend commands need `pnpm install` once. `apps/desktop/src-tauri` (crate
`codepack-desktop`) is a normal workspace member, so `cargo xtask gate` builds and tests
it like any other crate.

## Running the app, and the working-directory trap

`pnpm desktop:dev` runs the app with hot reload; `pnpm desktop:build` bundles it.

**The working directory matters.** The Tauri CLI locates a project by finding
`tauri.conf.json` in a *subfolder* of the current directory. Here the shell
(`apps/desktop/src-tauri`) sits **beside** the frontend (`apps/desktop/ui`) rather than
under it, so from `ui` the config is a sibling and the CLI aborts with "couldn't
recognize the current folder as a Tauri project" — which is why the once-documented
`pnpm --filter @codepack/ui exec tauri dev` never worked at all. Both `desktop:*` scripts
run from `apps/desktop`, and the CLI is a workspace-root dev dependency so it resolves
there.

`cargo xtask package` (or the `build-installer` script) leaves an NSIS `.exe` in
`target/release/bundle/nsis/`. Signing, notarisation, `SHA256SUMS.txt`, and auto-update
stay in stage S14 — only the installer itself was pulled forward, by owner decision
2026-07-26.

## Formatting, and the pre-commit hook

`rustfmt` owns `.rs` (`rustfmt.toml`); Prettier owns the frontend and config files
(`prettier.config.mjs`; `.prettierignore` protects `tests/golden/`, test fixtures, and
the generated `AGENTS.md`). `cargo xtask fmt` runs both.

`install-hooks` once per clone points `core.hooksPath` at the tracked `.githooks/`, so
the hook is versioned instead of living in an untracked `.git/hooks`. The `pre-commit`
hook formats **only staged files** and re-stages them; it skips a partially staged file
rather than sweeping its unstaged half into the commit, and skips Prettier with a notice
when `node_modules` is absent. `git commit --no-verify` bypasses it once — the gate still
checks formatting later.

## Adding or changing a dev script

New routine work gets a new script: `scripts/<name>/__main__.py` plus one entry in
`scripts/runner/config/scripts.json` — adding a script changes no Python in
`scripts/runner/`. Settings live in each script's own `config/*.json`; scripts never
import each other, only `scripts/_toolkit`. Resolve tools through
`_toolkit/processes.py` (a bare `"pnpm"` does not resolve on Windows), and let genuinely
Windows-only work refuse with a reason instead of failing part-way.

## `clean-project`, and per-clone git settings

`clean-project` is a dry run by default; it never touches `.env`, signing material,
local databases, or a nested git repository — judging a directory by its contents, since
git reports a wholly untracked one as a single entry. Read its `config/clean.json`
first. It refuses to plan when `git status` cannot see the whole tree, and names the fix.

**Per-clone git settings**, checked by `doctor` as warnings: `core.hooksPath` at
`.githooks` (run `install-hooks`), and on Windows `core.longpaths true`, without which
`clean-project` cannot plan.

## Other tools

`cargo deny check` needs the `cargo-deny` binary installed separately (`cargo install
cargo-deny`, not a toolchain component; CI uses `taiki-e/install-action`).

`cargo xtask golden` re-runs the archived legacy implementation to rewrite
`tests/golden/reference/`. Developer-machine only: it needs Python 3, and CI never runs
it because the references are committed. Run it when legacy's own output *should* change
— never to make a failing comparison pass.

`cargo xtask ai-api` formats, lints and tests `codepack-ai-api` — the S13 API path, which
`workspace.exclude` keeps out of the product build (owner decision 2026-09-06, Q41, so
that `keyring` and `ureq` are not compiled on every platform for code no binary reaches).
**The gate does not run it**, which is the cost of the exclusion: this crate is preserved,
not maintained. Run it when touching that crate, and before finishing stage S13. Its
formatting *is* covered by `cargo xtask fmt` and by the gate's format step, because
formatting compiles nothing.

## Platform notes

Target today: **Windows 10/11** — but macOS and Linux are back in the plan as of the
owner decision 2026-09-06, and the switched-off code below is what has to come back. See
`docs/__arch__/open-questions.md` for that decision and for the superseded 2026-07-26
one, and Q21 for what must be re-diagnosed before the two platforms return.

- Windows: long paths and antivirus interfere with temporary directories; prefer a
  repository-local temp directory in tests.
- Switched-off cross-platform code is **commented with `TODO(cross-platform)`**, never
  deleted — grep that marker to find everything that must return together.
  `codepack-core::paths` is the only domain crate affected.
- Test helpers under `#[cfg(unix)]` stay: they do not compile on Windows, so they cost
  nothing there, and they carry the invariant I7 symlink coverage.
- The Rust toolchain is pinned in `rust-toolchain.toml`; do not bypass it. Node and pnpm
  versions are declared in `package.json`.
