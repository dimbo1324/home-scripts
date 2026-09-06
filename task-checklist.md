# Task Checklist

**Task:** Fix every finding in `docs/__arch__/AUDIT-2026-09-05.txt` — 40 findings, worst first.

**Date:** 2026-09-05
**Branch:** fix/audit-2026-09-05

Owner instruction, 2026-09-05: work through the whole audit in one branch, most serious
first, with careful intermediate commits; then update the documentation, produce a fresh
`.exe`, merge to `main`, push, delete every branch but `main` (local and remote), and shut
the machine down.

## How this is being worked

One commit per coherent group rather than per finding: several findings are the *same*
defect in different copies, and the audit's own summary says so — its central observation
is that one rule is implemented in several places and the copies drifted. Fixing a group
together is what stops the next copy from drifting too.

Where a finding asks for an owner decision rather than a repair (No. 1's redaction of
copied files, No. 26's fate of the API half), the honest half is done now and the question
goes into the decisions log rather than being invented.

## CRITICAL

- [+] **No. 2** — package.json scripts reach three reports unredacted while a fourth
      redacts them and explains why. One shared extractor returning already-redacted
      values, so the mistake becomes unexpressible; plus a bundle-wide test.
- [+] **No. 5** — the network-isolation gate is bypassed by ordinary TOML
      (`[dependencies.reqwest]`). Parse with a real TOML parser, take the package name
      from `[package]`, walk `workspace.members`, drop the duplicate `ureq`, add the
      negative test that would have caught it.
- [+] **No. 6** — six Tauri commands take a path from the webview and unpack archives and
      open files with it. Validate against the export history, unpack under app data,
      confine `open_path`.
- [+] **No. 4** — `action.yml` interpolates `${{ inputs.* }}` inside `run:`. Pass inputs
      through `env:`, validate against a whitelist, protect `GITHUB_OUTPUT`, pin `ref`.
- [+] **No. 1** — README promises secrets never reach the archive; copied source files are
      not redacted. Correct the README and the misleading docstring now; record the
      behaviour question as an owner decision.

## HIGH

- [+] **No. 3** — I2 is checked only by the CLI; move it into `run_export`
- [+] **No. 13** — the CLI's I2 check creates the directory before checking
- [+] **No. 7** — placeholder recognition is a prefix match; make it exact
- [+] **No. 8** — `restore_archive_set` applies the budget per volume, not per set
- [+] **No. 9** — unbounded recursion depth on directory walks
- [+] **No. 10** — git blob contents written to disk without path validation
- [+] **No. 11** — the CLI prints error text unredacted
- [+] **No. 12** — `ERROR_*.txt` diagnostics written into the bundle unredacted

## MEDIUM (14 - 27)

- [+] No. 14 verify re-reads a file per finding · No. 15 text dump built wholly in memory
- [+] No. 16 detectors allocate per line · No. 17 watch throttle drops the last change
- [+] No. 18 MCP hangs when stdout closes first · No. 19 cache key tied to crate version
- [+] No. 20 21 of 32 reports read files without redacting · No. 21 absolute paths with
      the account name reach the bundle · No. 22 no total budget on `scan --history`
- [+] No. 23 duplicated path logic · No. 24 two file-group tables · No. 25 stale allowlist
      docs · No. 26 the API half of `codepack-ai` is unreachable · No. 27 dead config
      functions

## LOW (28 - 40)

- [+] No. 28 CSP `unsafe-inline` · No. 29 one unescaped HTML parameter · No. 30 ZIP64 and
      buffering · No. 31 `fs::copy` follows symlinks · No. 32 byte-offset slicing
- [+] No. 33 advisory ignores without review dates · No. 34 cache read whole · No. 35
      fingerprint built with `format!` per byte · No. 36 duplicated page CSS
- [+] No. 37 "Eleven" vs "Twelve" commands · No. 38 version in two places · No. 39
      duplicate entry in the xtask rule list · No. 40 quadratic pre-commit check

## Completion

- [+] Documentation updated (`README.md`, `docs/architecture/overview.md` and
      `invariants.md`, `docs/__arch__/open-questions.md` Q39-Q42, `ROADMAP.md`,
      `.ai/project/12-domain-rules.md` and `.ai/CHANGELOG.md`, `AGENTS.md` regenerated)
- [+] `cargo xtask gate` green
- [+] Fresh installer built (`cargo xtask package`)
- [+] Merged to `main`, pushed
- [+] Every branch but `main` deleted, local and remote
- [+] Final report in Russian

## What was NOT done, and why

- **No. 1, No. 21, No. 26, No. 27** each ask for a change that is the owner's to make, not
  a repair. In every case the half that is unambiguously a fix was done and the decision
  itself was recorded rather than invented:
  - No. 1: README and the `redact_secrets` docstring now describe what the code does.
    Whether an export should redact the *contents* of the files it copies — which would
    stop a bundle being a buildable project — is Q39.
  - No. 21: `Config::disclose_absolute_paths` exists and works, defaulting to today's
    behaviour so no artifact and no golden reference moved. Making the safer value the
    default changes artifact contents and needs a `schema_version` bump: Q40.
  - No. 26: `docs/architecture/overview.md` now says the API half of `codepack-ai` cannot
    be reached from either binary. Finishing S13 or splitting the crate out is Q41.
  - No. 27: `normalise_profile` was a dead duplicate of a live function and is deleted.
    `import_settings`/`export_settings` are an unimplemented capability rather than dead
    code, so their fate is Q42.
- **No. 10**, staged half: no end-to-end fixture. `libgit2`'s own `Index::add` refuses a
  path containing `..`, so the guard there covers an index file written by something else,
  and building one means writing the on-disk index format with its SHA-1 checksum — a
  dependency the project does not have. The rule itself is covered in `codepack_core::paths`,
  and the reason is recorded at the guard.
- **No. 15**, per-file streaming: the dump is now streamed to disk and a hard 256 MiB
  ceiling applies regardless of configuration, but each file is still read whole.
  `decode_best_effort` needs the entire buffer to name the encoding in the dump's banner,
  so reading line by line would change encoding detection — a behaviour change the audit
  did not ask for.
- **No. 20**, the `read_text_redacted` counterpart the audit suggested: tried and removed.
  `redact_line` trims each line by contract, so redacting a file before parsing destroys
  the indentation a YAML parser needs — the Docker report stopped finding services. The
  naming and the gate carry the rule instead; `text.rs` records the attempt.
- **No. 34**, selecting only this run's cache keys: not done, deliberately. A key is a
  hash of a file's contents, so knowing the keys means reading every file before the scan
  — an extra full read pass to avoid loading a bounded number of small rows. The reasoning
  is in `load_scan_cache`.
- **No. 36**: the frontend has no test runner, so the CSS consolidation is verified by
  `typecheck`, `lint` and a production build (bundled CSS fell from 42.6 to 41.8 KiB), not
  by an automated visual check.
