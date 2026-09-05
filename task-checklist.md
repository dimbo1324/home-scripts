# Task Checklist

**Task:** Fix every finding in `AUDIT-2026-09-05.txt` — 40 findings, worst first.

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

- [ ] **No. 2** — package.json scripts reach three reports unredacted while a fourth
      redacts them and explains why. One shared extractor returning already-redacted
      values, so the mistake becomes unexpressible; plus a bundle-wide test.
- [ ] **No. 5** — the network-isolation gate is bypassed by ordinary TOML
      (`[dependencies.reqwest]`). Parse with a real TOML parser, take the package name
      from `[package]`, walk `workspace.members`, drop the duplicate `ureq`, add the
      negative test that would have caught it.
- [ ] **No. 6** — six Tauri commands take a path from the webview and unpack archives and
      open files with it. Validate against the export history, unpack under app data,
      confine `open_path`.
- [ ] **No. 4** — `action.yml` interpolates `${{ inputs.* }}` inside `run:`. Pass inputs
      through `env:`, validate against a whitelist, protect `GITHUB_OUTPUT`, pin `ref`.
- [ ] **No. 1** — README promises secrets never reach the archive; copied source files are
      not redacted. Correct the README and the misleading docstring now; record the
      behaviour question as an owner decision.

## HIGH

- [ ] **No. 3** — I2 is checked only by the CLI; move it into `run_export`
- [ ] **No. 13** — the CLI's I2 check creates the directory before checking
- [ ] **No. 7** — placeholder recognition is a prefix match; make it exact
- [ ] **No. 8** — `restore_archive_set` applies the budget per volume, not per set
- [ ] **No. 9** — unbounded recursion depth on directory walks
- [ ] **No. 10** — git blob contents written to disk without path validation
- [ ] **No. 11** — the CLI prints error text unredacted
- [ ] **No. 12** — `ERROR_*.txt` diagnostics written into the bundle unredacted

## MEDIUM (14 - 27)

- [ ] No. 14 verify re-reads a file per finding · No. 15 text dump built wholly in memory
- [ ] No. 16 detectors allocate per line · No. 17 watch throttle drops the last change
- [ ] No. 18 MCP hangs when stdout closes first · No. 19 cache key tied to crate version
- [ ] No. 20 21 of 32 reports read files without redacting · No. 21 absolute paths with
      the account name reach the bundle · No. 22 no total budget on `scan --history`
- [ ] No. 23 duplicated path logic · No. 24 two file-group tables · No. 25 stale allowlist
      docs · No. 26 the API half of `codepack-ai` is unreachable · No. 27 dead config
      functions

## LOW (28 - 40)

- [ ] No. 28 CSP `unsafe-inline` · No. 29 one unescaped HTML parameter · No. 30 ZIP64 and
      buffering · No. 31 `fs::copy` follows symlinks · No. 32 byte-offset slicing
- [ ] No. 33 advisory ignores without review dates · No. 34 cache read whole · No. 35
      fingerprint built with `format!` per byte · No. 36 duplicated page CSS
- [ ] No. 37 "Eleven" vs "Twelve" commands · No. 38 version in two places · No. 39
      duplicate entry in the xtask rule list · No. 40 quadratic pre-commit check

## Completion

- [ ] Documentation updated (`README.md`, `docs/architecture/*`, `open-questions.md`,
      `ROADMAP.md` where the shape changed)
- [ ] `cargo xtask gate` green
- [ ] Fresh installer built (`cargo xtask package`)
- [ ] Merged to `main`, pushed
- [ ] Every branch but `main` deleted, local and remote
- [ ] Final report in Russian
