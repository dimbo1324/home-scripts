# Task Checklist

**Task:** Implement the improvement batch proposed on 2026-09-05 — business logic only.

**Date:** 2026-09-05
**Branch:** feat/scan-perf-allowlist-mcp-ui

Owner instruction, 2026-09-05: implement **every** proposal from the preceding message,
and *only* the business logic. Explicitly out of scope by owner instruction: writing
tests, writing or updating documentation, and running the app / the gate. Compilation
checks (`cargo check`) are used as a correctness tool for the edits themselves — code
that does not build is not delivered work.

**Standing debt this task deliberately creates** (owner asked for the code now, the rest
later): no new tests for any of the behaviour below; no `README.md`,
`docs/architecture/overview.md` or `docs/__arch__/ROADMAP.md` updates; no decision
records in `docs/__arch__/open-questions.md` for the two owner decisions this task acts
on (the I5 format change in item 5 and the severity-assignment change in item 3).

## Preparation

- [ ] Branch from up-to-date `main`, commit this checklist before the work

## Business logic

1. Parallel content scan

- [ ] `codepack-security` takes `rayon`; `scan_project`'s per-file loop becomes an
      ordered parallel map so finding order stays byte-identical (golden references and
      SARIF depend on it), cancellation still checked per file

2. Scan-result cache keyed by content hash

- [ ] `codepack-storage` migration 2: a cache table keyed by `sha256` + a detector
      fingerprint, so a changed detector never serves stale findings
- [ ] `codepack-engine` consults the cache before scanning and fills it afterwards

3. Offline provider-token checksum validation

- [ ] GitHub's documented `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`/`github_pat_` checksum
      (base62 CRC32 of the body) verified in `codepack-security::patterns::provider`
- [ ] A failing checksum **downgrades** the finding rather than dropping it: recall is
      never traded for precision (I9), and a wrong algorithm must not be able to hide a
      real token

4. Release checksums (the part of S14 that is not a certificate)

- [ ] `cargo xtask package` writes `SHA256SUMS.txt` beside the installer
- [ ] Code signing / notarisation: **not done** — needs a certificate the repository
      does not and must not hold

5. Redaction labels reach the scan artifacts (Q34, invariant I5)

- [ ] `Finding` carries the stable per-secret label; `06_security_scan.json` and SARIF
      emit it; `schema_version` bumped on both

6. `.codepack-allow` honoured beyond `scan`/`verify` (Q26)

- [ ] The export pipeline and the reports filter accepted findings through the same
      allowlist the CLI already uses

7. `scan --baseline`

- [ ] Report only what is not present in a stored baseline of the working tree, and be
      able to write that baseline

8. Strict pre-commit hook (Q35)

- [ ] `codepack init --hook --strict` writes a hook that fails the commit when the
      binary is missing instead of warning and passing

9. MCP: cancellation and resources (Q37)

- [ ] `notifications/cancelled` observed by a running tool call through the engine's
      existing cancellation token
- [ ] `resources/list` + `resources/read` over a produced bundle

10. Parallel report generation

- [ ] Independent reports built in parallel, cancellation still observed

11. Artifact localization (Q12)

- [ ] The report catalogue's strings go through the localization layer rather than one
      pilot report

12. `explain` in the desktop app

- [ ] A Tauri command over the CLI's own explain builder and the minimum UI to reach it

13. The S13 API path gets its door

- [ ] Config fields, Tauri commands and the minimum UI for the key, the model and the
      explicit send confirmation

## Not done in this task, and why

- [ ] Fuzzing the archive-extraction and tree-sitter paths — that is test code, excluded
      by the owner's instruction
- [ ] README screenshots — needs the app to be run, excluded by the owner's instruction
- [ ] `deny.toml` gtk/gdk advisory ignores — removing one blind can turn the gate red;
      it needs a `cargo tree` verification run, excluded by the owner's instruction
- [ ] `AGENTS.md` size budget (Q22) — a rules/documentation change, excluded
- [ ] Linux/macOS gate diagnosis (Q21) — needs runs on those platforms

## Verification

- [ ] `cargo check --workspace --all-targets` clean (compilation only; no test run, no
      gate, by owner instruction)

## Completion

- [ ] Checklist filled with `+`/`-`
- [ ] Final report in Russian, naming every piece of deferred work honestly
