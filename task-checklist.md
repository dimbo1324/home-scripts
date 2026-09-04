# Task Checklist

**Task:** Implement the improvement batch proposed on 2026-09-05 — business logic only.

**Date:** 2026-09-05
**Branch:** feat/scan-perf-allowlist-mcp-ui

Owner instruction, 2026-09-05: implement **every** proposal from the preceding message,
and *only* the business logic. Explicitly out of scope by owner instruction: writing
tests, writing or updating documentation, and running the app / the gate. Compilation
checks were used as a correctness tool for the edits themselves — code that does not
build is not delivered work.

**Standing debt this task deliberately creates** (owner asked for the code now, the rest
later): no new tests for any of the behaviour below; no `README.md`,
`docs/architecture/overview.md` or `docs/__arch__/ROADMAP.md` updates; no decision
records in `docs/__arch__/open-questions.md` for the decisions this task acts on.

## Preparation

- [+] Branch from up-to-date `main`, commit this checklist before the work

## Business logic

1. Parallel content scan

- [+] `codepack-security` takes `rayon`; `scan_project`'s per-file loop is an ordered
      parallel map, so finding order stays byte-identical (the three sorts are stable and
      tie on insertion order, and `06_security_scan.json`/SARIF/goldens depend on it).
      Errors are selected by input order too, not by whichever thread failed first.
      Cancellation still checked per file

2. Scan-result cache keyed by content hash

- [+] `codepack-storage` migration 2 (`file_scan_cache`), LRU-pruned at 50 000 entries
- [+] `codepack-engine::scan_cache` implements the trait `codepack-security` defines; the
      whole table is read before the pass and written once after, because the pass is
      parallel and a `Connection` is not `Sync`
- [+] Only content-derived findings are cached — the sensitive-filename rule is a fact
      about the path, and caching it under a content key would report `.env`'s severity
      for a copy saved as `notes.txt`
- [+] The key covers the detector recipe, the crate version and the option bits, so an
      improved detector cannot ship and silently keep answering with the old verdict
- [+] A labelling run bypasses the cache: `<REDACTED:s1>` is numbered per run, so a
      stored message would carry a number standing for a different value

3. Offline provider-token checksum validation

- [+] `codepack-security::patterns::checksum` — CRC32 + base62, GitHub's classic shapes
- [+] A failing checksum downgrades to `medium` rather than dropping the finding
- [−] **Off by default** (`Config::strict_token_checksums`), against the plan, and the
      reason is a finding rather than caution: GitHub's blog states the checksum exists
      but does **not** publish the recipe, and the public implementations that reproduce
      it are reverse-engineered and disagree on what the CRC is taken over. An
      unverifiable algorithm that can demote a real token is a recall loss in the one
      detector this product exists for (I9). Flip the default once a freshly issued token
      of each accepted prefix has been checked against this code

4. Release checksums

- [+] `cargo xtask package` writes `SHA256SUMS.txt` beside the installer; `sha2` added to
      xtask with the reason recorded in its manifest
- [−] Code signing / notarisation **not done**: it needs a certificate this repository
      does not and must not hold

5. Redaction labels reach the scan artifacts (Q34)

- [+] The engine passes a `Redactor` into the scan, so `<REDACTED:s1>` reaches
      `06_security_scan.json`, SARIF and the text report
- [−] Done through `message` rather than a new `Finding` field, and **no `schema_version`
      bump**, which is a deliberate departure from the plan: the shape does not change
      (nothing added, removed or retyped), and `06_security_scan.json`'s version is
      compared against the archived legacy implementation by the golden references — a
      bump could never be satisfied by regenerating them. A structured `labels` field
      remains possible; it would break existing `Finding` literals, which is test work

6. `.codepack-allow` honoured beyond `scan`/`verify` (Q26)

- [+] Screening moved from `codepack-cli` into `codepack-security::allow`, so the export
      pipeline and the ~30 reports reach the verdict the CLI already did
- [+] Read from the source project, never the staging copy; suppressions are counted and
      named in the run log, never silently dropped

7. `scan --baseline`

- [+] `--baseline <file>` filters, `--write-baseline <file>` records; its own JSON format
      with `schema_version`, separate from `.codepack-allow` so nobody bulk-dumps
      unreviewed entries into the file that means somebody read them
- [+] Order: allowlist, then write, then filter. The MCP scan tool passes no baseline

8. Strict pre-commit hook (Q35)

- [+] `codepack init --hook --strict` refuses a commit it cannot check

9. MCP: cancellation and resources (Q37)

- [+] Input is read on its own thread, the call runs on a worker, and
      `notifications/cancelled` naming that request trips the tool's token. Still one
      request at a time; anything else is queued and answered in order
- [+] Cancellation reaches `scan` (including `--history`) and `export`
- [−] `preview` and `explain` are not cancellable: both finish in the time it takes to
      walk the tree, and a token there gives a client nothing to act on
- [+] `resources/list` / `resources/read` over the bundle this session produced, and only
      that — a server that opened any URI handed to it would be a file-reading service
      wearing a scanner's name

10. Parallel report generation

- [+] The catalogue runs in three phases: profile first, the independent reports
      concurrently, `REPORT_DASHBOARD.html` last (it reads siblings). Outcomes fold in
      job order, so the summary and `ERROR_<name>.txt` files are unchanged

11. Artifact localization (Q12)

- [+] `Config::artifact_language` (default `en`), `ReportContext::artifact_language()`,
      and the summary report driven by it instead of a hard-coded `Language::En`. A field
      of its own rather than `Config::language`, whose default `ru` would have flipped
      every report
- [−] **The other ~29 reports are still English-only.** The mechanism is wired; the
      translation is not. Writing several hundred technical strings in Russian without
      review would put unverified text into a product surface, and some report strings
      are part of an artifact contract that must be preserved verbatim. Deliberately not
      fabricated

12. `explain` in the desktop app

- [+] The verdict moved into `codepack_engine::explain`, so both front ends ask one
      implementation; `canonicalize_existing` moved to `codepack-core` with it
- [+] `explain_file` Tauri command, typed client method, and the minimum UI on the
      preview page — where the question is actually asked

13. The S13 API path gets its door

- [−] **Not done, and not because it is hard.** `cargo xtask gate`'s `network isolation`
      step fails when a dependent crate enables `codepack-ai`'s `api` feature, which is
      the mechanism enforcing invariant I1 — the error text itself says this is an owner
      decision recorded in `docs/__arch__/open-questions.md`, not a dependency added in
      passing. Building this UI means either weakening that check or restructuring how
      the transport is linked. Both need the owner, so the work stopped here rather than
      loosening the rule to finish a task

## Not done in this task, and why

- [−] Fuzzing the archive-extraction and tree-sitter paths — test code, excluded
- [−] README screenshots — needs the app to be run, excluded
- [−] `deny.toml` gtk/gdk advisory ignores — removing one blind can turn the gate red; it
      needs a `cargo tree` verification run, excluded
- [−] `AGENTS.md` size budget (Q22) — a rules/documentation change, excluded
- [−] Linux/macOS gate diagnosis (Q21) — needs runs on those platforms

## Verification

- [+] `cargo check --workspace --all-targets` clean
- [+] `cargo clippy --workspace --all-targets -- -D warnings` clean
- [+] `cargo xtask fmt` applied
- [+] `pnpm --filter @codepack/ui typecheck` — 137 files, 0 errors; `lint` clean
- [−] **The test suite was not run and the gate was not run**, by owner instruction. This
      change touches the scanner's ordering, the report runner's concurrency and the MCP
      loop's structure — three places where only execution can confirm the reasoning. The
      work is not verified, and is not claimed to be

## Completion

- [+] Checklist filled with `+`/`-`
- [−] Not merged to `main` and not pushed: no publish was requested, and the quality gate
      has not been run
- [+] Final report in Russian
