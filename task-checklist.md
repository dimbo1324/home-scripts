# Task Checklist

**Task:** A quality pass over the existing code — no new business logic. Find genuine
weak points, harden them, and make what is there more modular and maintainable.

**Date:** 2026-09-05
**Branch:** refactor/harden-extraction-and-split-modules

Owner instruction, 2026-09-05: merge and push the previous branch, then improve the
existing code — security, readability, maintainability, and "as object-oriented as
possible" — without introducing new behaviour. Explicitly: *if something does not need
changing, do not change it.*

## On the object-orientation request, stated before acting

Rust is not class-oriented, and forcing inheritance hierarchies onto it produces worse
code, not better. What carries over from OO — and what this task actually pursues — is
encapsulation (nothing public that does not need to be), cohesion (a module doing one
thing), and programming against an interface rather than a concrete type. The codebase
already does the third well: `FileScanCache`, `AiProvider` and `ReportJob` are trait or
function-table seams. This task fixes the first two where they are genuinely broken.

## What the audit found, and what it cleared

Measured rather than assumed. Cleared, and therefore **not touched**:

- No `unsafe` anywhere in production code.
- Every `panic!`/`todo!`/`unimplemented!` is in a test.
- HTML generation escapes correctly — `escape_html` is applied at every interpolation in
  `dashboard.rs` and `overview.rs` (a line-based search suggested otherwise; reading the
  call sites showed the escaping sits on the argument lines).
- The frontend has no `any`, no `@ts-ignore`, no non-null assertions.
- Path-traversal safety on extraction is sound: `enclosed_name()` **and** an independent
  lexical check, failing closed on the first bad member.
- Of six modules over 600 raw lines, four are under the limit once their inline tests are
  excluded, and two more are test files, which the rules exempt. Only two are real.

## Preparation

- [+] Branch from up-to-date `main`, commit this checklist before the work

## 1 — Security: a decompression bomb has nothing stopping it

- [+] `extract_zip_safely` streams every member with `std::io::copy` and no ceiling, and
      `codepack verify` feeds it an archive that came from somebody else — the one input
      in this product that is untrusted by design. A small archive expanding to hundreds
      of gigabytes fills the disk.
- [+] Add a budget: total decompressed bytes, per-member bytes, and member count. Fail
      closed, naming the limit that was hit.
- [+] Keep `extract_zip_safely`'s signature so no caller breaks; the limits are a value
      with a `Default`, and a caller that needs different ones passes them.
- [+] `read_zip_entry_to_string` gets the same per-member ceiling.

## 2 — Two modules genuinely past the project's own 600-line limit

Both were pushed over the line by the previous task, so this is cleaning up after it.

- [+] `codepack-cli/src/commands/scan.rs` (757 production lines) -> directory module
- [+] `codepack-security/src/scan/mod.rs` (748) -> split by responsibility
- [+] The public surface of each stays exactly as it is: this is code movement, not an
      API change.

## 3 — Encapsulation: production API widened for tests

- [+] `codepack_engine::explain` exports five helpers (`default_reason`,
      `relative_to_project`, `resolve_through_existing_ancestor`, `plan_spelling`,
      `skipped_directory_on_path`) that nothing outside the crate legitimately needs —
      they are `pub` only because CLI tests reach them. Also from the previous task.
- [+] Narrow them, and move the tests that exercise them into the crate that owns them.

## 4 — One `unwrap` without the justification the rules require

- [+] `xtask/src/sync_agents.rs`: `path.file_name().unwrap()`. The rule allows `unwrap`
      only "where the invariant is proven by an adjacent comment". Restructure so the
      name is never an `Option` rather than adding a comment to excuse it.

## Verification

- [+] `cargo xtask gate` green — all eight sections, exit 0. 1424 Rust tests across 56
      binaries, `cargo deny` clean, frontend 137 files / 0 errors, 78 `scripts/` tests,
      `AGENTS.md` in sync, network isolation ok
- [+] The refactor is behaviour-preserving: every test that passed before passes after,
      and none was rewritten to match new behaviour. Eight tests were *added*, all for
      the decompression budget, which is new behaviour by design
- [+] `cargo xtask sync-agents --check` still reports `AGENTS.md` byte-identical after
      the xtask change, which is what makes that one a refactor rather than a change
- [+] Module sizes re-measured afterwards: no production module is over the limit; the
      only files above it are test files, which the rules exempt

## Also audited and deliberately left alone

Reported so the next reader knows these were checked rather than skipped:

- **The desktop shell.** The webview holds no filesystem, shell or HTTP permission; the
  CSP is `default-src 'self'` with no remote origin; lock poisoning is handled everywhere
  (`.lock().unwrap()` appears nowhere) and two tests prove the registry survives a thread
  panicking while holding it.
- **HTML generation.** `escape_html` is applied at every interpolation in `dashboard.rs`
  and `overview.rs`.
- **The frontend.** No `any`, no `@ts-ignore`, no non-null assertions.
- **Path traversal.** Two independent checks per member, failing closed.
- **`verify.rs`, `mcp/mod.rs`, `mcp/tools.rs`, `git_report.rs`** — all under the limit
  once inline tests are excluded, so splitting them would have been churn.

## Not done, and why

- **No OO rewrite.** Rust has no class hierarchies, and adding trait objects where a
  concrete type is correct would cost indirection and readability for nothing. The
  seams that genuinely deserve an interface already have one.
- **No behaviour changed** anywhere except the new extraction ceiling, which is the point
  of item 1.

## Completion

- [+] Checklist filled with `+`/`-`
- [+] Final report in Russian
- [-] Not merged or pushed: no publish was requested for this branch. The gate is green,
      so the merge is available on request.
