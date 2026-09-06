# Task Checklist

**Task:** Return macOS and Linux to the supported set, and close Q21 — the `cargo xtask
gate` failure on both Unix runners whose cause had never been found.

**Date:** 2026-09-06
**Branch:** feat/cross-platform-return

Owner instruction, 2026-09-06: "начинай кроссплатформенность". The stated goal behind it
is that the product runs on the owner's team's machines, not only the owner's.

**Written retrospectively**, part-way through the work, which the protocol says to do
first. The reason is not a good one — the branch grew out of the preceding owner-decision
task rather than starting as its own — and the honest record is worth more than a
back-dated file. Everything below is marked from what actually happened.

## Preparation

- [+] Read the 2026-09-06 owner decisions in `docs/__arch__/open-questions.md`
- [+] Establish what "switched off" actually meant in code (`TODO(cross-platform)` sweep)

## Implementation

- [+] Restore `codepack-core::paths`: `Os::{Mac,Linux}`, `current_os()`, `layout()`,
      `resolve_base_dirs()`, `home_dir_from_env()`, and the two BLUEPRINT §D.4 tests
- [+] Restore the three-runner CI matrix and the Tauri Linux dependency step
- [+] Make a failing gate diagnosable from outside: an annotation naming the failed
      section, one per failing test, and the test's own output as the reason
- [+] `--no-fail-fast`, so one round names every failure instead of one crate's worth
- [+] **Q21 root cause**: `safe_join` accepted a Windows-shaped path on Unix, because
      `Path::components` splits on a backslash only on Windows. Fixed in the check, not
      the test — the input arrives from archives and other people's git trees
- [+] `find_on_path` searched only Windows-style names; no formatter resolved on macOS or
      Linux, silently. Per-platform search, executable bit on Unix
- [+] `05_git_deep.txt` printed libgit2's absolute `workdir()` past
      `disclose_absolute_paths`; routed through `disclosed_source_root()`
- [+] The bundle-wide sweep searched two spellings of a path, not three, and named only
      the file. Third spelling added; it now names the offending line

## Verification

- [+] Full `cargo xtask gate` green locally (Windows), all ten sections
- [+] CI green on `ubuntu-latest`, `macos-latest` and `windows-latest` (run 34034377909)
- [+] Every fix carries a regression test that fails on the platform that had the defect
- [-] No local Unix run: Docker Desktop's daemon was not running and there is no WSL
      distro on this machine. Verification of the Unix side is CI's, which is why the
      annotations mattered

## Completion

- [+] `ROADMAP.md` §1 and the B.4 row; `open-questions.md` Q21 row and a resolution section
- [+] `.ai/project/11-commands.md`, `15-command-reference.md`, `.ai/CHANGELOG.md`, `AGENTS.md`
- [+] Final report to the owner
- [-] Not merged to `main` and not published: the owner asked for the work, not for a
      release. Awaiting an explicit instruction

## Not done, deliberately

- **Packaging for macOS and Linux.** `cargo xtask package` still builds only the Windows
  NSIS installer. BLUEPRINT and `ROADMAP.md` put bundling for the other two in S14, and
  pulling it forward was not asked for. The *code* runs on all three; the *installer*
  does not exist for two of them.
- **Q43** (the residual window between `symlink_metadata` and `open` in the copy guard)
  still awaits an owner decision on taking a `libc` dependency for `O_NOFOLLOW`.
