# Task Checklist

**Task:** Bring codepack to a release — version 2.0.0, working on Windows 10 and 11.
Finish what is unfinished, re-run the tests, make every document accurate, and produce a
fresh installer.

**Date:** 2026-09-06
**Branch:** feat/cross-platform-return → main

Owner instruction, 2026-09-06: bring the project to a logical conclusion so it works on
Windows 10/11; finish the unfinished business logic and tests; re-run the tests; update
all the documentation; produce an up-to-date `.exe`. Further features come after.

## Preparation

- [ ] Survey what is genuinely unfinished, rather than assuming (stub sweep, CLI/UI
      inventory, version strings, existing bundle)
- [ ] Decide the version number and what a 2.0.0 does *not* claim

## Implementation

- [ ] Version `2.0.0-dev` → `2.0.0` everywhere it is written, including the excluded
      `codepack-ai-api` and the frontend package
- [ ] CI: the four actions GitHub is force-migrating off Node 20
- [ ] Fix whatever the sweep finds genuinely half-done and reachable on Windows

## Verification

- [ ] `cargo xtask gate` green — all ten sections
- [ ] `cargo xtask ai-api` green — the excluded crate the gate cannot see
- [ ] CI green on all three runners
- [ ] The installer builds, and the built app reports the new version

## Documentation

- [ ] `README.md` — install, version, what a release does and does not include; the stale
      "checksums planned but not done" claim (`SHA256SUMS.txt` is produced today)
- [ ] `docs/architecture/overview.md` — state of the system at 2.0.0
- [ ] `docs/__arch__/ROADMAP.md` — §1 statuses and the S14 status line
- [ ] `docs/__arch__/open-questions.md` — the release decision and what it defers

## Completion

- [ ] Merge to `main` fast-forward, push
- [ ] Build the installer from `main`, verify the checksum file
- [ ] Hand the `.exe` to the owner
- [ ] Final report, including everything not done

## Explicitly out of scope for this release

Named here so the report cannot quietly drop them:

- **Code signing and notarisation.** Needs a certificate the owner must buy; without it
  SmartScreen keeps warning about an unknown publisher. This is S14's remaining half.
- **macOS and Linux installers.** The code runs on all three; only Windows has a bundle.
- **Auto-update** — Q1, an owner decision, still open.
- **S13's API path** — preserved in the excluded `codepack-ai-api`, no UI.
- **Q19 (Mermaid rendering), Q20 (file:line links)** — each needs a new dependency or new
  work in `codepack-diff`; both are owner decisions.
- **Q43** — the residual TOCTOU window in the copy guard, awaiting a `libc` decision.
