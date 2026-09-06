# Task Checklist

**Task:** Make codepack install and behave on Linux the way it does on Windows — the
seven items of the 2026-09-06 audit, in order.

**Date:** 2026-09-06
**Branch:** feat/linux-distribution

Owner instruction, 2026-09-06: work through audit items 1–7 in order, unhurried, with
intermediate commits.

## The constraint that shapes this work

**There is no Linux machine here.** Docker Desktop's daemon is not running and there is
no WSL distribution; the host is Windows 11. Every Linux claim in this task is therefore
verified on CI or not verified at all, and the checklist says which. Where a step cannot
be proven, it is marked `-` with the reason, never `+` on the strength of the code
looking right.

## 1. AppImage, and `cargo xtask package` on Linux

- [ ] `tauri.conf.json`: bundle targets for Linux (`deb`, `rpm`, `appimage`) beside `nsis`
- [ ] `bundle.linux`: per-distro runtime dependencies, desktop entry metadata
- [ ] Icons Linux themes actually ask for (256, 512)
- [ ] `xtask package` stops hardcoding `bundle/nsis`; reports every artifact produced
- [ ] `build-installer` script and `doctor` stop calling packaging Windows-only
- [ ] CI proves it: a packaging job on `ubuntu-latest` that uploads the artifacts

## 2. Unix permissions

- [ ] The copy step preserves the executable bit
- [ ] The ZIP writers record Unix modes rather than defaulting every entry to 0644
- [ ] Restore applies the recorded mode
- [ ] Tests under `#[cfg(unix)]` for each, running on the macOS and Ubuntu legs

## 3. The database moves to `$XDG_DATA_HOME`

- [ ] `AppPaths` grows a data directory; the database and history live there on Linux
- [ ] Existing installations migrate rather than losing their history
- [ ] Windows and macOS layouts unchanged
- [ ] Tests for the layout and for the migration

## 4. deb and rpm as real packages

- [ ] The CLI ships in the package, not only the desktop binary
- [ ] Shell completions and a man page where a distro expects them
- [ ] Dependencies correct for Debian/Ubuntu and for Fedora

## 5. Proof that installation works

- [ ] A CI job that installs the built package in a clean container and runs an export
- [ ] `ubuntu:24.04`, `debian:12`, `fedora:41`

## 6. The small Linux differences

- [ ] inotify watch-descriptor exhaustion reports what to do about it
- [ ] `xdg-utils` declared as a dependency
- [ ] Font stack names Linux fonts before the generic fallback
- [ ] Symlinks excluded from an export are counted where a user can see it

## 7. Backslash-separated paths in artifacts (owner decision inside)

- [ ] Establish exactly what breaks on Linux, with a test that fails first
- [ ] Decide the fix with the owner: it changes an artifact contract (I5) and needs a
      `schema_version` bump

## Completion

- [ ] Full gate green; CI green on all three runners
- [ ] Documentation updated: README install per distro, overview, ROADMAP, decisions log
- [ ] Final report, naming everything not done and everything unverifiable from here
