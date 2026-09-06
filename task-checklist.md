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

- [+] `tauri.conf.json`: bundle targets for Linux (`deb`, `rpm`, `appimage`) beside `nsis`
- [+] `bundle.linux`: per-distro runtime dependencies, desktop entry metadata
- [+] Icons Linux themes actually ask for — nothing to do: `icon.png` is 512x512 and
      `128x128@2x.png` is 256x256, both already listed. The audit was wrong about this
- [+] `xtask package` stops hardcoding `bundle/nsis`; reports every artifact produced
- [+] `build-installer` script and `doctor` stop calling packaging Windows-only
- [+] CI proves it: a packaging job on `ubuntu-latest` that uploads the artifacts

## 2. Unix permissions

- [+] The copy step preserves the executable bit
- [+] The ZIP writers record Unix modes rather than defaulting every entry to 0644
- [+] Restore applies the recorded mode
- [+] Tests under `#[cfg(unix)]` for each, running on the macOS and Ubuntu legs

## 3. The database moves to `$XDG_DATA_HOME`

- [+] `AppPaths` grows a data directory; the database and history live there on Linux
- [+] Existing installations migrate rather than losing their history
- [+] Windows and macOS layouts unchanged
- [+] Tests for the layout and for the migration

## 4. deb and rpm as real packages

**Not started.** The owner stopped the run after item 3 to consolidate.

- [-] The CLI ships in the package, not only the desktop binary
- [-] Shell completions and a man page where a distro expects them
- [~] Dependencies for Debian/Ubuntu are declared and read back out of the built `.deb`
      by CI; the Fedora names are declared but nothing has installed an `.rpm` yet —
      that is item 5's job

## 5. Proof that installation works

**Not started.** What exists today proves the packages *build* and declare the right
things; nothing has yet installed one and run it.

- [-] A CI job that installs the built package in a clean container and runs an export
- [-] `ubuntu:24.04`, `debian:12`, `fedora:41`

## 6. The small Linux differences

**Mostly not started.**

- [-] inotify watch-descriptor exhaustion reports what to do about it
- [+] `xdg-utils` declared as a dependency (done as part of item 1, and CI reads it back
      out of the built package)
- [-] Font stack names Linux fonts before the generic fallback
- [-] Symlinks excluded from an export are counted where a user can see it

## 7. Backslash-separated paths in artifacts (owner decision inside)

**Not started**, and it is the one item that cannot be finished without a decision: a
filename containing a backslash is legal on Linux, and `display_backslash` turns it into
a path separator, so the file is addressed wrongly. Fixing it changes the artifact
contract (I5) and needs a `schema_version` bump.

- [-] Establish exactly what breaks on Linux, with a test that fails first
- [-] Decide the fix with the owner

## Completion

- [+] Full gate green; CI green on all three runners and on the packaging job
- [-] Documentation not updated: README still says the Linux bundles "are still to come",
      and `overview.md`, `ROADMAP.md` and the decisions log say nothing about the XDG move
      or the permission work. This is real debt and it is the first thing to do next
- [+] Final report, naming everything not done and everything unverifiable from here

## What was verified, and where

Nothing Linux-specific can be executed on this machine. So, explicitly:

| Claim | Proven by |
|---|---|
| The Linux packages build | CI `package (ubuntu-latest)` |
| The `.deb` declares its webview, GTK and `xdg-utils` dependencies | CI reads them back out of the built package |
| The `.deb` installs a desktop entry and 128px/512px icons | the same |
| Permissions survive copy → archive → extract | `#[cfg(unix)]` tests on the macOS and Ubuntu gate legs |
| setuid is never restored from an archive | the same |
| The XDG layout and the migration | tests that force the split layout, so they run everywhere |
| **That an installed package actually runs** | **nothing yet — item 5** |
