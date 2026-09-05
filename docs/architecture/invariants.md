# Invariants: what must never break

> This registry is binding. Breaking an invariant is a defect, not a trade-off.
> Only the owner can change one, and that decision is recorded — with its date and
> reasoning — in the project's decision log.

## I1. Privacy is absolute

All analysis runs locally. No crate reaches the network. The single exception is the
stage S13 integration, and only on an explicit user action. Adding an HTTP client to any
other crate is a violation.

**Why.** The product handles other people's source code and secrets. Trusting it rests
entirely on the data not going anywhere.

**How it is enforced (since 2026-07-27).** This stopped being text and became a
mechanism: the `network isolation` step of `cargo xtask gate` reads every crate manifest
and fails if an HTTP client is declared anywhere but `codepack-ai`. The reason is the
shape of the failure — a crate that gains an HTTP client behaves identically until the
day it makes a request, so "someone will catch it in review" does not work here. Same
approach as the webview's isolation: not a convention, a mechanism
(`crates/xtask/src/network_isolation.rs`).

## I2. The source is immutable

An export never writes, renames or deletes anything inside the source project folder.
All work happens on a copy in the staging directory.

**Why.** People run this against their working project. Corrupting the source is
unacceptable under any circumstances, cancellation and failure included.

**How it is enforced (since 2026-09-06).** In `codepack_engine::run_export`, before the
pipeline computes a single path — the one layer both front ends go through. An output
directory that resolves inside the source root fails with
`EngineError::OutputInsideSource`.

It used to be checked only in `codepack-cli`, which left the desktop shell — which calls
the engine directly — free to stage a bundle inside the user's own working tree, pick it
up as a source on the next run, and, with `keep_staging_folder = false`, recursively
delete a directory inside their project.

The comparison runs on a *prospective* path
(`codepack_core::validate_destination_outside`): the destination is resolved through its
longest existing ancestor rather than created first. A check that runs `create_dir_all`
before refusing leaves a stray directory inside the source tree, which is this invariant
broken by the code meant to hold it — the CLI did exactly that until this date. The same
function now serves all three callers (engine, CLI `--out`, `codepack-sanitize`), where
the rule was previously written three times and behaved differently in each.

## I3. A secret never leaves the redactor

The value of a detected secret never reaches a log, a report, the history, the database,
an error message or the clipboard in the clear. Redaction is applied before anything is
written.

**Why.** A tool that logs the secrets it finds becomes a source of leaks itself.

## I4. Byte figures are preserved

Size in bytes is reported everywhere the previous version reported it. Tokens are an
additional metric alongside, never a replacement.

**Why.** A direct owner decision (2026-07-22): bytes are what people read, and what
tells you the real volume of data.

## I5. Artifact formats stay backward compatible

Report file names and the structure of `manifest.json`, `PROJECT_PROFILE.json`,
`06_security_scan.json`, SARIF 2.1.0 and `ARCHIVE_SET_MANIFEST.json` are a contract.
Changing one requires bumping `schema_version` and recording the decision.

**Why.** These artifacts are consumed by other tools and by people; changing a format
quietly breaks someone else's process.

## I6. Cancelling never corrupts state

Every long operation can be interrupted at any moment. A cancelled or failed run does
not overwrite the snapshot baseline and leaves behind no partial data presented as
complete.

**Why.** Otherwise the next differential export produces a wrong answer.

## I7. Walking and extraction are safe

Symlinks are never dereferenced while walking a tree. When extracting an archive, each
member's target path is validated before anything is written (path-traversal safety).

**Why.** Otherwise a specially crafted project or archive escapes the destination
directory.

## I8. The core does not depend on the interface

No `codepack-*` crate depends on Tauri or on the frontend; the whole core builds and
tests headless. Dependencies point strictly downward, and cycles are forbidden.

**Why.** The CLI, automation and testability all rest on this — and mixing the layers is
what made the previous version Windows-only.

## I9. Detector quality thresholds are never lowered

The precision/recall thresholds of `codepack-security`'s corpus test are not lowered to
make a build green. A drop in recall is a defect in the detector, not a reason to edit
the test.

**Why.** Secret detection is the product's central value; degrading it quietly is more
dangerous than a red build.
