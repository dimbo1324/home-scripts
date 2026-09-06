//! The pnpm half of the toolchain: Prettier formatting, and the frontend gate checks.
//!
//! Everything here is **optional on a developer machine and mandatory in CI**. A fresh
//! clone that has never run `pnpm install` must still be able to run `cargo xtask gate`
//! and get a meaningful answer about the Rust side, because most work in this repository
//! never touches the frontend — so a missing `node_modules` prints a notice and skips.
//!
//! In CI the same skip would be a silent hole: the checks would exist, report "skipped",
//! and exit 0, leaving unformatted or type-broken frontend code to pass. So when `CI` is
//! set, a missing toolchain is a failure instead — see [`require_or_skip`]. That is not
//! belt-and-braces with the workflow's `pnpm install` step, it is what makes deleting that
//! step impossible to do quietly.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use std::process::Command;

/// pnpm ships as `pnpm.CMD` on Windows, and `std::process::Command` only ever appends
/// `.exe` when resolving a bare name — so naming it `pnpm` fails with "program not found"
/// on the one platform this project currently targets.
pub(crate) const PNPM: &str = if cfg!(windows) { "pnpm.cmd" } else { "pnpm" };

/// Prettier lives in the workspace root's `node_modules`; `svelte-check` and ESLint live
/// in the UI package's. One `pnpm install` produces both, so both are checked — a partial
/// install should skip loudly rather than fail halfway through the gate.
pub(crate) fn dependencies_installed(root: &Path) -> bool {
    root.join("node_modules").is_dir() && root.join("apps/desktop/ui/node_modules").is_dir()
}

pub(crate) fn skip_notice() {
    println!(
        "  skipped: apps/desktop/ui/node_modules is missing.\n  \
         Run `pnpm install` to include the frontend in this command."
    );
}

/// Decides whether the frontend steps run, skip, or fail.
///
/// Returns `Ok(true)` to run them, `Ok(false)` to skip on a developer machine, and `Err`
/// in CI — where an absent toolchain means the workflow lost its `pnpm install` step and
/// the checks would otherwise pass by not happening.
pub(crate) fn require_or_skip(root: &Path) -> Result<bool, String> {
    if dependencies_installed(root) {
        return Ok(true);
    }
    if std::env::var_os("CI").is_some() {
        return Err(
            "frontend dependencies are missing, and CI is set: the workflow must run \
             `pnpm install` before the gate, or these checks would silently skip"
                .to_string(),
        );
    }
    skip_notice();
    Ok(false)
}

fn pnpm(root: &Path, label: &str, args: &[&str]) -> Result<(), String> {
    println!("$ {PNPM} {}", args.join(" "));
    let status = Command::new(PNPM)
        .args(args)
        .current_dir(root)
        .status()
        .map_err(|error| format!("{label}: failed to launch `{PNPM}`: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(label.to_string())
    }
}

/// Rewrites frontend and configuration files in place. Paired with `cargo fmt --all` by
/// `cargo xtask fmt`, so one command covers both toolchains.
pub(crate) fn format_write(root: &Path) -> Result<(), String> {
    pnpm(root, "prettier", &["run", "format:write"])
}

/// The frontend's share of the gate, in cheapest-first order so an obvious formatting
/// slip does not wait behind a full type-check.
pub(crate) fn gate_checks(root: &Path) -> Result<(), String> {
    pnpm(root, "prettier --check", &["run", "format"])?;
    pnpm(
        root,
        "svelte-check",
        &["--filter", "@codepack/ui", "typecheck"],
    )?;
    pnpm(root, "eslint", &["--filter", "@codepack/ui", "lint"])
}

/// Builds the Windows installer: frontend bundle, release binary, then the NSIS package.
///
/// Runs from `apps/desktop`, and that detail is the whole trick. The Tauri CLI locates a
/// project by looking for `tauri.conf.json` in a *subfolder* of the working directory, and
/// this repository keeps the shell in `apps/desktop/src-tauri` beside the frontend in
/// `apps/desktop/ui`. Invoked from `ui`, the config is a sibling rather than a child and
/// the CLI aborts with "couldn't recognize the current folder as a Tauri project" — which
/// is exactly what the previously documented `--filter @codepack/ui exec tauri dev`
/// command did. `apps/desktop` is the directory that contains both halves.
///
/// The CLI is a pnpm dev dependency rather than a global install, so the version that
/// builds a release is pinned by `pnpm-lock.yaml` like everything else. `tauri build` runs
/// `beforeBuildCommand` itself, so the frontend is not built twice.
pub(crate) fn package(root: &Path) -> Result<(), String> {
    if !dependencies_installed(root) {
        return Err("packaging needs the frontend toolchain: run `pnpm install` first".to_string());
    }
    pnpm(
        &root.join("apps/desktop"),
        "tauri build",
        &["exec", "tauri", "build"],
    )?;

    report_bundles(&root.join("target/release/bundle"))
}

/// Lists what the bundler actually produced, and checksums each format's directory.
///
/// One directory per bundle format, named by the bundler: `nsis` on Windows, and `deb`,
/// `rpm` and `appimage` on Linux. Naming `nsis` directly — which this did until
/// 2026-09-06 — meant that on Linux the build would succeed and the command would then
/// fail with "target/release/bundle/nsis is unreadable", reporting a missing installer
/// for a build that had just produced three.
///
/// `SHA256SUMS.txt` stays *inside* each format's directory rather than as one file above
/// them, because it holds bare names: `sha256sum -c` is run from the directory the file
/// sits in, and keeping that property is worth more than having a single file.
fn report_bundles(bundle_root: &Path) -> Result<(), String> {
    let mut formats: Vec<PathBuf> = std::fs::read_dir(bundle_root)
        .map_err(|error| {
            format!(
                "tauri build succeeded but {} is unreadable: {error}",
                bundle_root.display()
            )
        })?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    formats.sort();

    let mut produced = 0usize;
    for format in &formats {
        let mut artifacts: Vec<PathBuf> = std::fs::read_dir(format)
            .map_err(|error| format!("cannot list {}: {error}", format.display()))?
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.is_file() && path.file_name() != Some(CHECKSUM_FILE.as_ref()))
            .collect();
        artifacts.sort();
        if artifacts.is_empty() {
            continue;
        }

        println!("\n{}:", format.display());
        for artifact in &artifacts {
            let size = artifact.metadata().map(|meta| meta.len()).unwrap_or(0);
            println!(
                "  {} ({:.1} MiB)",
                artifact.file_name().unwrap_or_default().to_string_lossy(),
                size as f64 / (1024.0 * 1024.0)
            );
            produced += 1;
        }
        let sums = write_checksums(format)?;
        println!("  checksums: {}", sums.display());
    }

    // A build that reports success and leaves nothing behind is the case worth naming:
    // it means the bundler wrote somewhere this does not know about, and silence here
    // would read as "packaged fine".
    if produced == 0 {
        return Err(format!(
            "tauri build succeeded but produced no artifact under {}",
            bundle_root.display()
        ));
    }
    Ok(())
}

const CHECKSUM_FILE: &str = "SHA256SUMS.txt";

/// Writes `SHA256SUMS.txt` beside the installers, in the format `sha256sum -c` reads:
/// the hex digest, two spaces, the file name.
///
/// This is the half of stage S14's "signed, checksummed release" that needs nothing but
/// arithmetic. It does not replace code signing: a checksum proves a download arrived
/// intact, not that it came from anyone in particular, and only a certificate can say
/// the second thing.
///
/// Names, never paths — the file is published next to the installers and verified from
/// the directory it sits in. Entries are sorted, so the same set of files always
/// produces the same file.
fn write_checksums(bundle: &Path) -> Result<PathBuf, String> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(bundle)
        .map_err(|error| format!("cannot list {}: {error}", bundle.display()))?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && path.file_name() != Some(CHECKSUM_FILE.as_ref()))
        .collect();
    entries.sort();

    let mut lines: Vec<String> = Vec::new();
    for path in entries {
        let bytes = std::fs::read(&path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        let digest = Sha256::digest(&bytes);
        let mut hex = String::with_capacity(digest.len() * 2);
        for byte in digest.iter() {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
        }
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        lines.push(format!("{hex}  {name}"));
    }

    let target = bundle.join(CHECKSUM_FILE);
    let mut body = lines.join("\n");
    body.push('\n');
    std::fs::write(&target, body)
        .map_err(|error| format!("cannot write {}: {error}", target.display()))?;
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SHA-256 of the empty input, from the standard's own test vectors. It pins the
    /// digest this file publishes, rather than only pinning it against itself.
    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn checksums_are_written_in_the_format_sha256sum_reads() {
        let bundle = tempfile::tempdir().unwrap();
        std::fs::write(bundle.path().join("codepack_setup.exe"), b"").unwrap();

        let written = write_checksums(bundle.path()).unwrap();
        assert_eq!(written, bundle.path().join(CHECKSUM_FILE));

        let body = std::fs::read_to_string(&written).unwrap();
        assert_eq!(body, format!("{EMPTY_SHA256}  codepack_setup.exe\n"));
    }

    /// Names, never paths: the file is published beside the installers and verified from
    /// the directory it sits in.
    #[test]
    fn entries_carry_the_file_name_alone() {
        let bundle = tempfile::tempdir().unwrap();
        std::fs::write(bundle.path().join("installer.exe"), b"payload").unwrap();

        let body = std::fs::read_to_string(write_checksums(bundle.path()).unwrap()).unwrap();
        assert!(body.ends_with("  installer.exe\n"), "{body}");
        assert!(!body.contains(std::path::MAIN_SEPARATOR), "{body}");
    }

    /// Sorted, so the same set of files always produces the same file.
    #[test]
    fn entries_are_sorted_and_the_output_is_stable() {
        let bundle = tempfile::tempdir().unwrap();
        for name in ["c.exe", "a.exe", "b.exe"] {
            std::fs::write(bundle.path().join(name), name.as_bytes()).unwrap();
        }

        let first = std::fs::read_to_string(write_checksums(bundle.path()).unwrap()).unwrap();
        let names: Vec<&str> = first
            .lines()
            .map(|line| line.split_whitespace().nth(1).unwrap())
            .collect();
        assert_eq!(names, ["a.exe", "b.exe", "c.exe"]);

        // Re-running over the same directory reproduces it exactly, including the fact
        // that the previous SHA256SUMS.txt is not hashed into the new one.
        let second = std::fs::read_to_string(write_checksums(bundle.path()).unwrap()).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn the_checksum_file_never_hashes_itself() {
        let bundle = tempfile::tempdir().unwrap();
        std::fs::write(bundle.path().join("installer.exe"), b"x").unwrap();
        std::fs::write(bundle.path().join(CHECKSUM_FILE), "stale\n").unwrap();

        let body = std::fs::read_to_string(write_checksums(bundle.path()).unwrap()).unwrap();
        assert_eq!(body.lines().count(), 1);
        assert!(!body.contains(CHECKSUM_FILE));
    }

    #[test]
    fn a_directory_is_not_an_artifact() {
        let bundle = tempfile::tempdir().unwrap();
        std::fs::create_dir(bundle.path().join("nested")).unwrap();
        std::fs::write(bundle.path().join("installer.exe"), b"x").unwrap();

        let body = std::fs::read_to_string(write_checksums(bundle.path()).unwrap()).unwrap();
        assert_eq!(body.lines().count(), 1);
        assert!(body.ends_with("  installer.exe\n"));
    }

    #[test]
    fn an_empty_bundle_still_writes_a_file_rather_than_nothing() {
        let bundle = tempfile::tempdir().unwrap();
        let body = std::fs::read_to_string(write_checksums(bundle.path()).unwrap()).unwrap();
        assert_eq!(body, "\n");
    }

    #[test]
    fn a_directory_that_is_not_there_is_an_error_that_names_it() {
        let bundle = tempfile::tempdir().unwrap();
        let missing = bundle.path().join("absent");
        let error = write_checksums(&missing).unwrap_err();
        assert!(error.contains("absent"), "{error}");
    }

    /// The Linux case this function exists for: three formats in one build, each with
    /// its own directory, each checksummed where it sits.
    #[test]
    fn every_bundle_format_is_reported_and_checksummed() {
        let root = tempfile::tempdir().unwrap();
        for (format, artifact) in [
            ("deb", "codepack_2.0.0_amd64.deb"),
            ("rpm", "codepack-2.0.0-1.x86_64.rpm"),
            ("appimage", "codepack_2.0.0_amd64.AppImage"),
        ] {
            let dir = root.path().join(format);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(artifact), format.as_bytes()).unwrap();
        }

        report_bundles(root.path()).expect("three formats is a successful package run");

        for (format, artifact) in [
            ("deb", "codepack_2.0.0_amd64.deb"),
            ("rpm", "codepack-2.0.0-1.x86_64.rpm"),
            ("appimage", "codepack_2.0.0_amd64.AppImage"),
        ] {
            let sums = root.path().join(format).join(CHECKSUM_FILE);
            let body = std::fs::read_to_string(&sums).unwrap();
            assert!(body.trim_end().ends_with(artifact), "{format}: {body:?}");
        }
    }

    /// A bundler that reports success and writes nothing is the failure this must not
    /// paper over — it is what "target/release/bundle/nsis is unreadable" used to be on
    /// Linux, said badly.
    #[test]
    fn a_build_that_left_no_artifact_is_an_error_rather_than_a_quiet_success() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("deb")).unwrap();

        let error = report_bundles(root.path()).unwrap_err();
        assert!(error.contains("no artifact"), "{error}");
    }

    /// And a missing bundle root names itself, since that is the one case where the
    /// build genuinely wrote somewhere unexpected.
    #[test]
    fn a_missing_bundle_root_is_named_in_the_error() {
        let root = tempfile::tempdir().unwrap();
        let error = report_bundles(&root.path().join("bundle")).unwrap_err();
        assert!(error.contains("bundle"), "{error}");
    }
}
