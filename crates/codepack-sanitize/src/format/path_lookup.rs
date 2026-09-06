//! Manual `PATH` binary resolution.
//!
//! Not the `which` crate: this needs exactly one thing — "does this bare name resolve to
//! a runnable file on `PATH`" — and a dependency that also handles custom search paths,
//! cross-platform quirks and `PATHEXT` edge cases is more than one lookup needs
//! (`.ai/universal/05-security-and-secrets.md`). `std::process::Command::new` does not
//! answer the question up front; it only fails, per candidate, at spawn time.
//!
//! The two platforms search differently and both are implemented here. Windows appends
//! every `PATHEXT` extension, without which `rustfmt` never resolves at all. Unix looks
//! for the name itself and asks whether anyone may execute it — a `PATH` directory holds
//! plenty of files that are not programs. Getting this wrong is quiet: the caller reads a
//! `None` as "no formatter installed" and writes unformatted output, so a Unix-blind
//! lookup would have disabled this whole feature on macOS and Linux without one error
//! message (found on both Unix CI runners, 2026-09-06).

use std::path::{Path, PathBuf};

/// Finds `binary_name` on `PATH`, or `None` if nothing runnable answers to it.
pub(super) fn find_on_path(binary_name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        for name in candidate_names(binary_name) {
            let candidate = dir.join(name);
            if is_runnable(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

/// The file names one `PATH` directory is searched for, in order.
///
/// On Unix a command is its own file name and nothing else. On Windows every `PATHEXT`
/// entry is appended instead, exactly as `CreateProcess`'s own search does — unless the
/// name already carries an extension, in which case it is taken as written.
fn candidate_names(binary_name: &str) -> Vec<String> {
    if !cfg!(windows) || Path::new(binary_name).extension().is_some() {
        return vec![binary_name.to_string()];
    }
    let pathext = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
    pathext
        .split(';')
        .filter(|ext| !ext.is_empty())
        .map(|ext| format!("{binary_name}{ext}"))
        .collect()
}

/// On Unix the executable bit is the question, since `PATH` directories hold data files
/// too and `is_file` alone would hand back a candidate that cannot be spawned.
#[cfg(unix)]
fn is_runnable(candidate: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    candidate
        .metadata()
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

/// Windows has no executable bit; `PATHEXT` already decided what counts as runnable.
#[cfg(not(unix))]
fn is_runnable(candidate: &Path) -> bool {
    candidate.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_binary_that_cannot_exist_is_not_found() {
        assert!(find_on_path("codepack-sanitize-definitely-not-a-real-tool-9f3b").is_none());
    }

    #[test]
    fn a_binary_every_supported_platform_has_resolves() {
        // The cheapest possible proof that the search walks real directories rather than
        // trivially returning `None` for everything. One name per platform, each
        // guaranteed present: `cmd.exe` ships with every Windows install, and `sh` is
        // POSIX. Naming only the Windows one is how this test passed on Windows while
        // the lookup it guards was broken on both Unix platforms.
        let always_present = if cfg!(windows) { "cmd" } else { "sh" };
        assert!(
            find_on_path(always_present).is_some(),
            "{always_present} should resolve on PATH"
        );
    }
}
