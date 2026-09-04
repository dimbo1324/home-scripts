//! `codepack init --hook` — installing the pre-commit hook into someone else's project.
//!
//! ## Why this is a command and not a documented snippet
//!
//! `scan --staged` has existed since the CLI shipped, and so has the exit-code contract
//! it is built on. What was missing was the last step: a person had to know that hooks
//! live in `.git/hooks`, that `core.hooksPath` can move them somewhere else, that the
//! file needs an executable bit on Unix, and that git runs it through `sh` even on
//! Windows. Each of those is a chance to end up with a hook that never runs — and a
//! security gate that never runs looks exactly like a security gate that always passes.
//!
//! ## `core.hooksPath`
//!
//! Honoured, because a project that has set it has already decided where its hooks live,
//! and writing to `.git/hooks` anyway would produce a file git never executes. Note the
//! consequence when that directory is tracked in the repository (this repository does
//! exactly that): the hook is then committed, and a colleague who has never installed
//! codepack will run it. That is why a missing binary is not treated as a failure —
//! see [`HOOK_SCRIPT`].
//!
//! ## Refusing to overwrite
//!
//! An existing hook this command did not write is left alone unless `--force` is given.
//! People put real work in these files; silently replacing one would be the most
//! destructive thing this binary does, and it would do it to a file outside the export
//! path entirely.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::cli::InitArgs;
use crate::commands;
use crate::error::{CliError, Result};
use crate::exit::Outcome;
use crate::output::{self, Format};

/// Identifies a hook this command wrote. Kept on its own line and never reworded once
/// released: it is how a later `init --hook` tells "mine, safe to update" from
/// "somebody else's, do not touch".
const HOOK_MARKER: &str = "# codepack-managed-hook";

/// The hook itself.
///
/// POSIX `sh`, because that is what git runs on every platform including Windows, where
/// Git for Windows ships its own shell.
///
/// **A missing `codepack` binary does not block the commit.** The hook can be committed
/// (via a tracked `core.hooksPath`) and then runs for colleagues who have never
/// installed the tool; failing their commits over a tool they did not choose would get
/// the hook deleted, which protects nobody. It says so loudly instead, on stderr, every
/// single time — the failure mode this file has to avoid is the *quiet* one.
/// The strict counterpart, for a team that would rather stop than proceed unchecked.
///
/// Same hook, one different answer to one question: a missing binary fails the commit
/// instead of warning past it (Q35). Both defaults are defensible and neither is right
/// for everyone — a shared repository where the tool is part of the setup wants this
/// one, and an open-source project whose contributors never chose codepack does not.
/// The choice is the installer's, made once, and visible in the hook's own text.
const HOOK_SCRIPT_STRICT: &str = r#"#!/bin/sh
# codepack-managed-hook
#
# Blocks a commit that would add a critical secret, reading the staged content itself
# rather than the working tree. Written by `codepack init --hook --strict`; safe to
# delete.
#
# Strict: if codepack is missing, the commit is refused rather than let through
# unchecked. Reinstall without --strict to warn and continue instead.
if ! command -v codepack >/dev/null 2>&1; then
    echo "codepack: not installed, so this commit CANNOT be checked for secrets." >&2
    echo "codepack: install it, reinstall the hook without --strict, or delete the hook." >&2
    exit 1
fi

codepack scan --staged
status=$?
if [ $status -ne 0 ]; then
    echo "" >&2
    echo "codepack: commit blocked. Fix the findings above, or accept one by adding its" >&2
    echo "codepack: fingerprint to .codepack-allow, then commit again." >&2
fi
exit $status
"#;

const HOOK_SCRIPT: &str = r#"#!/bin/sh
# codepack-managed-hook
#
# Blocks a commit that would add a critical secret, reading the staged content itself
# rather than the working tree. Written by `codepack init --hook`; safe to delete.
#
# Raise the bar to every high-severity finding with:
#   codepack scan --staged --fail-on high
if ! command -v codepack >/dev/null 2>&1; then
    echo "codepack: not installed, so this commit was NOT checked for secrets." >&2
    echo "codepack: install it, or delete this hook if you do not want the check." >&2
    exit 0
fi

codepack scan --staged
status=$?
if [ $status -ne 0 ]; then
    echo "" >&2
    echo "codepack: commit blocked. Fix the findings above, or accept one by adding its" >&2
    echo "codepack: fingerprint to .codepack-allow, then commit again." >&2
fi
exit $status
"#;

#[derive(Debug, Serialize)]
pub(crate) struct InitReport {
    pub project: String,
    /// Where the hook was written.
    pub hook: String,
    /// `installed`, `updated` (an older codepack hook was replaced), or `replaced`
    /// (`--force` overwrote a hook this command did not write).
    pub action: &'static str,
    /// True when `core.hooksPath` pointed the hook somewhere other than `.git/hooks`.
    pub custom_hooks_path: bool,
    /// True when the installed hook refuses a commit it cannot check.
    pub strict: bool,
}

pub(crate) fn run(args: &InitArgs, format: Format) -> Result<Outcome> {
    if !args.hook {
        return Err(CliError::message(
            "nothing to do: pass --hook to install the pre-commit hook".to_string(),
        ));
    }

    let root = commands::resolve_project_root(&args.project.path)?;
    let report = install_hook_with(&root, args.force, args.strict)?;

    if format.is_json() {
        output::emit_json("init", &report)?;
    } else {
        print_human(&report);
    }
    Ok(Outcome::Success)
}

fn install_hook_with(project_root: &Path, force: bool, strict: bool) -> Result<InitReport> {
    let repository = git2::Repository::discover(project_root).map_err(|error| {
        CliError::message(format!(
            "a pre-commit hook needs a git repository, and {} is not inside one ({})",
            project_root.display(),
            error.message()
        ))
    })?;

    let (hooks_dir, custom_hooks_path) = hooks_directory(&repository);
    std::fs::create_dir_all(&hooks_dir).map_err(|source| CliError::Read {
        path: hooks_dir.clone(),
        source,
    })?;

    let hook = hooks_dir.join("pre-commit");
    let action = match std::fs::read_to_string(&hook) {
        Ok(existing) if existing.contains(HOOK_MARKER) => "updated",
        Ok(_) if force => "replaced",
        Ok(_) => {
            return Err(CliError::message(format!(
                "{} already exists and was not written by codepack. Re-run with --force \
                 to replace it, or add `codepack scan --staged` to it yourself.",
                hook.display()
            )));
        }
        Err(_) => "installed",
    };

    let script = if strict {
        HOOK_SCRIPT_STRICT
    } else {
        HOOK_SCRIPT
    };
    std::fs::write(&hook, script).map_err(|source| CliError::Read {
        path: hook.clone(),
        source,
    })?;
    make_executable(&hook)?;

    Ok(InitReport {
        project: project_root.display().to_string(),
        hook: hook.display().to_string(),
        action,
        strict,
        custom_hooks_path,
    })
}

/// Where this repository's hooks actually live.
///
/// A relative `core.hooksPath` is resolved against the working directory, which is what
/// git does; a bare repository has no working directory, so it falls back to the git
/// directory itself.
fn hooks_directory(repository: &git2::Repository) -> (PathBuf, bool) {
    let configured = repository
        .config()
        .ok()
        .and_then(|config| config.get_string("core.hooksPath").ok())
        .filter(|value| !value.trim().is_empty());

    match configured {
        Some(value) => {
            let path = PathBuf::from(value);
            if path.is_absolute() {
                return (path, true);
            }
            let base = repository
                .workdir()
                .unwrap_or_else(|| repository.path())
                .to_path_buf();
            (base.join(path), true)
        }
        None => (repository.path().join("hooks"), false),
    }
}

/// Gives the hook the executable bit on Unix. A no-op on Windows, where git decides
/// executability from the shebang rather than from a file mode.
#[cfg(unix)]
fn make_executable(hook: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(hook)
        .map_err(|source| CliError::Read {
            path: hook.to_path_buf(),
            source,
        })?
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(hook, permissions).map_err(|source| CliError::Read {
        path: hook.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn make_executable(_hook: &Path) -> Result<()> {
    Ok(())
}

fn print_human(report: &InitReport) {
    let what = match report.action {
        "updated" => "Updated the pre-commit hook",
        "replaced" => "Replaced the existing pre-commit hook",
        _ => "Installed the pre-commit hook",
    };
    output::line(format!("{what}: {}", report.hook));
    if report.custom_hooks_path {
        output::line("This repository sets core.hooksPath, so the hook went there.");
    }
    output::line("");
    output::line("Every commit now runs: codepack scan --staged");
    if report.strict {
        output::line("A commit is refused when codepack is not installed (--strict).");
    }
    output::line("Findings you have accepted go in .codepack-allow beside the project.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use git2::Repository;

    /// Repositories are built through `git2`, never by shelling out — the domain rules
    /// forbid a test that needs a `git` binary installed.
    fn repository(root: &Path) -> Repository {
        Repository::init(root).unwrap()
    }

    #[test]
    fn a_fresh_repository_gets_the_hook_in_the_git_directory() {
        let dir = tempfile::tempdir().unwrap();
        repository(dir.path());

        let report = install_hook_with(dir.path(), false, false).unwrap();

        assert_eq!(report.action, "installed");
        assert!(!report.custom_hooks_path);
        let body = std::fs::read_to_string(&report.hook).unwrap();
        assert!(body.contains("codepack scan --staged"));
        assert!(body.contains(HOOK_MARKER));
    }

    #[test]
    fn installing_twice_updates_our_own_hook_without_needing_force() {
        let dir = tempfile::tempdir().unwrap();
        repository(dir.path());

        install_hook_with(dir.path(), false, false).unwrap();
        let report = install_hook_with(dir.path(), false, false).unwrap();
        assert_eq!(report.action, "updated");
    }

    #[test]
    fn a_foreign_hook_is_refused_rather_than_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let repo = repository(dir.path());
        let hooks = repo.path().join("hooks");
        std::fs::create_dir_all(&hooks).unwrap();
        std::fs::write(hooks.join("pre-commit"), "#!/bin/sh\nmake lint\n").unwrap();

        let error = install_hook_with(dir.path(), false, false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("--force"), "{error}");

        let survived = std::fs::read_to_string(hooks.join("pre-commit")).unwrap();
        assert!(
            survived.contains("make lint"),
            "someone else's hook was destroyed"
        );
    }

    #[test]
    fn force_replaces_a_foreign_hook() {
        let dir = tempfile::tempdir().unwrap();
        let repo = repository(dir.path());
        let hooks = repo.path().join("hooks");
        std::fs::create_dir_all(&hooks).unwrap();
        std::fs::write(hooks.join("pre-commit"), "#!/bin/sh\nmake lint\n").unwrap();

        let report = install_hook_with(dir.path(), true, false).unwrap();
        assert_eq!(report.action, "replaced");
        assert!(
            std::fs::read_to_string(&report.hook)
                .unwrap()
                .contains(HOOK_MARKER)
        );
    }

    #[test]
    fn a_configured_hooks_path_is_honoured() {
        // Writing to `.git/hooks` when git has been told to look elsewhere produces a
        // file that never runs — a gate that silently does nothing.
        let dir = tempfile::tempdir().unwrap();
        let repo = repository(dir.path());
        repo.config()
            .unwrap()
            .set_str("core.hooksPath", ".githooks")
            .unwrap();

        let report = install_hook_with(dir.path(), false, false).unwrap();

        assert!(report.custom_hooks_path);
        // Canonicalised on both sides, and never compared as text. `git2` reports the
        // working directory in its own spelling — long form, forward slashes — while
        // `tempfile` hands back whatever `TEMP` holds, which on a GitHub Windows runner
        // is the 8.3 short form (`RUNNER~1` against `runneradmin`). Two spellings of one
        // path are equal as paths and unequal as strings, and this project has already
        // lost a CI run to exactly that (`explain`, 2026-07-30).
        let written = std::fs::canonicalize(&report.hook).unwrap();
        let expected =
            std::fs::canonicalize(dir.path().join(".githooks").join("pre-commit")).unwrap();
        assert_eq!(written, expected);
    }

    #[test]
    fn a_directory_outside_any_repository_is_an_error_that_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let error = install_hook_with(dir.path(), false, false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("git repository"), "{error}");
    }

    #[test]
    fn the_hook_does_not_block_a_commit_when_codepack_is_not_installed() {
        // The hook can be committed through a tracked `core.hooksPath` and then runs for
        // people who never installed the tool. It must say so rather than fail them.
        assert!(HOOK_SCRIPT.contains("command -v codepack"));
        assert!(HOOK_SCRIPT.contains("exit 0"));
        assert!(HOOK_SCRIPT.contains("NOT checked"));
    }
}
