//! Narrowing a git operation to the project inside its repository.
//!
//! `Repository::discover` walks upward, so in a monorepo the repository root is usually an
//! ancestor of the project being scanned. Without a pathspec, `--staged` and `--history`
//! would both report every path in the whole repository while the report still named the
//! project the user asked about.
//!
//! One copy. `staged.rs` and `history_scan.rs` each carried a byte-identical version, the
//! second with a comment explaining that the duplication was deliberate "because the two
//! modules answer different questions" — a justification that existed only in prose, since
//! the code was the same to the character (audit No. 23). If the two ever genuinely need
//! to differ, that becomes a parameter here, where both callers can see it.

use std::path::Path;

use git2::Repository;

/// `project_root` expressed relative to the repository's working directory, in the
/// forward-slash form git pathspecs use.
///
/// Returns `None` when the project *is* the repository root (no narrowing needed), when
/// the repository has no working directory (bare), or when the two cannot be related — in
/// which case scanning the whole repository is the safe direction to fail.
pub(crate) fn scope_pathspec(repository: &Repository, project_root: &Path) -> Option<String> {
    let workdir = repository.workdir()?;
    // Both sides are canonicalised so that a path reached through a symlinked or shortened
    // parent still matches the workdir prefix. On failure, fall back to the path as given
    // rather than silently widening the scope to the whole repository.
    let workdir = std::fs::canonicalize(workdir).unwrap_or_else(|_| workdir.to_path_buf());
    let project =
        std::fs::canonicalize(project_root).unwrap_or_else(|_| project_root.to_path_buf());

    let relative = project.strip_prefix(&workdir).ok()?;
    if relative.as_os_str().is_empty() {
        return None;
    }

    let mut pathspec = String::new();
    for component in relative.components() {
        if !pathspec.is_empty() {
            pathspec.push('/');
        }
        pathspec.push_str(&component.as_os_str().to_string_lossy());
    }
    Some(pathspec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_project_that_is_the_repository_root_needs_no_narrowing() {
        let dir = tempfile::tempdir().unwrap();
        let repository = Repository::init(dir.path()).unwrap();
        assert_eq!(scope_pathspec(&repository, dir.path()), None);
    }

    #[test]
    fn a_nested_project_is_expressed_with_forward_slashes() {
        let dir = tempfile::tempdir().unwrap();
        let repository = Repository::init(dir.path()).unwrap();
        let nested = dir.path().join("packages").join("api");
        std::fs::create_dir_all(&nested).unwrap();

        // Forward slashes on every platform: this is a git pathspec, not a filesystem
        // path, and git's separator does not vary by host.
        assert_eq!(
            scope_pathspec(&repository, &nested),
            Some("packages/api".to_string())
        );
    }

    /// A path that cannot be related to the working directory widens the scope rather
    /// than narrowing it wrongly — reporting too much never hides a secret, and reporting
    /// too little would.
    #[test]
    fn an_unrelated_path_yields_no_pathspec() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let repository = Repository::init(dir.path()).unwrap();
        assert_eq!(scope_pathspec(&repository, elsewhere.path()), None);
    }
}
