//! `scan --staged` — reading what is about to be committed.
//!
//! ## Why the index, and not the working tree
//!
//! A pre-commit hook exists to answer one question: *is it safe to make this commit?*
//! The commit is built from the git index, not from the files on disk, and the two stop
//! agreeing the moment someone stages a file and then edits it again. Scanning the
//! working tree would therefore answer a subtly different question, and it fails in the
//! dangerous direction: a secret staged and then wiped from the working copy would be
//! committed while the hook reported nothing.
//!
//! So the staged blobs are materialised into a temporary directory and scanned there.
//! That costs a copy of the staged content, which is bounded by what a person is about
//! to commit, and buys an answer about the thing that is actually being committed.
//!
//! ## What counts as staged
//!
//! Entries the index adds or modifies relative to `HEAD`. Deletions are excluded: a path
//! being removed cannot carry a secret into the commit. On a repository with no commits
//! yet, everything in the index is new, and all of it is scanned.
//!
//! Symlink and submodule ("gitlink") entries are skipped rather than materialised —
//! neither has file content to scan, and following a symlink out of the temporary
//! directory is exactly the class of escape invariant I7 exists to forbid.

use std::path::{Path, PathBuf};

use git2::{Delta, DiffOptions, ObjectType, Repository};

use crate::error::{CliError, Result};

/// Staged content, unpacked into a temporary directory that is removed when this is
/// dropped.
#[derive(Debug)]
pub(crate) struct StagedContent {
    directory: tempfile::TempDir,
    relative_files: Vec<PathBuf>,
    /// Staged paths refused for not staying under the temporary root. Reported rather
    /// than silently dropped: a repository whose tree carries such a name is itself
    /// something the user should hear about.
    unsafe_paths: usize,
}

impl StagedContent {
    /// The root the materialised files live under — what `scan_project` should treat as
    /// the project root.
    pub(crate) fn root(&self) -> &Path {
        self.directory.path()
    }

    /// Paths relative to [`Self::root`], in the order git reported them.
    pub(crate) fn relative_files(&self) -> &[PathBuf] {
        &self.relative_files
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.relative_files.is_empty()
    }

    /// Staged entries whose recorded path would not have stayed under the temporary
    /// root, and were therefore not materialised or scanned.
    pub(crate) fn unsafe_paths(&self) -> usize {
        self.unsafe_paths
    }
}

/// Materialises every staged blob under `project_root` into a temporary directory.
///
/// Fails when `project_root` is not inside a git repository: answering "nothing staged"
/// there would be a lie that reads exactly like a clean result.
///
/// **The diff is scoped to `project_root`.** `Repository::discover` walks upward, so in
/// a monorepo the repository root is usually an ancestor of the project being scanned;
/// without a pathspec the diff would return every staged path in the whole repository
/// while the report still named the project the user asked about. That over-reports
/// rather than under-reports, so it never lets a secret through, but it makes the
/// command unusable exactly where it is most wanted — a per-package pre-commit hook in
/// a monorepo — and it makes the `project` field of the JSON report untrue.
pub(crate) fn collect(project_root: &Path) -> Result<StagedContent> {
    let repository = Repository::discover(project_root).map_err(|error| {
        CliError::message(format!(
            "--staged needs a git repository, and {} is not inside one ({})",
            project_root.display(),
            error.message()
        ))
    })?;

    let head_tree = match repository.head() {
        Ok(reference) => Some(
            reference
                .peel_to_tree()
                .map_err(|error| git_error("read HEAD's tree", &error))?,
        ),
        // An unborn HEAD is a repository with no commits yet: every index entry is new.
        Err(_) => None,
    };

    let mut options = DiffOptions::new();
    if let Some(scope) = scope_pathspec(&repository, project_root) {
        options.pathspec(scope);
    }
    let diff = repository
        .diff_tree_to_index(head_tree.as_ref(), None, Some(&mut options))
        .map_err(|error| git_error("compare the index against HEAD", &error))?;

    let directory = tempfile::tempdir().map_err(|source| CliError::Read {
        path: project_root.to_path_buf(),
        source,
    })?;
    let mut relative_files = Vec::new();
    let mut unsafe_paths = 0usize;

    for delta in diff.deltas() {
        // Deleted paths carry nothing into the commit.
        if matches!(delta.status(), Delta::Deleted) {
            continue;
        }
        let entry = delta.new_file();
        let Some(relative) = entry.path() else {
            continue;
        };
        // Blobs only: a symlink has no content worth scanning, and a submodule's
        // content is not part of this commit at all.
        if entry.mode() != git2::FileMode::Blob && entry.mode() != git2::FileMode::BlobExecutable {
            continue;
        }
        let Ok(object) = repository.find_object(entry.id(), Some(ObjectType::Blob)) else {
            continue;
        };
        let Some(blob) = object.as_blob() else {
            continue;
        };

        // The path as git recorded it, in a repository this command is designed to be
        // pointed at without owning: `--staged` runs in a pre-commit hook, and the same
        // materialisation backs a scan of somebody else's checkout. Writing a blob
        // outside the temporary directory is exactly the escape invariant I7 exists to
        // prevent (audit No. 10).
        //
        // Defence in depth here, unlike its twin in `history_scan`: `libgit2`'s own
        // `Index::add` refuses a path containing `..`, so an index this process builds
        // cannot carry one — but an index *file* written by something else and read back
        // is not validated the same way, and this loop should not be the thing that
        // depends on which. No end-to-end fixture covers it: constructing such an index
        // means writing the on-disk index format, checksum included, which needs a SHA-1
        // dependency the project does not have and would not be worth adding for one
        // test. The rule itself is covered in `codepack_core::paths`.
        let Ok(destination) = codepack_core::safe_join(directory.path(), relative) else {
            unsafe_paths += 1;
            continue;
        };
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent).map_err(|source| CliError::Read {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        std::fs::write(&destination, blob.content()).map_err(|source| CliError::Read {
            path: destination.clone(),
            source,
        })?;
        relative_files.push(relative.to_path_buf());
    }

    Ok(StagedContent {
        directory,
        relative_files,
        unsafe_paths,
    })
}

fn git_error(action: &str, error: &git2::Error) -> CliError {
    CliError::message(format!("cannot {action}: {}", error.message()))
}

/// `project_root` expressed relative to the repository's working directory, in the
/// forward-slash form git pathspecs use.
///
/// Returns `None` when the project *is* the repository root (no narrowing needed), when
/// the repository has no working directory (bare), or when the two cannot be related —
/// in which case scanning the whole repository is the safe direction to fail.
fn scope_pathspec(repository: &Repository, project_root: &Path) -> Option<String> {
    let workdir = repository.workdir()?;
    // Both sides are canonicalised so that a path reached through a symlinked or
    // shortened parent still matches the workdir prefix. On failure, fall back to the
    // path as given rather than silently widening the scope to the whole repository.
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
    use git2::{IndexAddOption, Signature};

    /// Repositories are built through `git2`, never by shelling out to a `git` binary —
    /// `.ai/project/12-domain-rules.md` forbids tests that depend on one being installed.
    fn repository_with_commit(root: &Path) -> Repository {
        let repository = Repository::init(root).unwrap();
        std::fs::write(root.join("seed.txt"), "seed\n").unwrap();
        let mut index = repository.index().unwrap();
        index
            .add_all(["seed.txt"], IndexAddOption::DEFAULT, None)
            .unwrap();
        index.write().unwrap();
        let tree_id = index.write_tree().unwrap();
        let tree = repository.find_tree(tree_id).unwrap();
        let signature = Signature::now("Test", "test@example.local").unwrap();
        repository
            .commit(Some("HEAD"), &signature, &signature, "seed", &tree, &[])
            .unwrap();
        drop(tree);
        repository
    }

    fn stage(repository: &Repository, relative: &str) {
        let mut index = repository.index().unwrap();
        index
            .add_all([relative], IndexAddOption::DEFAULT, None)
            .unwrap();
        index.write().unwrap();
    }

    #[test]
    fn not_a_repository_is_an_error_not_an_empty_result() {
        let dir = tempfile::tempdir().unwrap();
        let error = collect(dir.path()).unwrap_err();
        assert!(
            error.to_string().contains("git repository"),
            "unhelpful message: {error}"
        );
    }

    #[test]
    fn nothing_staged_yields_an_empty_set() {
        let dir = tempfile::tempdir().unwrap();
        repository_with_commit(dir.path());
        let staged = collect(dir.path()).unwrap();
        assert!(staged.is_empty());
    }

    #[test]
    fn a_staged_file_is_materialised_with_its_staged_content() {
        let dir = tempfile::tempdir().unwrap();
        let repository = repository_with_commit(dir.path());

        std::fs::write(dir.path().join("added.txt"), "staged content\n").unwrap();
        stage(&repository, "added.txt");

        let staged = collect(dir.path()).unwrap();
        assert_eq!(staged.relative_files(), [PathBuf::from("added.txt")]);
        let materialised = std::fs::read_to_string(staged.root().join("added.txt")).unwrap();
        assert_eq!(materialised, "staged content\n");
    }

    #[test]
    fn an_unstaged_working_tree_file_is_not_collected() {
        let dir = tempfile::tempdir().unwrap();
        repository_with_commit(dir.path());
        std::fs::write(dir.path().join("untracked.txt"), "never staged\n").unwrap();

        let staged = collect(dir.path()).unwrap();
        assert!(
            staged.is_empty(),
            "an unstaged file must not reach the scanner"
        );
    }

    #[test]
    fn editing_a_file_after_staging_does_not_change_what_is_scanned() {
        // The whole reason this module reads the index rather than the working tree.
        let dir = tempfile::tempdir().unwrap();
        let repository = repository_with_commit(dir.path());

        std::fs::write(dir.path().join("edited.txt"), "the staged version\n").unwrap();
        stage(&repository, "edited.txt");
        std::fs::write(
            dir.path().join("edited.txt"),
            "the later, unstaged version\n",
        )
        .unwrap();

        let staged = collect(dir.path()).unwrap();
        let materialised = std::fs::read_to_string(staged.root().join("edited.txt")).unwrap();
        assert_eq!(materialised, "the staged version\n");
    }

    #[test]
    fn a_staged_deletion_is_not_collected() {
        let dir = tempfile::tempdir().unwrap();
        let repository = repository_with_commit(dir.path());

        std::fs::remove_file(dir.path().join("seed.txt")).unwrap();
        let mut index = repository.index().unwrap();
        index.remove_path(Path::new("seed.txt")).unwrap();
        index.write().unwrap();

        let staged = collect(dir.path()).unwrap();
        assert!(
            staged.is_empty(),
            "a path being removed cannot carry a secret into the commit"
        );
    }

    #[test]
    fn nested_paths_keep_their_directory_structure() {
        let dir = tempfile::tempdir().unwrap();
        let repository = repository_with_commit(dir.path());

        std::fs::create_dir_all(dir.path().join("src").join("deep")).unwrap();
        std::fs::write(
            dir.path().join("src").join("deep").join("a.rs"),
            "fn a() {}\n",
        )
        .unwrap();
        stage(&repository, "src/deep/a.rs");

        let staged = collect(dir.path()).unwrap();
        assert!(
            staged
                .root()
                .join("src")
                .join("deep")
                .join("a.rs")
                .is_file()
        );
    }

    #[test]
    fn the_temporary_directory_is_removed_when_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let repository = repository_with_commit(dir.path());
        std::fs::write(dir.path().join("added.txt"), "x\n").unwrap();
        stage(&repository, "added.txt");

        let root = {
            let staged = collect(dir.path()).unwrap();
            staged.root().to_path_buf()
        };
        assert!(!root.exists(), "staged content outlived its handle");
    }

    #[test]
    fn a_sibling_packages_staged_file_is_not_collected_for_this_project() {
        // Review finding: `Repository::discover` walks upward, so scanning `mono/appA`
        // used to return every staged path in `mono`, including `appB`'s — while the
        // report still said the project was `appA`.
        let dir = tempfile::tempdir().unwrap();
        let repository = repository_with_commit(dir.path());

        for package in ["appA", "appB"] {
            std::fs::create_dir_all(dir.path().join(package)).unwrap();
            std::fs::write(
                dir.path().join(package).join("config.txt"),
                format!("{package} config\n"),
            )
            .unwrap();
        }
        stage(&repository, "appA");
        stage(&repository, "appB");

        let staged = collect(&dir.path().join("appA")).unwrap();

        let names: Vec<String> = staged
            .relative_files()
            .iter()
            .map(|path| path.to_string_lossy().replace('\\', "/"))
            .collect();
        assert_eq!(
            names,
            ["appA/config.txt"],
            "only the scanned project's staged files belong in this result"
        );
    }

    #[test]
    fn scanning_the_repository_root_still_sees_every_staged_file() {
        let dir = tempfile::tempdir().unwrap();
        let repository = repository_with_commit(dir.path());

        std::fs::create_dir_all(dir.path().join("pkg")).unwrap();
        std::fs::write(dir.path().join("pkg").join("a.txt"), "a\n").unwrap();
        std::fs::write(dir.path().join("top.txt"), "top\n").unwrap();
        stage(&repository, "pkg");
        stage(&repository, "top.txt");

        let staged = collect(dir.path()).unwrap();
        assert_eq!(
            staged.relative_files().len(),
            2,
            "narrowing must not kick in when the project is the repository root"
        );
    }

    #[test]
    fn a_repository_with_no_commits_still_reports_its_staged_files() {
        let dir = tempfile::tempdir().unwrap();
        let repository = Repository::init(dir.path()).unwrap();
        std::fs::write(dir.path().join("first.txt"), "first\n").unwrap();
        stage(&repository, "first.txt");

        let staged = collect(dir.path()).unwrap();
        assert_eq!(staged.relative_files(), [PathBuf::from("first.txt")]);
    }
}
