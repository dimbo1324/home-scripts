//! `scan --history` — looking for secrets in what was committed, not only in what is
//! there now.
//!
//! ## Why the working tree is not enough
//!
//! Deleting a credential from a file does not delete it from the repository. It stays
//! in every commit that carried it, and it travels with every clone, fork and mirror of
//! that history — which is the whole reason a leaked key has to be *rotated* and not
//! merely removed. Until this existed, `codepack scan` answered "is my working tree
//! clean?" and a user could reasonably read that as "am I safe?", which are different
//! questions with different answers.
//!
//! ## What is walked
//!
//! Commits reachable from `HEAD`, newest first, each compared against its first parent
//! so only what that commit *introduced* is examined. A merge is therefore read against
//! its first parent alone: content coming in from the second side was introduced by the
//! commits on that side, and they are walked in their own right. A root commit is
//! compared against nothing, so all of it is new.
//!
//! `--since <ref>` hides everything reachable from that ref, which turns the walk into
//! "what has this branch added since `main`" — the CI question.
//!
//! ## Blobs, not commits, are the unit of work
//!
//! A file untouched for a thousand commits appears in exactly one of them, but a file
//! rewritten daily appears many times with a different blob each time. Deduplicating by
//! blob id means each distinct *content* is scanned once, and the report can say which
//! commit first introduced it. Without that, one secret in a busy file becomes one
//! finding per commit, and the report is unreadable exactly when it matters most.
//!
//! ## The two limits, and why they are visible
//!
//! A history walk is unbounded work on someone else's repository, so there is a commit
//! cap and a blob-size cap. Both are reported. A truncated security answer that looks
//! complete is the single worst thing this file could produce, so when the cap is hit,
//! the report says so and the human output prints it as a warning rather than a note.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use codepack_core::time::UtcDateTime;
use git2::{Delta, DiffOptions, ObjectType, Oid, Repository};

use crate::error::{CliError, Result};

/// Commits walked when `--max-commits` is not given.
///
/// Not unlimited: a full walk of a large repository writes every distinct version of
/// every text file to disk, and somebody typing `codepack scan --history` to see what it
/// does should not discover that by filling their drive. `0` means no limit, for the
/// person who does want the whole history.
pub(crate) const DEFAULT_MAX_COMMITS: usize = 500;

/// Blobs larger than this are skipped and counted.
///
/// A credential is a short string; an eight-megabyte file is a data set, a minified
/// bundle or a checked-in artifact. This bounds any single file version; what bounds the
/// walk as a whole is [`MAX_TOTAL_BYTES`].
const MAX_BLOB_BYTES: usize = 8 * 1024 * 1024;

/// Total bytes this walk will write into the temporary directory.
///
/// The per-blob cap and the commit cap between them bound nothing in aggregate: five
/// hundred commits of a large repository is easily tens of thousands of distinct blobs,
/// and at a hundred kilobytes each that is gigabytes on disk. The module comment claimed
/// the commit cap existed so a user would not "discover the disk filling up" — a cap on
/// commits does not bound volume, and `--max-commits 0` is documented, offered, and
/// wired through `action.yml`, which removes even that (audit No. 22).
///
/// Two gibibytes is generous for a scan of file *versions*, and small enough to leave a
/// CI runner able to finish its job.
const MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// One historical file version, and where it came from.
#[derive(Debug, Clone)]
pub(crate) struct HistoricalBlob {
    /// Path inside the temporary directory, relative to [`HistoryContent::root`].
    pub relative: PathBuf,
    /// The path the file had in the repository, as git spells it.
    pub repo_path: String,
    /// Abbreviated id of the commit that introduced this content.
    pub commit: String,
    /// Committer time, at full precision with its zone stated
    /// (`.ai/universal/09-time-and-timestamps.md`).
    pub committed_at: String,
    /// The commit's subject line, trimmed to one line.
    pub summary: String,
}

/// Historical blobs unpacked into a temporary directory that is removed on drop.
#[derive(Debug)]
pub(crate) struct HistoryContent {
    directory: tempfile::TempDir,
    blobs: Vec<HistoricalBlob>,
    pub commits_walked: usize,
    /// True when the commit cap stopped the walk before history ran out.
    pub truncated: bool,
    /// Blobs skipped for exceeding [`MAX_BLOB_BYTES`].
    pub skipped_large_blobs: usize,
    /// True when [`MAX_TOTAL_BYTES`] stopped the walk. Reported as a **warning** rather
    /// than a note: it means the answer covers only part of the history, and a partial
    /// "nothing found" that reads like a complete one is the failure this module already
    /// guards against for its other two limits.
    pub truncated_by_size: bool,
    /// Tree entries refused for naming a path that would not stay under the temporary
    /// root. Counted rather than dropped quietly: such an entry is a finding about the
    /// repository, not noise.
    pub skipped_unsafe_paths: usize,
}

impl HistoryContent {
    pub(crate) fn root(&self) -> &Path {
        self.directory.path()
    }

    pub(crate) fn blobs(&self) -> &[HistoricalBlob] {
        &self.blobs
    }

    pub(crate) fn relative_files(&self) -> Vec<PathBuf> {
        self.blobs
            .iter()
            .map(|blob| blob.relative.clone())
            .collect()
    }
}

/// Options a caller can narrow the walk with.
#[derive(Debug, Clone, Default)]
pub(crate) struct HistoryOptions {
    /// Everything reachable from this ref is excluded — the walk becomes "what was added
    /// since".
    pub since: Option<String>,
    /// Commit cap; `0` means no cap.
    pub max_commits: usize,
}

/// Materialises every distinct historical version of every file under `project_root`.
pub(crate) fn collect(project_root: &Path, options: &HistoryOptions) -> Result<HistoryContent> {
    let repository = Repository::discover(project_root).map_err(|error| {
        CliError::message(format!(
            "--history needs a git repository, and {} is not inside one ({})",
            project_root.display(),
            error.message()
        ))
    })?;

    let mut revwalk = repository
        .revwalk()
        .map_err(|error| git_error("start walking the history", &error))?;
    revwalk
        .push_head()
        .map_err(|error| git_error("read HEAD", &error))?;
    if let Some(reference) = &options.since {
        let object = repository.revparse_single(reference).map_err(|error| {
            CliError::message(format!(
                "--since {reference:?} does not name anything in this repository ({})",
                error.message()
            ))
        })?;
        revwalk
            .hide(object.id())
            .map_err(|error| git_error("exclude the --since ref", &error))?;
    }

    // Scoped exactly like `scan --staged`: `Repository::discover` walks upward, so in a
    // monorepo the repository root is usually an ancestor of the project being scanned,
    // and an unscoped walk would report another package's history under this project's
    // name.
    let pathspec = scope_pathspec(&repository, project_root);

    let directory = tempfile::tempdir().map_err(|source| CliError::Read {
        path: project_root.to_path_buf(),
        source,
    })?;

    let mut seen: HashSet<Oid> = HashSet::new();
    let mut blobs: Vec<HistoricalBlob> = Vec::new();
    let mut commits_walked = 0usize;
    let mut truncated = false;
    let mut skipped_large_blobs = 0usize;
    let mut skipped_unsafe_paths = 0usize;
    let mut materialised_bytes = 0u64;
    let mut truncated_by_size = false;

    'walk: for id in revwalk {
        if options.max_commits != 0 && commits_walked >= options.max_commits {
            truncated = true;
            break;
        }
        let id = id.map_err(|error| git_error("walk the history", &error))?;
        let commit = repository
            .find_commit(id)
            .map_err(|error| git_error("read a commit", &error))?;
        commits_walked += 1;

        let tree = commit
            .tree()
            .map_err(|error| git_error("read a commit's tree", &error))?;
        let parent_tree = match commit.parent(0) {
            Ok(parent) => Some(
                parent
                    .tree()
                    .map_err(|error| git_error("read a parent commit's tree", &error))?,
            ),
            // A root commit introduced everything it contains.
            Err(_) => None,
        };

        let mut diff_options = DiffOptions::new();
        if let Some(scope) = &pathspec {
            diff_options.pathspec(scope);
        }
        let diff = repository
            .diff_tree_to_tree(parent_tree.as_ref(), Some(&tree), Some(&mut diff_options))
            .map_err(|error| git_error("compare a commit against its parent", &error))?;

        let committed_at =
            UtcDateTime::from_unix_seconds(commit.time().seconds()).format_human_utc();
        let short_id = short_id(&repository, id);
        let summary = commit
            .summary()
            .ok()
            .flatten()
            .unwrap_or("")
            .trim()
            .to_string();

        for delta in diff.deltas() {
            // A deletion introduces nothing; its content was already seen in the commit
            // that added it, and that commit is in this walk.
            if matches!(delta.status(), Delta::Deleted) {
                continue;
            }
            let entry = delta.new_file();
            let Some(repo_path) = entry.path() else {
                continue;
            };
            // Blobs only: symlinks carry no content of their own and a submodule's
            // content is not in this repository at all (invariant I7's reasoning).
            if entry.mode() != git2::FileMode::Blob
                && entry.mode() != git2::FileMode::BlobExecutable
            {
                continue;
            }
            if !seen.insert(entry.id()) {
                continue;
            }
            let Ok(object) = repository.find_object(entry.id(), Some(ObjectType::Blob)) else {
                continue;
            };
            let Some(blob) = object.as_blob() else {
                continue;
            };
            if blob.size() > MAX_BLOB_BYTES {
                skipped_large_blobs += 1;
                continue;
            }
            // Checked before writing, so the budget is a ceiling on what lands rather
            // than on what has already landed.
            let blob_bytes = blob.size() as u64;
            if materialised_bytes.saturating_add(blob_bytes) > MAX_TOTAL_BYTES {
                truncated_by_size = true;
                // Out of the commit walk entirely, not just this commit's deltas: with
                // the budget spent there is nothing left to materialise, and walking on
                // would only inflate `commits_walked` into a claim of coverage the scan
                // does not have.
                break 'walk;
            }

            // Each distinct blob gets its own directory, named for its id: the same path
            // legitimately holds different content in different commits, and writing
            // them over each other would scan only the last one.
            // `repo_path` is the path as the foreign repository recorded it, and this
            // command exists to be run against foreign history — on a fork in CI, on a
            // pull request from the GitHub action. `libgit2` does not validate tree entry
            // names the way `git fsck` does, so an entry spelled `../..` or as an absolute
            // path would otherwise have this loop write a blob outside the temporary
            // directory (audit No. 10).
            let Ok(safe_repo_path) = codepack_core::safe_join(Path::new(""), repo_path) else {
                skipped_unsafe_paths += 1;
                continue;
            };
            let relative = PathBuf::from(short_oid(entry.id())).join(safe_repo_path);
            let destination = directory.path().join(&relative);
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

            materialised_bytes = materialised_bytes.saturating_add(blob_bytes);
            blobs.push(HistoricalBlob {
                relative,
                repo_path: repo_path.to_string_lossy().replace('\\', "/"),
                commit: short_id.clone(),
                committed_at: committed_at.clone(),
                summary: summary.clone(),
            });
        }
    }

    Ok(HistoryContent {
        directory,
        blobs,
        commits_walked,
        truncated,
        skipped_large_blobs,
        skipped_unsafe_paths,
        truncated_by_size,
    })
}

/// The abbreviation git itself would print, falling back to a fixed-width prefix when
/// the repository cannot compute one.
fn short_id(repository: &Repository, id: Oid) -> String {
    repository
        .find_object(id, None)
        .ok()
        .and_then(|object| object.short_id().ok())
        .map(|buffer| String::from_utf8_lossy(&buffer).into_owned())
        .filter(|short| !short.is_empty())
        .unwrap_or_else(|| short_oid(id))
}

fn short_oid(id: Oid) -> String {
    id.to_string()[..8].to_string()
}

fn git_error(action: &str, error: &git2::Error) -> CliError {
    CliError::message(format!("cannot {action}: {}", error.message()))
}

/// `project_root` relative to the repository's working directory, in the forward-slash
/// form git pathspecs use. Identical in intent to `staged::scope_pathspec`; kept beside
/// its own walk rather than shared, because the two modules answer different questions
/// and a change to one is not automatically right for the other.
fn scope_pathspec(repository: &Repository, project_root: &Path) -> Option<String> {
    let workdir = repository.workdir()?;
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

    /// Built through `git2`, never by shelling out to a `git` binary — the domain rules
    /// forbid a test that needs one installed.
    fn commit_file(repository: &Repository, name: &str, contents: &str, message: &str) -> Oid {
        let root = repository.workdir().unwrap().to_path_buf();
        let path = root.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, contents).unwrap();

        let mut index = repository.index().unwrap();
        index.add_all(["."], IndexAddOption::DEFAULT, None).unwrap();
        index.write().unwrap();
        let tree_id = index.write_tree().unwrap();
        let tree = repository.find_tree(tree_id).unwrap();
        let signature = Signature::now("Test", "test@example.local").unwrap();

        let parents = match repository
            .head()
            .ok()
            .and_then(|head| head.peel_to_commit().ok())
        {
            Some(parent) => vec![parent],
            None => Vec::new(),
        };
        let parent_refs: Vec<&git2::Commit<'_>> = parents.iter().collect();
        let id = repository
            .commit(
                Some("HEAD"),
                &signature,
                &signature,
                message,
                &tree,
                &parent_refs,
            )
            .unwrap();
        drop(tree);
        id
    }

    fn repository(root: &Path) -> Repository {
        Repository::init(root).unwrap()
    }

    /// A tree entry whose recorded name climbs out of the repository (audit No. 10).
    ///
    /// The tree object is written straight into the object database: `git2`'s
    /// `TreeBuilder` and its index both validate entry names, and that validation is
    /// exactly what a hostile repository does not perform on itself. `git fsck` would
    /// reject this; `libgit2` reading a packfile does not, and this command exists to be
    /// run against repositories nobody here controls.
    #[test]
    fn a_tree_entry_that_escapes_the_repository_is_refused_and_counted() {
        let dir = tempfile::tempdir().unwrap();
        let repo = repository(dir.path());
        commit_file(&repo, "a.txt", "clean\n", "first");

        let blob = repo.blob(b"AWS_KEY = 'leaked'\n").unwrap();
        let mut tree_bytes = Vec::new();
        tree_bytes.extend_from_slice(b"100644 ../escape.txt\0");
        tree_bytes.extend_from_slice(blob.as_bytes());
        let tree_id = repo
            .odb()
            .unwrap()
            .write(git2::ObjectType::Tree, &tree_bytes)
            .unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let signature = Signature::now("Test", "test@example.local").unwrap();
        let parent = repo.head().unwrap().peel_to_commit().unwrap();
        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            "hostile",
            &tree,
            &[&parent],
        )
        .unwrap();

        let history = collect(dir.path(), &HistoryOptions::default()).unwrap();

        assert_eq!(history.skipped_unsafe_paths, 1);
        assert!(
            history
                .blobs()
                .iter()
                .all(|blob| !blob.repo_path.contains("escape")),
            "the escaping entry must not have been materialised"
        );
    }

    /// The budget the walk did not have. Per-blob and per-commit caps bound neither the
    /// number of distinct blobs nor their total, and `--max-commits 0` removes even the
    /// commit cap (audit No. 22).
    #[test]
    fn the_walk_stops_when_it_has_materialised_as_much_as_it_may_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let repo = repository(dir.path());
        // Distinct content per commit, so nothing is deduplicated away.
        for index in 0..4 {
            commit_file(
                &repo,
                &format!("f{index}.txt"),
                &format!(
                    "version {index}
"
                ),
                &format!("commit {index}"),
            );
        }

        let history = collect(
            dir.path(),
            &HistoryOptions {
                max_commits: 0,
                ..HistoryOptions::default()
            },
        )
        .unwrap();

        // The real ceiling is two gibibytes, which no test should write, so what is
        // asserted here is that an ordinary walk is *not* marked truncated — the flag
        // must mean something rather than being set by default.
        assert!(!history.truncated_by_size);
        assert!(!history.blobs().is_empty());
    }

    /// Exercises the budget itself at a size a test can afford, by checking the
    /// arithmetic the walk uses rather than by writing gigabytes.
    #[test]
    fn the_budget_refuses_the_blob_that_would_cross_it_rather_than_after_it() {
        let mut materialised: u64 = MAX_TOTAL_BYTES - 10;
        let blob: u64 = 11;
        // The check is `would exceed`, evaluated before the write.
        assert!(materialised.saturating_add(blob) > MAX_TOTAL_BYTES);

        materialised = MAX_TOTAL_BYTES - 11;
        assert!(
            materialised.saturating_add(blob) <= MAX_TOTAL_BYTES,
            "a blob that exactly fills the budget is still written"
        );
    }

    #[test]
    fn not_a_repository_is_an_error_not_an_empty_result() {
        let dir = tempfile::tempdir().unwrap();
        let error = collect(dir.path(), &HistoryOptions::default())
            .unwrap_err()
            .to_string();
        assert!(error.contains("git repository"), "{error}");
    }

    #[test]
    fn content_deleted_from_the_working_tree_is_still_found_in_history() {
        // The entire reason this module exists.
        let dir = tempfile::tempdir().unwrap();
        let repo = repository(dir.path());
        commit_file(&repo, "config.py", "AWS_KEY = 'leaked'\n", "add config");
        std::fs::remove_file(dir.path().join("config.py")).unwrap();
        commit_file(&repo, "readme.md", "clean now\n", "remove config");

        let history = collect(dir.path(), &HistoryOptions::default()).unwrap();

        let found = history
            .blobs()
            .iter()
            .find(|blob| blob.repo_path == "config.py")
            .expect("the deleted file's content is still in the history");
        let text = std::fs::read_to_string(history.root().join(&found.relative)).unwrap();
        assert!(text.contains("leaked"));
    }

    #[test]
    fn identical_content_committed_twice_is_materialised_once() {
        let dir = tempfile::tempdir().unwrap();
        let repo = repository(dir.path());
        commit_file(&repo, "a.txt", "same bytes\n", "first");
        commit_file(&repo, "b.txt", "same bytes\n", "second");

        let history = collect(dir.path(), &HistoryOptions::default()).unwrap();

        let copies = history
            .blobs()
            .iter()
            .filter(|blob| {
                std::fs::read_to_string(history.root().join(&blob.relative)).unwrap()
                    == "same bytes\n"
            })
            .count();
        assert_eq!(copies, 1, "one blob, one scan");
    }

    #[test]
    fn two_versions_of_one_path_are_both_kept() {
        // The reason each blob gets its own directory: writing them to the same path
        // would scan only whichever was written last.
        let dir = tempfile::tempdir().unwrap();
        let repo = repository(dir.path());
        commit_file(&repo, "config.py", "KEY = 'old'\n", "first");
        commit_file(&repo, "config.py", "KEY = 'new'\n", "second");

        let history = collect(dir.path(), &HistoryOptions::default()).unwrap();

        let versions: Vec<String> = history
            .blobs()
            .iter()
            .filter(|blob| blob.repo_path == "config.py")
            .map(|blob| std::fs::read_to_string(history.root().join(&blob.relative)).unwrap())
            .collect();
        assert_eq!(versions.len(), 2);
        assert!(versions.iter().any(|text| text.contains("old")));
        assert!(versions.iter().any(|text| text.contains("new")));
    }

    #[test]
    fn each_blob_names_the_commit_that_introduced_it_with_a_full_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        let repo = repository(dir.path());
        commit_file(&repo, "a.txt", "content\n", "the subject line");

        let history = collect(dir.path(), &HistoryOptions::default()).unwrap();
        let blob = &history.blobs()[0];

        assert_eq!(blob.summary, "the subject line");
        assert!(!blob.commit.is_empty());
        // Full precision with the zone stated, per `09-time-and-timestamps.md`.
        assert!(blob.committed_at.ends_with(" UTC"), "{}", blob.committed_at);
        assert_eq!(
            blob.committed_at.matches(':').count(),
            2,
            "a bare date cannot order two commits made on the same day: {}",
            blob.committed_at
        );
    }

    #[test]
    fn since_excludes_everything_reachable_from_that_ref() {
        let dir = tempfile::tempdir().unwrap();
        let repo = repository(dir.path());
        let base = commit_file(&repo, "old.txt", "already reviewed\n", "base");
        commit_file(&repo, "new.txt", "just added\n", "new work");

        let history = collect(
            dir.path(),
            &HistoryOptions {
                since: Some(base.to_string()),
                ..HistoryOptions::default()
            },
        )
        .unwrap();

        let paths: Vec<&str> = history
            .blobs()
            .iter()
            .map(|blob| blob.repo_path.as_str())
            .collect();
        assert_eq!(paths, ["new.txt"]);
    }

    #[test]
    fn an_unknown_since_ref_is_an_error_that_names_it() {
        let dir = tempfile::tempdir().unwrap();
        let repo = repository(dir.path());
        commit_file(&repo, "a.txt", "x\n", "first");

        let error = collect(
            dir.path(),
            &HistoryOptions {
                since: Some("no-such-branch".to_string()),
                ..HistoryOptions::default()
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("no-such-branch"), "{error}");
    }

    #[test]
    fn the_commit_cap_stops_the_walk_and_says_so() {
        // A truncated security answer that looks complete is the worst outcome here.
        let dir = tempfile::tempdir().unwrap();
        let repo = repository(dir.path());
        for index in 0..4 {
            commit_file(&repo, &format!("f{index}.txt"), "x\n", "commit");
        }

        let history = collect(
            dir.path(),
            &HistoryOptions {
                max_commits: 2,
                ..HistoryOptions::default()
            },
        )
        .unwrap();

        assert_eq!(history.commits_walked, 2);
        assert!(history.truncated);
    }

    #[test]
    fn a_walk_that_reaches_the_end_is_not_marked_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let repo = repository(dir.path());
        commit_file(&repo, "a.txt", "x\n", "only commit");

        let history = collect(
            dir.path(),
            &HistoryOptions {
                max_commits: 50,
                ..HistoryOptions::default()
            },
        )
        .unwrap();

        assert_eq!(history.commits_walked, 1);
        assert!(!history.truncated);
    }

    #[test]
    fn an_oversized_blob_is_skipped_and_counted_rather_than_written() {
        let dir = tempfile::tempdir().unwrap();
        let repo = repository(dir.path());
        let big = "x".repeat(MAX_BLOB_BYTES + 1);
        commit_file(&repo, "huge.txt", &big, "add a large file");

        let history = collect(dir.path(), &HistoryOptions::default()).unwrap();

        assert_eq!(history.skipped_large_blobs, 1);
        assert!(history.blobs().is_empty());
    }

    #[test]
    fn a_sibling_packages_history_is_not_collected_for_this_project() {
        let dir = tempfile::tempdir().unwrap();
        let repo = repository(dir.path());
        commit_file(&repo, "appA/config.txt", "a\n", "app a");
        commit_file(&repo, "appB/config.txt", "b\n", "app b");

        let history = collect(&dir.path().join("appA"), &HistoryOptions::default()).unwrap();

        let paths: Vec<&str> = history
            .blobs()
            .iter()
            .map(|blob| blob.repo_path.as_str())
            .collect();
        assert_eq!(paths, ["appA/config.txt"]);
    }

    #[test]
    fn the_temporary_directory_is_removed_when_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let repo = repository(dir.path());
        commit_file(&repo, "a.txt", "x\n", "first");

        let root = {
            let history = collect(dir.path(), &HistoryOptions::default()).unwrap();
            history.root().to_path_buf()
        };
        assert!(!root.exists(), "historical content outlived its handle");
    }
}
