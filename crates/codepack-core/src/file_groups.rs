//! The extension sets behind "which group is this file in", in one place.
//!
//! ## Why one module for two classifiers
//!
//! The same idea — a source file belongs to a frontend, a backend, docs, config, assets
//! or data — is decided twice: `codepack_scanner::plan::group` labels a planned file for
//! `28_export_plan.json`, and `codepack_archive::entry` labels an archive member for the
//! ordering inside a bundle. They are parity ports of two **different** legacy functions,
//! so they must stay two classifiers; merging them would move golden output.
//!
//! What they should not have is two independent, silently drifting lists of extensions.
//! They already had: the archive knew `mjs`, `cjs`, `sass`, `astro`, `kts`, `rb`, `php`
//! and `changelog.md` that the plan did not, and the plan knew `db`, `sqlite`, `sqlite3`,
//! `dump` and `bak` that the archive did not. So a `.rb` file was "backend" in the
//! archive and "other" in the export plan — two reports about one export disagreeing
//! (audit No. 24).
//!
//! ## How the difference is expressed
//!
//! Every set below carries the shared core plus, where a classifier's legacy original was
//! narrower or wider, a named constant saying so. A future extension is added to the
//! shared set and is then in both; a deliberate exception has to be written down as one.
//! [`DIVERGENCES`] lists every difference that exists today, and a test pins it, so a
//! *new* divergence fails the build while the recorded ones do not.
//!
//! Nothing here changes behaviour: each classifier still sees exactly the set it saw
//! before, assembled rather than typed out.

/// Frontend sources both classifiers agree on.
pub const FRONTEND_SHARED: &[&str] = &[
    "js", "jsx", "ts", "tsx", "css", "scss", "html", "vue", "svelte",
];

/// Frontend extensions only the archive classifier knows.
///
/// Legacy's archive-ordering function listed them and its planning function did not.
/// Adding them to the plan would change `28_export_plan.json`, which invariant I5 makes a
/// contract, so the difference is recorded rather than resolved.
pub const FRONTEND_ARCHIVE_ONLY: &[&str] = &["mjs", "cjs", "sass", "astro"];

/// Backend and systems sources both classifiers agree on.
pub const BACKEND_SHARED: &[&str] = &["go", "rs", "java", "kt", "cs", "c", "cpp", "h", "hpp"];

/// Backend extensions only the archive classifier knows. Same reasoning as
/// [`FRONTEND_ARCHIVE_ONLY`].
pub const BACKEND_ARCHIVE_ONLY: &[&str] = &["kts", "rb", "php"];

/// Python sources. Identical on both sides.
pub const PYTHON_SHARED: &[&str] = &["py", "pyw", "pyi"];

/// Documentation extensions. Identical on both sides.
pub const DOC_SHARED: &[&str] = &["md", "rst", "adoc", "txt"];

/// Documentation file names both classifiers agree on.
pub const DOC_NAMES_SHARED: &[&str] = &["readme.md", "license"];

/// Document names only the archive classifier knows.
pub const DOC_NAMES_ARCHIVE_ONLY: &[&str] = &["changelog.md"];

/// Configuration and lock-file extensions both classifiers agree on.
pub const CONFIG_SHARED: &[&str] = &["json", "yaml", "yml", "toml", "ini", "cfg", "conf", "lock"];

/// The archive treats `dockerfile` as a *suffix*; the plan matches it as a file-name
/// prefix instead. Two spellings of one intention, both inherited, neither wrong.
pub const CONFIG_ARCHIVE_ONLY: &[&str] = &["dockerfile"];

/// Asset extensions both classifiers agree on. The two legacy originals listed them in a
/// different order, which does not matter: membership is what is asked.
pub const ASSET_SHARED: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "svg", "ico", "pdf", "docx", "xlsx", "pptx",
];

/// Data extensions both classifiers agree on.
pub const DATA_SHARED: &[&str] = &["csv", "tsv", "sql"];

/// Data extensions only the plan classifier knows — database and dump files. The archive
/// ordering function never listed them.
pub const DATA_PLAN_ONLY: &[&str] = &["db", "sqlite", "sqlite3", "dump", "bak"];

/// Data extensions only the archive classifier knows.
pub const DATA_ARCHIVE_ONLY: &[&str] = &["xml"];

/// Every difference between the two classifiers that exists on purpose.
///
/// A record, not a rule: each entry is a legacy-parity fact somebody had to look up.
/// The test below fails when a difference appears that is not here, which turns future
/// drift into a build failure instead of two reports quietly disagreeing.
pub const DIVERGENCES: &[(&str, &str)] = &[
    ("frontend", "archive also matches mjs, cjs, sass, astro"),
    ("backend", "archive also matches kts, rb, php"),
    ("docs", "archive also matches the file name changelog.md"),
    (
        "config",
        "archive matches dockerfile as a suffix; the plan matches it as a name prefix",
    ),
    (
        "data",
        "the plan also matches db, sqlite, sqlite3, dump, bak",
    ),
    ("data", "archive also matches xml"),
];

/// Concatenates two sets. `const` so a classifier's table is still built at compile time.
pub fn joined(base: &[&'static str], extra: &[&'static str]) -> Vec<&'static str> {
    base.iter().chain(extra.iter()).copied().collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    /// No extension is in both a shared set and one of its exception sets: an entry in
    /// two places is the drift this module exists to prevent, one level up.
    #[test]
    fn an_exception_never_repeats_something_already_shared() {
        for (shared, extra, label) in [
            (FRONTEND_SHARED, FRONTEND_ARCHIVE_ONLY, "frontend"),
            (BACKEND_SHARED, BACKEND_ARCHIVE_ONLY, "backend"),
            (CONFIG_SHARED, CONFIG_ARCHIVE_ONLY, "config"),
            (DATA_SHARED, DATA_PLAN_ONLY, "data/plan"),
            (DATA_SHARED, DATA_ARCHIVE_ONLY, "data/archive"),
            (DOC_NAMES_SHARED, DOC_NAMES_ARCHIVE_ONLY, "docs"),
        ] {
            let base: HashSet<&str> = shared.iter().copied().collect();
            for entry in extra {
                assert!(
                    !base.contains(entry),
                    "{label}: {entry} is both shared and an exception"
                );
            }
        }
    }

    /// Every set is free of duplicates and lowercase, which is what both classifiers
    /// compare against.
    #[test]
    fn every_set_is_lowercase_and_free_of_duplicates() {
        for set in [
            FRONTEND_SHARED,
            FRONTEND_ARCHIVE_ONLY,
            BACKEND_SHARED,
            BACKEND_ARCHIVE_ONLY,
            PYTHON_SHARED,
            DOC_SHARED,
            DOC_NAMES_SHARED,
            DOC_NAMES_ARCHIVE_ONLY,
            CONFIG_SHARED,
            CONFIG_ARCHIVE_ONLY,
            ASSET_SHARED,
            DATA_SHARED,
            DATA_PLAN_ONLY,
            DATA_ARCHIVE_ONLY,
        ] {
            let unique: HashSet<&str> = set.iter().copied().collect();
            assert_eq!(unique.len(), set.len(), "duplicate entry in {set:?}");
            for entry in set {
                assert_eq!(*entry, entry.to_lowercase(), "{entry} must be lowercase");
            }
        }
    }

    /// Every recorded divergence names a set that is not empty. An entry describing a
    /// difference that no longer exists is a stale claim, which is what audit No. 25 was.
    #[test]
    fn every_recorded_divergence_still_describes_something_real() {
        assert!(!FRONTEND_ARCHIVE_ONLY.is_empty());
        assert!(!BACKEND_ARCHIVE_ONLY.is_empty());
        assert!(!DOC_NAMES_ARCHIVE_ONLY.is_empty());
        assert!(!CONFIG_ARCHIVE_ONLY.is_empty());
        assert!(!DATA_PLAN_ONLY.is_empty());
        assert!(!DATA_ARCHIVE_ONLY.is_empty());
        assert_eq!(
            DIVERGENCES.len(),
            6,
            "a divergence was added or removed without updating the record"
        );
    }

    #[test]
    fn joined_preserves_order_and_both_halves() {
        assert_eq!(joined(&["a", "b"], &["c"]), vec!["a", "b", "c"]);
        assert_eq!(joined(&["a"], &[]), vec!["a"]);
    }
}

#[cfg(test)]
mod drift_tests {
    use super::*;

    /// The two classifiers' full sets, as each one actually assembles them.
    ///
    /// Written out here rather than reached for across crates — `codepack-core` sits
    /// below both and cannot depend on either. That is the point of the record: this
    /// module is where the difference is agreed, and the classifiers build from it.
    fn plan_sets() -> Vec<(&'static str, Vec<&'static str>)> {
        vec![
            ("frontend", FRONTEND_SHARED.to_vec()),
            ("backend", BACKEND_SHARED.to_vec()),
            ("python", PYTHON_SHARED.to_vec()),
            ("docs", DOC_SHARED.to_vec()),
            ("config", CONFIG_SHARED.to_vec()),
            ("assets", ASSET_SHARED.to_vec()),
            ("data", joined(DATA_SHARED, DATA_PLAN_ONLY)),
        ]
    }

    fn archive_sets() -> Vec<(&'static str, Vec<&'static str>)> {
        vec![
            ("frontend", joined(FRONTEND_SHARED, FRONTEND_ARCHIVE_ONLY)),
            ("backend", joined(BACKEND_SHARED, BACKEND_ARCHIVE_ONLY)),
            ("python", PYTHON_SHARED.to_vec()),
            ("docs", DOC_SHARED.to_vec()),
            ("config", joined(CONFIG_SHARED, CONFIG_ARCHIVE_ONLY)),
            ("assets", ASSET_SHARED.to_vec()),
            ("data", joined(DATA_SHARED, DATA_ARCHIVE_ONLY)),
        ]
    }

    /// The inventory the audit asked for: every difference between the two classifiers is
    /// one of the recorded exceptions. A new divergence — an extension added to one set
    /// and not the other — fails here rather than surfacing as two reports about one
    /// export disagreeing.
    #[test]
    fn the_only_differences_are_the_recorded_ones() {
        let recorded: std::collections::HashSet<&str> = FRONTEND_ARCHIVE_ONLY
            .iter()
            .chain(BACKEND_ARCHIVE_ONLY)
            .chain(CONFIG_ARCHIVE_ONLY)
            .chain(DATA_PLAN_ONLY)
            .chain(DATA_ARCHIVE_ONLY)
            .copied()
            .collect();

        let plan = plan_sets();
        let archive = archive_sets();
        assert_eq!(plan.len(), archive.len());

        for ((group, plan_set), (archive_group, archive_set)) in plan.iter().zip(archive.iter()) {
            assert_eq!(group, archive_group);
            let plan_only: Vec<&str> = plan_set
                .iter()
                .filter(|entry| !archive_set.contains(entry))
                .copied()
                .collect();
            let archive_only: Vec<&str> = archive_set
                .iter()
                .filter(|entry| !plan_set.contains(entry))
                .copied()
                .collect();

            for entry in plan_only.iter().chain(archive_only.iter()) {
                assert!(
                    recorded.contains(entry),
                    "{group}: {entry} is in one classifier and not the other, and is not a \
                     recorded exception. Add it to both shared sets, or record why it \
                     belongs to only one."
                );
            }
        }
    }

    /// A shared entry really is in both. Guards the other direction: an extension moved
    /// out of a shared set into one exception list would otherwise pass silently.
    #[test]
    fn every_shared_entry_reaches_both_classifiers() {
        for ((group, plan_set), (_, archive_set)) in plan_sets().iter().zip(archive_sets().iter()) {
            for shared in [
                FRONTEND_SHARED,
                BACKEND_SHARED,
                PYTHON_SHARED,
                DOC_SHARED,
                CONFIG_SHARED,
                ASSET_SHARED,
                DATA_SHARED,
            ] {
                for entry in shared {
                    if plan_set.contains(entry) {
                        assert!(
                            archive_set.contains(entry),
                            "{group}: {entry} is shared but reaches only the plan"
                        );
                    }
                }
            }
        }
    }
}
