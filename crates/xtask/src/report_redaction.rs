//! Enforces the redaction rule for reports: raw file content is read only where it is
//! declared, with a reason.
//!
//! `codepack-reports` states the rule plainly — a report that quotes a project's own file
//! content must put that text through `redact_line` first, because invariant I3 says a
//! secret's value never reaches a report. Until now that rested on each report author
//! remembering it. Of the reports that read files, most only quote paths and computed
//! numbers and were fine; three quoted content and did not redact it, which is audit
//! No. 2. A rule that has already been broken once, and whose violation looks exactly
//! like an ordinary `push_str(&format!(...))`, will be broken again (audit No. 20).
//!
//! So the build checks it, the same way `network_isolation` checks I1. The mechanism is
//! not "detect a leak" — that cannot be done by reading source — but "make the risky
//! read impossible to add quietly": `text::read_text_unredacted` is named for what it
//! returns, and a report that calls it has to appear in [`ALLOWED`] with a sentence
//! saying why raw content is safe there. Adding a call without adding the entry fails the
//! gate; adding the entry is a line a reviewer reads.

use std::path::Path;

/// The read that hands back a project's file content unredacted.
const RAW_READ: &str = "read_text_unredacted";

/// Reports permitted to read raw content, and why each one is safe.
///
/// Safe here means: the text is analysed and never written into the artifact. A report
/// that starts quoting what it reads must either redact each quoted value with
/// `redact_line` or lose its entry.
const ALLOWED: &[(&str, &str)] = &[
    (
        "api_surface.rs",
        "extracts declaration signatures and redacts each one before writing it",
    ),
    (
        "backend.rs",
        "counts framework and route markers; writes counts and file paths only",
    ),
    (
        "code_metrics.rs",
        "counts lines, blanks and comments; writes numbers only",
    ),
    (
        "code_quality.rs",
        "matches marker words to score a file; writes scores and paths only",
    ),
    (
        "dependencies.rs",
        "parses manifests for package names and versions, each redacted before writing",
    ),
    (
        "dependency_intelligence.rs",
        "parses manifests for package names and versions, each redacted before writing",
    ),
    (
        "docker.rs",
        "parses compose structure; every emitted name and value goes through redact_line",
    ),
    (
        "frontend.rs",
        "counts framework markers and component shapes; writes counts and paths only",
    ),
    (
        "key_files.rs",
        "measures size and marker density to rank files; writes ranks and paths only",
    ),
    (
        "refactoring.rs",
        "measures function length and nesting; writes measurements and paths only",
    ),
    (
        "scripts.rs",
        "reads Makefile targets and package scripts, each redacted before writing",
    ),
    (
        "todo_fixme.rs",
        "collects TODO/FIXME lines and redacts each one before writing it",
    ),
];

/// Fails when a report reads raw content without being listed, or when a listed report no
/// longer reads it.
pub(crate) fn check(root: &Path) -> Result<(), String> {
    let directory = root.join("crates/codepack-reports/src/reports");
    let entries = std::fs::read_dir(&directory)
        .map_err(|error| format!("could not read {}: {error}", directory.display()))?;

    let mut reads_raw: Vec<String> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("could not read a report file: {error}"))?;
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("could not read {}: {error}", path.display()))?;
        if text.contains(RAW_READ) {
            reads_raw.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    reads_raw.sort();

    let listed: Vec<&str> = ALLOWED.iter().map(|(name, _)| *name).collect();

    let undeclared: Vec<&String> = reads_raw
        .iter()
        .filter(|name| !listed.contains(&name.as_str()))
        .collect();
    if !undeclared.is_empty() {
        return Err(format!(
            "these reports read raw file content but are not declared in \
             crates/xtask/src/report_redaction.rs: {undeclared:?}.\n\
             If the text is only analysed and never written into the artifact, add an entry \
             saying so. If any of it is written, redact each value with \
             `codepack_reports::context::redact_line` first — invariant I3."
        ));
    }

    // The other direction, so the list cannot rot into a set of claims about code that no
    // longer does this. A stale entry is a stale justification, and a reviewer reading it
    // would be reading a lie about the current code.
    let stale: Vec<&str> = listed
        .iter()
        .filter(|name| !reads_raw.contains(&(*name).to_string()))
        .copied()
        .collect();
    if !stale.is_empty() {
        return Err(format!(
            "these reports are declared in crates/xtask/src/report_redaction.rs but no \
             longer read raw content: {stale:?}. Remove their entries."
        ));
    }

    println!(
        "report redaction ok: {} report(s) read raw content, each declared with a reason \
         (invariant I3).",
        reads_raw.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The check passes against the repository as it stands. If it does not, either a
    /// report started reading raw content or one stopped — both are things the list has
    /// to be told about, which is the whole point.
    #[test]
    fn the_real_repository_is_declared_correctly() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("the workspace root is two levels above this crate");
        check(root).expect("every report that reads raw content is declared");
    }

    /// Every entry carries a reason a person can read. An empty justification would make
    /// the list a checkbox rather than a record.
    #[test]
    fn every_entry_explains_itself() {
        for (name, reason) in ALLOWED {
            assert!(
                reason.len() > 20,
                "{name} needs a real justification, not {reason:?}"
            );
        }
    }

    /// No duplicates, so one report cannot be justified twice with two different claims.
    #[test]
    fn the_list_names_each_report_once() {
        let mut names: Vec<&str> = ALLOWED.iter().map(|(name, _)| *name).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), before, "a report is listed twice");
    }

    /// An undeclared reader is refused. Written against a temporary tree rather than the
    /// real one, so the failure path is exercised rather than assumed.
    #[test]
    fn an_undeclared_reader_fails_the_check() {
        let dir = tempfile::tempdir().unwrap();
        let reports = dir.path().join("crates/codepack-reports/src/reports");
        std::fs::create_dir_all(&reports).unwrap();
        std::fs::write(
            reports.join("brand_new.rs"),
            format!("let text = {RAW_READ}(&path, None);"),
        )
        .unwrap();

        let error = check(dir.path()).expect_err("an undeclared reader must fail the gate");
        assert!(error.contains("brand_new.rs"), "{error}");
        assert!(error.contains("redact_line"), "{error}");
    }

    /// A report that does not read raw content needs no entry, and its presence alone is
    /// not what the check keys on.
    #[test]
    fn a_report_that_reads_nothing_raw_is_not_asked_to_declare_itself() {
        let dir = tempfile::tempdir().unwrap();
        let reports = dir.path().join("crates/codepack-reports/src/reports");
        std::fs::create_dir_all(&reports).unwrap();
        std::fs::write(reports.join("quiet.rs"), "fn run() {}").unwrap();

        // Every listed report is absent from this tree, so the staleness half fires —
        // which is itself the assertion that the check looks at both directions.
        let error = check(dir.path()).expect_err("the list is stale against an empty tree");
        assert!(error.contains("no longer read raw content"), "{error}");
        assert!(!error.contains("quiet.rs"), "{error}");
    }
}
