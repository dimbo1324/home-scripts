//! Reports ignored advisories that no longer match anything in the dependency graph.
//!
//! `deny.toml` carries a list of advisories accepted by owner decision, each because its
//! upstream has no safe upgrade. Nothing made that list expire: it would go on suppressing
//! an advisory long after the dependency that caused it was updated or dropped, and the
//! first sign would be nobody noticing a real one (audit No. 33).
//!
//! This does not fail the build. An entry that has stopped matching is housekeeping, not a
//! defect, and turning a dependency update into a red gate would teach people to delete
//! the check rather than the entry. It prints what can go, so the list prunes itself the
//! next time somebody looks.
//!
//! It reads `cargo deny`'s own JSON diagnostics rather than guessing: an entry is stale
//! exactly when `cargo deny` says it matched nothing, and asking the tool that owns the
//! question is the only answer that stays right as the graph moves.

use std::path::Path;
use std::process::Command;

/// Prints any advisory in `deny.toml`'s ignore list that matched nothing.
///
/// Never fails the gate — see the module docs. A `cargo deny` that cannot run at all is
/// reported and skipped, because the `deny` step itself has already had its say about
/// that by the time this runs.
pub(crate) fn check(root: &Path) -> Result<(), String> {
    let declared = declared_ignores(root)?;
    if declared.is_empty() {
        println!("ignored advisories: none declared.");
        return Ok(());
    }

    let output = Command::new("cargo")
        .args(["deny", "--format", "json", "check", "advisories"])
        .current_dir(root)
        .output();

    let Ok(output) = output else {
        println!(
            "ignored advisories: cargo-deny is not available, so {} entr(ies) were not \
             re-checked.",
            declared.len()
        );
        return Ok(());
    };

    // Diagnostics go to stderr, one JSON object per line.
    let diagnostics = String::from_utf8_lossy(&output.stderr);
    let matched: Vec<&String> = declared
        .iter()
        .filter(|id| diagnostics.contains(id.as_str()))
        .collect();
    let unmatched: Vec<&String> = declared
        .iter()
        .filter(|id| !diagnostics.contains(id.as_str()))
        .collect();

    if unmatched.is_empty() {
        println!(
            "ignored advisories: all {} still apply to the current graph.",
            declared.len()
        );
        return Ok(());
    }

    println!(
        "ignored advisories: {} of {} no longer match anything in the graph and can be \
         removed from deny.toml:",
        unmatched.len(),
        declared.len()
    );
    for id in &unmatched {
        println!("  {id}");
    }
    println!("  ({} still apply.)", matched.len());
    Ok(())
}

/// Every advisory id in `deny.toml`'s `[advisories] ignore` list.
///
/// Parsed as TOML rather than grepped: the entries are `{ id = "...", reason = "..." }`
/// tables since audit No. 33, and a regex over that shape is the kind of thing that keeps
/// working until the day somebody reformats the file.
fn declared_ignores(root: &Path) -> Result<Vec<String>, String> {
    let path = root.join("deny.toml");
    let text = std::fs::read_to_string(&path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let parsed: toml::Table = text
        .parse()
        .map_err(|error| format!("{} is not valid TOML: {error}", path.display()))?;

    let Some(ignore) = parsed
        .get("advisories")
        .and_then(|advisories| advisories.get("ignore"))
        .and_then(|ignore| ignore.as_array())
    else {
        return Ok(Vec::new());
    };

    Ok(ignore
        .iter()
        .filter_map(|entry| match entry {
            // Both spellings are valid cargo-deny: a bare id, or a table with a reason.
            toml::Value::String(id) => Some(id.clone()),
            toml::Value::Table(table) => table
                .get("id")
                .and_then(toml::Value::as_str)
                .map(str::to_string),
            _ => None,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace_root() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("the workspace root is two levels above this crate")
    }

    /// The real `deny.toml` parses, and every entry yields an id. A `reason` that swallowed
    /// the id would make this check silently examine nothing.
    #[test]
    fn every_entry_in_the_real_deny_toml_yields_an_id() {
        let ids = declared_ignores(workspace_root()).expect("deny.toml parses");
        assert!(!ids.is_empty(), "the project does ignore some advisories");
        for id in &ids {
            assert!(id.starts_with("RUSTSEC-"), "{id} is not an advisory id");
        }
    }

    /// Both spellings cargo-deny accepts are understood, so switching between them cannot
    /// quietly empty the list this step examines.
    #[test]
    fn both_a_bare_id_and_a_table_with_a_reason_are_read() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("deny.toml"),
            "[advisories]\nignore = [\n  \"RUSTSEC-0000-0001\",\n  \
             { id = \"RUSTSEC-0000-0002\", reason = \"because\" },\n]\n",
        )
        .unwrap();

        let ids = declared_ignores(dir.path()).unwrap();
        assert_eq!(ids, vec!["RUSTSEC-0000-0001", "RUSTSEC-0000-0002"]);
    }

    /// A file with no ignore list is not an error: a project that suppresses nothing is
    /// the state this check would like everyone to reach.
    #[test]
    fn a_deny_toml_with_no_ignores_yields_nothing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("deny.toml"),
            "[bans]\nwildcards = \"deny\"\n",
        )
        .unwrap();
        assert!(declared_ignores(dir.path()).unwrap().is_empty());
    }
}
