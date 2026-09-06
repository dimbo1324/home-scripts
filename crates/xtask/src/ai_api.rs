//! Checks `codepack-ai-api`, the one crate the gate deliberately cannot see.
//!
//! Excluding a package from the workspace buys a great deal — no `keyring` on Linux, no
//! `ureq` in the product's `Cargo.lock`, nothing extra in `cargo deny`'s graph — and
//! costs exactly one thing: `cargo xtask gate` stops compiling it, so it can rot without
//! anyone noticing. That cost was accepted knowingly (owner decision 2026-09-06, Q41),
//! and this command is what keeps it bounded.
//!
//! It is not part of `gate`, and putting it there would undo the exclusion: the whole
//! point is that a routine check on a Linux machine does not need a Secret Service
//! backend. Run it when touching this crate, and before finishing stage S13.

use std::path::Path;

use crate::step;

const MANIFEST: &str = "crates/codepack-ai-api/Cargo.toml";

/// Formats, lints and tests the excluded crate with the same denials the workspace uses.
///
/// The lint levels are duplicated in that crate's own manifest, because an excluded
/// package cannot inherit `[workspace.lints]`. Running clippy here with `-D warnings` is
/// what proves the duplicate is still doing its job rather than quietly drifting.
pub(crate) fn check(root: &Path) -> Result<(), String> {
    step(
        root,
        "ai-api: format",
        "cargo",
        &["fmt", "--manifest-path", MANIFEST, "--", "--check"],
    )?;

    step(
        root,
        "ai-api: clippy",
        "cargo",
        &[
            "clippy",
            "--manifest-path",
            MANIFEST,
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    )?;

    step(
        root,
        "ai-api: tests",
        "cargo",
        &["test", "--manifest-path", MANIFEST],
    )?;

    println!(
        "\nai-api ok. Reminder: `cargo xtask gate` does not run this — the crate is \
         excluded from the workspace so that `keyring` and `ureq` stay out of every \
         platform's build."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The manifest this command drives has to exist, or the command silently checks
    /// nothing — which is the failure mode the exclusion already risks.
    #[test]
    fn the_excluded_manifest_is_where_this_command_expects_it() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("the workspace root is two levels above this crate");
        assert!(
            root.join(MANIFEST).is_file(),
            "{MANIFEST} is missing; `cargo xtask ai-api` would check nothing"
        );
    }

    /// And it really is excluded. If somebody adds it back to `members`, this command
    /// becomes redundant and the exclusion's whole reason has quietly gone.
    #[test]
    fn the_crate_is_still_excluded_from_the_workspace() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("the workspace root is two levels above this crate");
        let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("root manifest");
        let parsed: toml::Table = manifest.parse().expect("root manifest is valid TOML");

        let excluded = parsed
            .get("workspace")
            .and_then(|workspace| workspace.get("exclude"))
            .and_then(toml::Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .any(|entry| entry == "crates/codepack-ai-api")
            })
            .unwrap_or(false);

        assert!(
            excluded,
            "crates/codepack-ai-api must stay in workspace.exclude — see Q41"
        );
    }
}
