//! Why one file did, or did not, end up in an export.
//!
//! ## Why this is here rather than in a front end
//!
//! It began in `codepack-cli`, which meant the desktop application could not answer the
//! question at all — its preview tree shows a short reason per excluded file and stops
//! there. The answer itself is a fact about the export plan, and the plan is this
//! crate's; what each front end owns is how it resolved the configuration it asked
//! with, and that stays where it belongs. So the verdict lives here and both surfaces
//! ask the same code, rather than two implementations drifting until they disagree
//! about the same file.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

use codepack_core::CancellationToken;
use codepack_core::config::Config;

use crate::error::{EngineError, Result};

/// In the plan and reaching the bundle.
pub const VERDICT_INCLUDED: &str = "included";
pub const VERDICT_EXCLUDED: &str = "excluded";
/// In the plan, but outside the diff selection — so the copy step will skip it and it
/// reaches no bundle. A distinct verdict rather than a flavour of `excluded`, because
/// the fix is different: widen the diff, not the safe mode or the profile.
pub const VERDICT_NOT_IN_DIFF: &str = "not_in_diff";
pub const VERDICT_NOT_PLANNED: &str = "not_planned";

/// One file's fate under one configuration.
///
/// Everything here is derived from the plan. What is deliberately absent is how the
/// caller arrived at the `Config` — that is a front end's own story, told in its own
/// report.
#[derive(Debug, Clone)]
pub struct FileExplanation {
    /// The path as the plan spells it (backslash-joined, relative to the project), so
    /// the answer can be matched against `manifest.json` and the plan by eye.
    pub file: String,
    pub profile: String,
    pub safe_mode: String,
    pub diff_mode: String,
    /// `included`, `excluded`, `not_in_diff`, or `not_planned`.
    pub verdict: &'static str,
    /// The plan's own wording where it has one; otherwise an explanation assembled from
    /// what the plan does record about the path's directories.
    pub reason: String,
    pub group: Option<String>,
    pub severity: Option<String>,
    pub size: Option<u64>,
    /// The skipped directory on this path, when one explains a `not_planned` verdict.
    pub skipped_directory: Option<String>,
    /// Whether the file exists on disk at all. A `not_planned` verdict means something
    /// quite different for a typo than for a file the walk chose not to visit.
    pub exists_on_disk: bool,
}

/// Answers for one file, planning the export but writing nothing.
///
/// `requested` may be absolute, relative to the project, or spelled the way the plan
/// stores it; all three name the same file.
pub fn explain_file(root: &Path, config: &Config, requested: &Path) -> Result<FileExplanation> {
    let relative = relative_to_project(root, requested)?;
    let key = plan_spelling(&relative);
    // `symlink_metadata` rather than `exists()`: the walker never follows a symlink
    // (invariant I7), so reporting "it exists" by dereferencing one would answer about
    // a file outside the tree the plan describes.
    let exists_on_disk = std::fs::symlink_metadata(root.join(&relative)).is_ok();

    // Built exactly the way a preview builds it, and for the same reason: explaining a
    // file must not write a bundle, a report, or a history row.
    let outcome = crate::plan_export(
        root,
        config,
        &HashMap::new(),
        None,
        &CancellationToken::new(),
    )?;
    let plan = &outcome.export_plan;

    // Lowercased rather than `eq_ignore_ascii_case`: this project ships Russian-named
    // artifacts, and Windows folds non-ASCII case too, so an ASCII-only comparison
    // would answer "not in the plan" about a file that is plainly in it.
    let folded_key = key.to_lowercase();
    let planned = plan
        .included_files
        .iter()
        .chain(plan.excluded_files.iter())
        .find(|file| file.relative_path.to_lowercase() == folded_key);

    let mut explanation = FileExplanation {
        file: key.clone(),
        profile: config.normalized_export_profile().to_string(),
        safe_mode: config.normalized_safe_export_mode().to_string(),
        diff_mode: outcome.diff_selection.mode.clone(),
        verdict: VERDICT_NOT_PLANNED,
        reason: String::new(),
        group: None,
        severity: None,
        size: None,
        skipped_directory: None,
        exists_on_disk,
    };

    if let Some(file) = planned {
        explanation.file = file.relative_path.clone();
        // Being in `included_files` is not enough to reach a bundle: under any diff
        // mode but `all`, the copy step further restricts itself to
        // `include_relative_paths`. Reporting "included" for a file the copy will skip
        // would be a confident wrong answer — and the `PR Review` preset makes
        // `uncommitted` an everyday setting.
        let in_diff_selection = outcome
            .include_relative_paths
            .as_ref()
            .is_none_or(|selected| selected.contains(&file.relative_path));

        explanation.verdict = match (file.status.as_str(), in_diff_selection) {
            ("included", true) => VERDICT_INCLUDED,
            ("included", false) => VERDICT_NOT_IN_DIFF,
            _ => VERDICT_EXCLUDED,
        };
        explanation.reason = if explanation.verdict == VERDICT_NOT_IN_DIFF {
            format!(
                "the rules include it, but the `{}` diff selection does not",
                outcome.diff_selection.mode
            )
        } else if file.reason.is_empty() {
            default_reason(explanation.verdict).to_string()
        } else {
            file.reason.clone()
        };
        explanation.group = Some(file.group.clone());
        explanation.severity = Some(file.severity.clone());
        explanation.size = Some(file.size);
        return Ok(explanation);
    }

    // The plan carries no per-file entry for anything under a directory the walk
    // skipped — it never descended. "Your file is under `node_modules`" is the answer
    // the user actually needs, so reconstruct it from `skipped_dirs`.
    if let Some(entry) = skipped_directory_on_path(&plan.skipped_dirs, &relative) {
        explanation.reason = format!("not visited: the directory {entry} was skipped");
        explanation.skipped_directory = Some(entry);
    } else if exists_on_disk {
        explanation.reason =
            "not in the plan: present on disk but not classified by this configuration".to_string();
    } else {
        explanation.reason = "not in the plan: no such file in this project".to_string();
    }
    Ok(explanation)
}

pub fn default_reason(verdict: &str) -> &'static str {
    if verdict == VERDICT_INCLUDED {
        "included by the current profile and safe mode"
    } else {
        "excluded by the current profile and safe mode"
    }
}

/// Accepts an absolute path, a path relative to the project, or the backslash-joined
/// form the plan itself stores — all three name the same file, and a user copying a
/// path out of `manifest.json` should not have to translate it.
pub fn relative_to_project(root: &Path, requested: &Path) -> Result<PathBuf> {
    let text = requested.to_string_lossy().replace('\\', "/");
    let normalized = PathBuf::from(text.trim_start_matches("./"));

    let relative = if normalized.is_absolute() {
        // Both sides are put through the same resolution before being compared. Anything
        // less fails on Windows in ways that are easy to miss: CI caught
        // `C:\Users\runneradmin\…` (the file, canonicalized) not matching
        // `C:\Users\RUNNER~1\…` (the root, as given) — an 8.3 short name, which no
        // amount of case-folding reconciles. The same applies to a junction or a mapped
        // drive on one side only.
        let candidate = resolve_through_existing_ancestor(&normalized)?;
        let base = resolve_through_existing_ancestor(root)?;
        strip_project_prefix(&base, &candidate).ok_or_else(|| {
            EngineError::Explain(format!(
                "{} is not inside {}",
                candidate.display(),
                base.display()
            ))
        })?
    } else {
        normalized
    };

    if relative
        .components()
        .any(|part| part == Component::ParentDir)
    {
        return Err(EngineError::Explain(format!(
            "{} escapes the project directory",
            requested.display()
        )));
    }
    // `.` survives `trim_start_matches("./")` as a `CurDir` component, so an empty
    // `OsStr` is not the only spelling of "the project root" that reaches here.
    if relative
        .components()
        .all(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(EngineError::Explain(
            "name a file to explain, not the project root".to_string(),
        ));
    }
    Ok(relative)
}

/// Canonicalizes as much of `path` as exists, then re-appends the rest verbatim.
///
/// A path that does not exist cannot be canonicalized, and "this file is not in the
/// project" is one of the answers `explain` must be able to give — so refusing to
/// resolve a missing path would turn a legitimate question into an error. Resolving the
/// longest existing ancestor gets the real spelling of every component that is actually
/// on disk (short names expanded, symlinks followed, case as the filesystem stores it)
/// and leaves only the genuinely-absent tail as typed.
pub fn resolve_through_existing_ancestor(path: &Path) -> Result<PathBuf> {
    let mut existing = path;
    let mut tail: Vec<&std::ffi::OsStr> = Vec::new();
    loop {
        if existing.exists() {
            let mut resolved =
                codepack_core::canonicalize_existing(existing).map_err(|source| {
                    EngineError::Explain(format!("cannot resolve {}: {source}", existing.display()))
                })?;
            for part in tail.iter().rev() {
                resolved.push(part);
            }
            return Ok(resolved);
        }
        match (existing.parent(), existing.file_name()) {
            (Some(parent), Some(name)) => {
                tail.push(name);
                existing = parent;
            }
            // Nothing on this path exists, not even its root — nothing to resolve
            // against, so the caller's spelling is the best available answer.
            _ => return Ok(path.to_path_buf()),
        }
    }
}

/// `Path::strip_prefix` compares components byte-wise apart from the drive letter. Both
/// sides reach here already resolved, so this is normally an exact match; the
/// case-folded fallback covers the tail components that did not exist on disk and could
/// therefore not be resolved — `C:\Proj\SRC\nope.rs` must still get the "no such file"
/// answer rather than a hard error.
fn strip_project_prefix(root: &Path, candidate: &Path) -> Option<PathBuf> {
    if let Ok(relative) = candidate.strip_prefix(root) {
        return Some(relative.to_path_buf());
    }

    let root_parts: Vec<String> = root
        .components()
        .map(|part| part.as_os_str().to_string_lossy().to_lowercase())
        .collect();
    let candidate_parts: Vec<_> = candidate.components().collect();
    if candidate_parts.len() < root_parts.len() {
        return None;
    }
    let matches = root_parts
        .iter()
        .zip(candidate_parts.iter())
        .all(|(a, b)| *a == b.as_os_str().to_string_lossy().to_lowercase());
    matches.then(|| candidate_parts[root_parts.len()..].iter().collect())
}

/// The plan stores paths backslash-joined regardless of platform (invariant I5), so a
/// lookup key has to be built the same way rather than by `Path::display`.
pub fn plan_spelling(relative: &Path) -> String {
    relative
        .components()
        .filter_map(|part| match part {
            Component::Normal(text) => Some(text.to_string_lossy().to_string()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\\")
}

/// Finds the skipped directory that contains this path, if any.
///
/// `skipped_dirs` holds already-rendered display strings — `.\node_modules` or
/// `.\node_modules (ignored directory)` — so the structure has to be recovered from
/// presentation. Splitting each entry on `" ("` would be ambiguous the moment a
/// directory is itself named `my folder (v2)`: it would lose the real answer, and could
/// match a *different* directory whose name happens to be the truncated prefix. So the
/// direction is reversed — the path's own ancestors are rendered the way the plan would
/// have rendered them, and an entry matches only if it is that ancestor exactly or that
/// ancestor followed by a parenthesised reason. Both spellings are generated here from
/// the same `format!` the scanner uses, so nothing is parsed at all.
/// Residual ambiguity, named rather than hidden: a project containing both a skipped
/// `build (old)` and a live `build` would, when asked about a *non-existent* file under
/// the live one, be told the skipped sibling explains it. Exact matches are therefore
/// preferred over parenthesised ones, which resolves the case that actually loses an
/// answer (`my folder (v2)` really being skipped); what remains is a wrong explanatory
/// sentence about a file that does not exist, and it costs a structured `SkippedDir` in
/// a contract-frozen artifact to remove entirely.
pub fn skipped_directory_on_path(skipped_dirs: &[String], relative: &Path) -> Option<String> {
    let folded: Vec<String> = skipped_dirs.iter().map(|dir| dir.to_lowercase()).collect();
    let rendered_ancestors = ancestor_renderings(relative);

    for rendered in &rendered_ancestors {
        if let Some(index) = folded.iter().position(|entry| entry == rendered) {
            return Some(skipped_dirs[index].clone());
        }
    }
    for rendered in &rendered_ancestors {
        let with_reason = format!("{rendered} (");
        if let Some(index) = folded
            .iter()
            .position(|entry| entry.starts_with(&with_reason))
        {
            return Some(skipped_dirs[index].clone());
        }
    }
    None
}

/// Each directory on the path, rendered exactly the way `skipped_dirs` renders one, so
/// nothing has to be parsed back out of a display string.
fn ancestor_renderings(relative: &Path) -> Vec<String> {
    let components: Vec<_> = relative.components().collect();
    let mut ancestor = PathBuf::new();
    let mut rendered = Vec::new();
    for part in components.iter().take(components.len().saturating_sub(1)) {
        let Component::Normal(name) = part else {
            continue;
        };
        ancestor.push(name);
        rendered.push(format!(".\\{}", plan_spelling(&ancestor)).to_lowercase());
    }
    rendered
}
