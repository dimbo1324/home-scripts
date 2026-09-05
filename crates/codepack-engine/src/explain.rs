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

fn default_reason(verdict: &str) -> &'static str {
    if verdict == VERDICT_INCLUDED {
        "included by the current profile and safe mode"
    } else {
        "excluded by the current profile and safe mode"
    }
}

/// Accepts an absolute path, a path relative to the project, or the backslash-joined
/// form the plan itself stores — all three name the same file, and a user copying a
/// path out of `manifest.json` should not have to translate it.
fn relative_to_project(root: &Path, requested: &Path) -> Result<PathBuf> {
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
fn resolve_through_existing_ancestor(path: &Path) -> Result<PathBuf> {
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
fn plan_spelling(relative: &Path) -> String {
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
fn skipped_directory_on_path(skipped_dirs: &[String], relative: &Path) -> Option<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn project() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src").join("main.rs"), "fn main() {}\n").unwrap();
        std::fs::create_dir_all(dir.path().join("node_modules").join("left-pad")).unwrap();
        std::fs::write(
            dir.path()
                .join("node_modules")
                .join("left-pad")
                .join("index.js"),
            "module.exports = 1;\n",
        )
        .unwrap();
        std::fs::write(dir.path().join(".env"), "API_KEY=abcdef0123456789\n").unwrap();
        dir
    }

    fn explain(dir: &Path, file: &str) -> FileExplanation {
        explain_file(dir, &Config::default(), Path::new(file)).unwrap()
    }

    #[test]
    fn a_planned_file_is_included_and_says_so() {
        let dir = project();
        let answer = explain(dir.path(), "src/main.rs");

        assert_eq!(answer.verdict, VERDICT_INCLUDED);
        assert!(answer.exists_on_disk);
        assert!(!answer.reason.is_empty());
        assert!(answer.size.is_some());
        assert_eq!(answer.file, r"src\main.rs");
    }

    /// The answer a user chasing a missing file actually needs: not "it is not in the
    /// plan" but "it is under a directory the walk skipped".
    #[test]
    fn a_file_under_a_skipped_directory_names_that_directory() {
        let dir = project();
        let answer = explain(dir.path(), "node_modules/left-pad/index.js");

        assert_eq!(answer.verdict, VERDICT_NOT_PLANNED);
        assert!(answer.exists_on_disk);
        assert!(
            answer.skipped_directory.is_some(),
            "expected a named directory, got {answer:?}"
        );
        assert!(answer.reason.contains("skipped"));
    }

    /// A typo and a deliberately unvisited file both come back `not_planned`, so the
    /// existence flag is what tells them apart.
    #[test]
    fn a_file_that_is_not_there_is_distinguishable_from_one_that_was_skipped() {
        let dir = project();
        let answer = explain(dir.path(), "src/nope.rs");

        assert_eq!(answer.verdict, VERDICT_NOT_PLANNED);
        assert!(!answer.exists_on_disk);
        assert!(answer.skipped_directory.is_none());
        assert!(answer.reason.contains("no such file"));
    }

    #[test]
    fn a_sensitive_file_is_excluded_under_the_default_safe_mode() {
        let dir = project();
        let answer = explain(dir.path(), ".env");

        assert_eq!(answer.verdict, VERDICT_EXCLUDED);
        assert!(!answer.reason.is_empty());
    }

    /// All three spellings name the same file: a user copying a path out of
    /// `manifest.json` should not have to translate it.
    #[test]
    fn every_spelling_of_a_path_reaches_the_same_answer() {
        let dir = project();
        let relative = explain(dir.path(), "src/main.rs");
        let plan_spelled = explain(dir.path(), r"src\main.rs");
        let dotted = explain(dir.path(), "./src/main.rs");
        let absolute = explain_file(
            dir.path(),
            &Config::default(),
            &dir.path().join("src").join("main.rs"),
        )
        .unwrap();

        for other in [plan_spelled, dotted, absolute] {
            assert_eq!(other.file, relative.file);
            assert_eq!(other.verdict, relative.verdict);
        }
    }

    #[test]
    fn a_path_outside_the_project_is_refused_rather_than_answered() {
        let dir = project();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("stranger.rs"), "\n").unwrap();

        let error = explain_file(
            dir.path(),
            &Config::default(),
            &outside.path().join("stranger.rs"),
        )
        .unwrap_err();
        assert!(matches!(error, EngineError::Explain(_)), "{error:?}");
    }

    #[test]
    fn the_configuration_it_answered_with_is_reported_back() {
        let dir = project();
        let config = Config {
            export_profile: "minimal".to_string(),
            ..Config::default()
        };
        let answer = explain_file(dir.path(), &config, Path::new("src/main.rs")).unwrap();

        assert_eq!(answer.profile, "minimal");
        assert_eq!(answer.safe_mode, config.normalized_safe_export_mode());
        assert!(!answer.diff_mode.is_empty());
    }

    #[test]
    fn explaining_writes_nothing() {
        let dir = project();
        let before = std::fs::read_dir(dir.path()).unwrap().count();
        let _ = explain(dir.path(), "src/main.rs");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), before);
    }

    #[test]
    fn the_default_reason_depends_on_the_verdict() {
        assert!(default_reason(VERDICT_INCLUDED).contains("included"));
        assert!(default_reason(VERDICT_EXCLUDED).contains("excluded"));
    }

    // --- The path helpers -------------------------------------------------------------
    //
    // Moved here from `codepack-cli` on 2026-09-05, along with the code they exercise.
    // They had been reaching into this module's internals from another crate, which is
    // what kept those internals public.
    #[test]
    fn a_directory_whose_name_contains_parentheses_still_explains_its_files() {
        // `skipped_dirs` entries are display strings — `.\dir (reason)` — so splitting
        // one on `" ("` would truncate a directory that is itself named `x (v2)` and
        // lose the answer entirely.
        let skipped = vec![".\\my folder (v2)".to_string()];
        assert_eq!(
            skipped_directory_on_path(&skipped, Path::new("my folder (v2)/a.txt")),
            Some(".\\my folder (v2)".to_string())
        );
    }
    #[test]
    fn a_skipped_directory_with_a_reason_is_matched_by_its_path_not_its_text() {
        let skipped = vec![".\\vendor (.exportignore/custom directory rule: vendor)".to_string()];
        assert!(
            skipped_directory_on_path(&skipped, Path::new("vendor/lib/x.go")).is_some(),
            "the parenthesised reason form must still match"
        );
        assert!(
            skipped_directory_on_path(&skipped, Path::new("vendors/lib/x.go")).is_none(),
            "a longer sibling name must not match"
        );
    }
    #[test]
    fn an_absolute_path_that_does_not_exist_still_gets_an_answer() {
        // The root is canonical in production while the user's spelling need not be,
        // and a missing path cannot be canonicalized to match — a case difference must
        // not turn "no such file" into a hard error.
        let dir = tempfile::tempdir().unwrap();
        let root = codepack_core::canonicalize_existing(dir.path()).unwrap();
        let shouted = PathBuf::from(root.to_string_lossy().to_uppercase()).join("src/nope.rs");

        let relative = relative_to_project(&root, &shouted).unwrap();
        assert_eq!(plan_spelling(&relative), "src\\nope.rs");
    }
    #[test]
    fn the_project_root_itself_is_refused_in_every_spelling() {
        let dir = project();
        for spelling in [".", "./", ""] {
            assert!(
                relative_to_project(dir.path(), Path::new(spelling)).is_err(),
                "`{spelling}` names the project root, not a file"
            );
        }
    }
    /// Regression for the CI failure of 2026-07-29: on the GitHub Windows runner the
    /// project root arrived as `C:\Users\RUNNER~1\…` (an 8.3 short name) while the
    /// canonicalized file was `C:\Users\runneradmin\…`, and the two did not match. The
    /// fix resolves both sides the same way, so this asserts on the helper rather than
    /// on a machine that happens to have short names enabled.
    #[test]
    fn both_sides_of_the_comparison_are_resolved_the_same_way() {
        let dir = project();
        let raw = dir.path();
        let canonical = codepack_core::canonicalize_existing(raw).unwrap();

        // Whichever spelling the caller has, the answer is the same file.
        let from_raw = relative_to_project(raw, &canonical.join("src/main.rs")).unwrap();
        let from_canonical = relative_to_project(&canonical, &raw.join("src/main.rs")).unwrap();

        assert_eq!(plan_spelling(&from_raw), "src\\main.rs");
        assert_eq!(plan_spelling(&from_canonical), "src\\main.rs");
    }
    #[test]
    fn a_missing_tail_is_kept_verbatim_while_its_existing_ancestor_is_resolved() {
        let dir = project();
        let resolved = resolve_through_existing_ancestor(&dir.path().join("src/deep/nope.rs"));

        let resolved = resolved.unwrap();
        assert!(resolved.ends_with("src/deep/nope.rs"), "{resolved:?}");
        assert!(
            resolved.starts_with(codepack_core::canonicalize_existing(dir.path()).unwrap()),
            "the existing ancestor should have been canonicalized: {resolved:?}"
        );
    }
}
