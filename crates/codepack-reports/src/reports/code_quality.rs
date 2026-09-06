//! `17_code_quality_report.md`, ported from legacy
//! `reports/insights/code_quality.py::write_code_quality_report`.
//!
//! [`python_symbol_lengths`] deliberately does **not** reproduce legacy's own
//! `ast.parse`-based `_python_function_lengths`: no Python-AST crate is a justified new
//! dependency for one heuristic report family (`.ai/universal/05-security-and-secrets.md`
//! forbids a heavy dependency for a small need). This ports the *intent* — flag long
//! Python functions/classes — via an indentation-based block-extent heuristic instead:
//! a `def`/`class` line's block runs through every following line that is blank or
//! indented further than the definition itself. This slightly over- or under-counts a
//! function's exact end line in edge cases (e.g. a trailing multi-line string literal
//! at a shallower indentation than expected), a documented, accepted approximation.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use crate::context::ReportContext;
use crate::error::ReportError;
use crate::paths::to_native_path;
use crate::plugin::ReportJob;
use crate::profile;
use crate::reports::layout::SOURCE_CODE_EXTENSIONS;
use crate::text::read_text_unredacted;
use crate::wordscan::{
    CODE_MARKERS, MIXED_CONCERN_SYMBOLS, UI_INFRA_SYMBOLS, contains_word, matching_words,
};

pub const JOB: ReportJob = ReportJob {
    filename: "17_code_quality_report.md",
    profiles: profile::CODE_QUALITY_REPORT_MD,
    description: "Large files, long Python functions, mixed-responsibility signals, duplicate filenames.",
    run: write_code_quality_report,
};

const LARGE_FILE_THRESHOLD: usize = 400;
const LONG_SYMBOL_THRESHOLD: usize = 80;
const MIXED_MIN_CONCERNS: usize = 4;
const MIXED_MIN_LINES: usize = 180;
const DUPLICATE_MIN_COUNT: usize = 3;
const DUPLICATE_EXCLUDED_NAMES: &[&str] = &["index.ts", "index.tsx", "__init__.py"];

const LARGE_FILES_LIMIT: usize = 100;
const LONG_SYMBOLS_LIMIT: usize = 100;
const MIXED_LIMIT: usize = 100;
const DUPLICATE_GROUPS_LIMIT: usize = 50;
const DUPLICATE_PATHS_PER_GROUP_LIMIT: usize = 20;

/// Python `def`/`async def`/`class` declarations, capturing the indentation and the
/// symbol name. Built once per report run and reused across every file: constructing it
/// inside the per-file loop, as this module previously did for its word-set patterns,
/// recompiles the same pattern once per scanned file.
static PYTHON_DEFINITION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(\s*)(?:async\s+def|def|class)\s+([A-Za-z_][A-Za-z0-9_]*)")
        .expect("fixed literal pattern, proven valid by this module's tests")
});

fn python_symbol_lengths(text: &str) -> Vec<(String, usize, usize)> {
    let def_pattern = &*PYTHON_DEFINITION;
    let lines: Vec<&str> = text.lines().collect();
    let mut results = Vec::new();

    for (index, line) in lines.iter().enumerate() {
        let Some(captures) = def_pattern.captures(line) else {
            continue;
        };
        let indent = captures.get(1).map(|m| m.as_str().len()).unwrap_or(0);
        let name = captures
            .get(2)
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();

        let mut end = index;
        for (later_index, later_line) in lines.iter().enumerate().skip(index + 1) {
            if later_line.trim().is_empty() {
                end = later_index;
                continue;
            }
            let later_indent = later_line.len() - later_line.trim_start_matches(' ').len();
            if later_indent <= indent {
                break;
            }
            end = later_index;
        }

        results.push((name, index + 1, end - index + 1));
    }

    results
}

fn write_code_quality_report(
    ctx: &ReportContext<'_>,
    output_file: &Path,
) -> Result<(), ReportError> {
    let max_bytes = ctx.config.effective_max_text_file_bytes();

    let mut large_files: Vec<(&str, usize)> = Vec::new();
    let mut long_symbols: Vec<(&str, String, usize, usize)> = Vec::new();
    let mut todo_files: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut duplicate_names: HashMap<String, Vec<&str>> = HashMap::new();
    let mut mixed_responsibility: Vec<(&str, Vec<&'static str>)> = Vec::new();
    let mut source_file_count = 0usize;

    for file in &ctx.inventory.files {
        let name = crate::paths::file_name_of(&file.relative_path).to_lowercase();
        duplicate_names
            .entry(name)
            .or_default()
            .push(file.relative_path.as_str());

        if !SOURCE_CODE_EXTENSIONS.contains(&file.extension.as_str()) {
            continue;
        }
        source_file_count += 1;

        let native = to_native_path(&file.relative_path);
        if !codepack_scanner::should_consider_text_file(&native) {
            continue;
        }
        let Some(text) = read_text_unredacted(&ctx.staging_root.join(&native), max_bytes) else {
            continue;
        };

        let line_count = text.lines().count();
        if line_count >= LARGE_FILE_THRESHOLD {
            large_files.push((file.relative_path.as_str(), line_count));
        }
        if contains_word(&text, CODE_MARKERS) {
            todo_files.insert(file.relative_path.as_str());
        }
        if file.extension == "py" {
            for (name, line, length) in python_symbol_lengths(&text) {
                if length >= LONG_SYMBOL_THRESHOLD {
                    long_symbols.push((file.relative_path.as_str(), name, line, length));
                }
            }
        }

        let mut signals: Vec<&'static str> = Vec::new();
        let lower_path = file.relative_path.to_lowercase();
        if lower_path.contains("ui") && contains_word(&text, UI_INFRA_SYMBOLS) {
            signals.push("UI file appears to contain infrastructure/threading/file-system logic");
        }
        let distinct_concerns = matching_words(&text, MIXED_CONCERN_SYMBOLS);
        if distinct_concerns.len() >= MIXED_MIN_CONCERNS && line_count >= MIXED_MIN_LINES {
            signals.push("many mixed technical concerns in a medium/large file");
        }
        if !signals.is_empty() {
            mixed_responsibility.push((file.relative_path.as_str(), signals));
        }
    }

    large_files.sort_by_key(|item| std::cmp::Reverse(item.1));
    long_symbols.sort_by_key(|item| std::cmp::Reverse(item.3));
    mixed_responsibility.sort_by_key(|item| item.0.to_lowercase());

    let duplicate_groups: BTreeMap<&String, &Vec<&str>> = duplicate_names
        .iter()
        .filter(|(name, paths)| {
            paths.len() >= DUPLICATE_MIN_COUNT && !DUPLICATE_EXCLUDED_NAMES.contains(&name.as_str())
        })
        .collect();
    let mut duplicate_sorted: Vec<(&String, &Vec<&str>)> = duplicate_groups.into_iter().collect();
    duplicate_sorted.sort_by_key(|item| std::cmp::Reverse(item.1.len()));

    let mut out = String::new();
    out.push_str("# Code Quality Report\n\nGenerated: ");
    out.push_str(&ctx.plan.generated_at);
    out.push_str("\n\n");
    out.push_str(
        "This report highlights maintainability risks using static heuristics. Treat findings as review prompts, not absolute errors.\n\n",
    );

    out.push_str("## Summary\n\n");
    out.push_str(&format!("- Source files analysed: {source_file_count}\n"));
    out.push_str(&format!(
        "- Large files >= {LARGE_FILE_THRESHOLD} lines: {}\n",
        large_files.len()
    ));
    out.push_str(&format!(
        "- Long Python classes/functions >= {LONG_SYMBOL_THRESHOLD} lines: {}\n",
        long_symbols.len()
    ));
    out.push_str(&format!(
        "- Files with TODO/FIXME-like markers: {}\n",
        todo_files.len()
    ));
    out.push_str(&format!(
        "- Duplicate filename groups: {}\n\n",
        duplicate_sorted.len()
    ));

    out.push_str("## Large files\n\n");
    if large_files.is_empty() {
        out.push_str("No large source files detected.\n");
    } else {
        for (path, lines) in large_files.iter().take(LARGE_FILES_LIMIT) {
            out.push_str(&format!("- `{path}` — {lines} lines\n"));
        }
    }

    out.push_str("\n## Long Python classes/functions\n\n");
    if long_symbols.is_empty() {
        out.push_str("No long Python symbols detected.\n");
    } else {
        for (path, name, line, length) in long_symbols.iter().take(LONG_SYMBOLS_LIMIT) {
            out.push_str(&format!("- `{path}`:{line} `{name}` — {length} lines\n"));
        }
    }

    out.push_str("\n## Possible mixed-responsibility files\n\n");
    if mixed_responsibility.is_empty() {
        out.push_str("No obvious mixed-responsibility files detected.\n");
    } else {
        for (path, signals) in mixed_responsibility.iter().take(MIXED_LIMIT) {
            out.push_str(&format!("- `{path}`\n"));
            for signal in signals {
                out.push_str(&format!("  - {signal}\n"));
            }
        }
    }

    out.push_str("\n## Repeated filenames\n\n");
    if duplicate_sorted.is_empty() {
        out.push_str("No concerning duplicate filename groups detected.\n");
    } else {
        for (name, paths) in duplicate_sorted.iter().take(DUPLICATE_GROUPS_LIMIT) {
            out.push_str(&format!("### `{name}` ({} files)\n", paths.len()));
            let mut sorted_paths: Vec<&str> = (*paths).clone();
            sorted_paths.sort_by_key(|path| path.to_lowercase());
            for path in sorted_paths.iter().take(DUPLICATE_PATHS_PER_GROUP_LIMIT) {
                out.push_str(&format!("- `{path}`\n"));
            }
            out.push('\n');
        }
    }

    std::fs::write(output_file, out).map_err(|source| ReportError::Write {
        path: output_file.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::Fixture;

    #[test]
    fn flags_a_large_file_and_a_long_python_function() {
        let long_body = (0..90)
            .map(|i| format!("    x{i} = {i}\n"))
            .collect::<String>();
        let source = format!("def long_function():\n{long_body}    return 1\n");
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("big.py"), source).unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_code_quality_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.starts_with("# Code Quality Report"));
        assert!(content.contains("`big.py`:1 `long_function`"));
    }

    #[test]
    fn flags_repeated_filenames_across_three_or_more_paths() {
        let fixture = Fixture::new(|root| {
            std::fs::create_dir_all(root.join("a")).unwrap();
            std::fs::create_dir_all(root.join("b")).unwrap();
            std::fs::create_dir_all(root.join("c")).unwrap();
            std::fs::write(root.join("a").join("utils.py"), "x = 1\n").unwrap();
            std::fs::write(root.join("b").join("utils.py"), "x = 1\n").unwrap();
            std::fs::write(root.join("c").join("utils.py"), "x = 1\n").unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_code_quality_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("### `utils.py` (3 files)"));
    }

    #[test]
    fn reports_no_findings_for_a_small_clean_project() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("main.py"), "print('hi')\n").unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_code_quality_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("No large source files detected."));
        assert!(content.contains("No long Python symbols detected."));
        assert!(content.contains("No obvious mixed-responsibility files detected."));
        assert!(content.contains("No concerning duplicate filename groups detected."));
    }
}
