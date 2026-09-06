//! `16_key_files_report.md`, ported from legacy
//! `reports/insights/key_files.py::write_key_files_report`/`_score_file`. The scoring
//! rules and weights below are the exact legacy heuristic, not an approximation:
//! entrypoint filename `+40`, important configuration/build file `+25`, "imported by
//! N internal files" boost `min(40, N * 8)`, architecturally important folder `+12`,
//! large file (>= 300 lines) `+18` / medium file (>= 120 lines) `+10`, many
//! imports/references (>= 8) `+10`, many declarations (>= 10) `+10`, and a flat `+5`
//! for a handful of "interesting" source extensions with no accompanying reason text
//! (legacy's own `_score_file` adds that `+5` without an `reasons.append(...)` call
//! either).
//!
//! One deliberate addition beyond legacy, per this stage's task scope: each ranked
//! file's size is shown via [`codepack_tokens::format_bytes`] alongside a rough token
//! estimate via [`codepack_tokens::estimate_tokens_fallback`] — legacy's own report has
//! no size column at all.

use std::collections::BTreeMap;
use std::path::Path;

use codepack_tokens::{estimate_tokens_fallback, format_bytes};
use regex::Regex;

use crate::context::{InventoryFile, ReportContext};
use crate::error::ReportError;
use crate::graph::collect;
use crate::plugin::ReportJob;
use crate::profile;
use crate::text::read_text_unredacted;

pub const JOB: ReportJob = ReportJob {
    filename: "16_key_files_report.md",
    profiles: profile::KEY_FILES_REPORT_MD,
    description: "Ranked important files with reasons (entrypoints, config, import fan-in, size).",
    run: write_key_files_report,
};

const RESULT_LIMIT: usize = 80;

const ENTRYPOINT_NAMES: &[&str] = &[
    "main.py",
    "__main__.py",
    "app.py",
    "server.py",
    "manage.py",
    "main.tsx",
    "main.ts",
    "index.tsx",
    "index.ts",
    "main.go",
];
const CONFIG_NAMES: &[&str] = &[
    "package.json",
    "pyproject.toml",
    "go.mod",
    "Cargo.toml",
    "docker-compose.yml",
    "docker-compose.yaml",
    "Dockerfile",
    "README.md",
];
const CONFIG_PREFIXES: &[&str] = &[
    "vite.config",
    "next.config",
    "eslint.config",
    "tailwind.config",
];
const ARCHITECTURAL_FOLDERS: &[&str] = &[
    "services",
    "api",
    "routes",
    "controllers",
    "stores",
    "domain",
    "core",
    "ui",
];
const INTERESTING_EXTENSIONS: &[&str] = &["py", "ts", "tsx", "js", "jsx", "go", "rs"];

fn import_reference_pattern() -> Regex {
    Regex::new(r"\b(import|from|require\s*\(|include|using)\b").expect("fixed literal")
}

fn class_func_pattern() -> Regex {
    Regex::new(r"\b(class|def|function|const|let|var|interface|type|struct|func)\b")
        .expect("fixed literal")
}

fn score_file(
    file: &InventoryFile,
    imported_by: &BTreeMap<String, usize>,
    max_bytes: Option<u64>,
    staging_root: &Path,
) -> (i64, Vec<String>) {
    let mut score = 0i64;
    let mut reasons: Vec<String> = Vec::new();

    let name = crate::paths::file_name_of(&file.relative_path);
    let rel_parts: Vec<String> = file
        .relative_path
        .split('\\')
        .map(|part| part.to_lowercase())
        .collect();

    if ENTRYPOINT_NAMES.contains(&name) {
        score += 40;
        reasons.push("entrypoint/bootstrap filename".to_string());
    }
    let name_lower = name.to_lowercase();
    if CONFIG_NAMES.contains(&name)
        || CONFIG_PREFIXES
            .iter()
            .any(|prefix| name_lower.starts_with(prefix))
    {
        score += 25;
        reasons.push("important configuration/build file".to_string());
    }
    if let Some(count) = imported_by.get(&file.relative_path).copied()
        && count > 0
    {
        let boost = (count as i64 * 8).min(40);
        score += boost;
        reasons.push(format!("imported by {count} internal file(s)"));
    }
    if rel_parts
        .iter()
        .any(|part| ARCHITECTURAL_FOLDERS.contains(&part.as_str()))
    {
        score += 12;
        reasons.push("located in an architecturally important folder".to_string());
    }

    let native = crate::paths::to_native_path(&file.relative_path);
    if codepack_scanner::should_consider_text_file(&native)
        && let Some(text) = read_text_unredacted(&staging_root.join(&native), max_bytes)
    {
        let line_count = text.lines().count();
        if line_count >= 300 {
            score += 18;
            reasons.push(format!("large file ({line_count} lines)"));
        } else if line_count >= 120 {
            score += 10;
            reasons.push(format!(
                "medium-size implementation file ({line_count} lines)"
            ));
        }
        let import_count = import_reference_pattern().find_iter(&text).count();
        let symbol_count = class_func_pattern().find_iter(&text).count();
        if import_count >= 8 {
            score += 10;
            reasons.push(format!("many imports/references ({import_count})"));
        }
        if symbol_count >= 10 {
            score += 10;
            reasons.push(format!("many declarations ({symbol_count})"));
        }
    }

    if INTERESTING_EXTENSIONS.contains(&file.extension.as_str()) {
        score += 5;
    }

    (score, reasons)
}

/// The same importance ranking `16_key_files_report` publishes, exposed for callers
/// that need to prioritize files rather than render a report — specifically the
/// "fit to budget" selection (BLUEPRINT §B.3), which is required to prioritize "by the
/// ranking that already exists" rather than invent a second, divergent one.
///
/// Returns every file with a positive score, keyed by relative path. Files scoring zero
/// are absent: they carry no positive signal, and the caller decides what to do with
/// the ones the ranking has no opinion about.
pub fn importance_ranking(ctx: &ReportContext<'_>) -> std::collections::BTreeMap<String, i64> {
    let graph = collect(ctx);
    let imported_by = graph.in_degree();
    let max_bytes = ctx.config.effective_max_text_file_bytes();

    ctx.inventory
        .files
        .iter()
        .filter_map(|file| {
            let (score, _reasons) = score_file(file, &imported_by, max_bytes, &ctx.staging_root);
            (score > 0).then_some((file.relative_path.clone(), score))
        })
        .collect()
}

/// Every file with a positive score, ranked highest-first (ties broken by path,
/// case-insensitively) — the same order `16_key_files_report.md` renders in.
///
/// Shared with [`crate::reports::onboarding`], which needs "the top N files to read
/// first" and must agree with the report a reader can open to see the full ranking;
/// two independently-scored top-N lists could silently disagree.
pub(crate) fn ranked_key_files<'a>(
    ctx: &ReportContext<'a>,
) -> Vec<(i64, &'a InventoryFile, Vec<String>)> {
    let graph = collect(ctx);
    let imported_by = graph.in_degree();
    let max_bytes = ctx.config.effective_max_text_file_bytes();

    let mut scored: Vec<(i64, &InventoryFile, Vec<String>)> = ctx
        .inventory
        .files
        .iter()
        .filter_map(|file| {
            let (score, reasons) = score_file(file, &imported_by, max_bytes, &ctx.staging_root);
            (score > 0).then_some((score, file, reasons))
        })
        .collect();
    scored.sort_by(|a, b| {
        b.0.cmp(&a.0).then_with(|| {
            a.1.relative_path
                .to_lowercase()
                .cmp(&b.1.relative_path.to_lowercase())
        })
    });
    scored
}

fn write_key_files_report(ctx: &ReportContext<'_>, output_file: &Path) -> Result<(), ReportError> {
    let scored = ranked_key_files(ctx);

    let project_name = ctx
        .staging_root
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();

    let mut out = String::new();
    out.push_str(&format!("# Key Files Report: {project_name}\n\n"));
    out.push_str(&format!("Generated: {}\n\n", ctx.plan.generated_at));
    out.push_str(
        "This report ranks files by likely importance: entrypoints, configuration files, central imports, size, and architectural location.\n\n",
    );

    if scored.is_empty() {
        out.push_str("No key files were identified.\n");
    } else {
        for (score, file, reasons) in scored.iter().take(RESULT_LIMIT) {
            out.push_str(&format!("## `{}`\n\n", file.relative_path));
            out.push_str(&format!("Score: **{score}**\n\n"));
            out.push_str(&format!(
                "Size: {} (~{} tokens)\n\n",
                format_bytes(file.size),
                estimate_tokens_fallback(file.size)
            ));
            for reason in reasons {
                out.push_str(&format!("- {reason}\n"));
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
    fn scores_entrypoint_above_a_plain_utility_file() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("main.py"), "print('hi')\n").unwrap();
            std::fs::write(root.join("helper.py"), "x = 1\n").unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_key_files_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        let main_pos = content.find("## `main.py`").unwrap();
        let helper_pos = content.find("## `helper.py`").unwrap();
        assert!(main_pos < helper_pos, "entrypoint should rank first");
        assert!(content.contains("entrypoint/bootstrap filename"));
        assert!(content.contains("Size:"));
        assert!(content.contains("tokens"));
    }

    #[test]
    fn boosts_score_for_files_with_high_import_fan_in() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("utils.py"), "").unwrap();
            std::fs::write(root.join("a.py"), "import utils\n").unwrap();
            std::fs::write(root.join("b.py"), "import utils\n").unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_key_files_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("imported by 2 internal file(s)"));
    }

    #[test]
    fn reports_no_key_files_when_nothing_scores_above_zero() {
        let fixture = Fixture::new(|_root| {});
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_key_files_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("No key files were identified."));
    }
}
