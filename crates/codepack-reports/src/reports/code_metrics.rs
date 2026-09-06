//! `08_code_metrics.txt`, ported from legacy
//! `reports/insights/metrics.py::write_code_metrics_report`.

use std::path::Path;

use crate::context::ReportContext;
use crate::error::ReportError;
use crate::paths::to_native_path;
use crate::plugin::ReportJob;
use crate::profile;
use crate::reports::layout::{SOURCE_CODE_EXTENSIONS, section_rule};
use crate::text::read_text_unredacted;

pub const JOB: ReportJob = ReportJob {
    filename: "08_code_metrics.txt",
    profiles: profile::CODE_METRICS_TXT,
    description: "LOC, comment ratio, files over 500/1000 lines.",
    run: write_code_metrics_report,
};

fn comment_like_line(stripped: &str, extension: &str) -> bool {
    if stripped.is_empty() {
        return false;
    }
    const PREFIXES: &[&str] = &["//", "/*", "*", "#", "<!--", "--"];
    if PREFIXES.iter().any(|prefix| stripped.starts_with(prefix)) {
        return true;
    }
    extension == "sql" && stripped.starts_with("--")
}

struct FileMetrics {
    relative_path: String,
    extension: String,
    lines: usize,
    code: usize,
}

fn write_code_metrics_report(
    ctx: &ReportContext<'_>,
    output_file: &Path,
) -> Result<(), ReportError> {
    let max_bytes = ctx.config.effective_max_text_file_bytes();
    let mut per_file = Vec::new();
    let mut total_lines = 0usize;
    let mut total_blank = 0usize;
    let mut total_comments = 0usize;
    let mut total_code = 0usize;

    for file in &ctx.inventory.files {
        if !SOURCE_CODE_EXTENSIONS.contains(&file.extension.as_str()) {
            continue;
        }
        let path = ctx.staging_root.join(to_native_path(&file.relative_path));
        let Some(text) = read_text_unredacted(&path, max_bytes) else {
            continue;
        };

        let lines: Vec<&str> = text.lines().collect();
        let mut blank = 0usize;
        let mut comments = 0usize;
        for line in &lines {
            let stripped = line.trim();
            if stripped.is_empty() {
                blank += 1;
            } else if comment_like_line(stripped, &file.extension) {
                comments += 1;
            }
        }
        let code = lines.len().saturating_sub(blank).saturating_sub(comments);

        total_lines += lines.len();
        total_blank += blank;
        total_comments += comments;
        total_code += code;

        per_file.push(FileMetrics {
            relative_path: file.relative_path.clone(),
            extension: file.extension.clone(),
            lines: lines.len(),
            code,
        });
    }

    let mut largest_by_lines: Vec<&FileMetrics> = per_file.iter().collect();
    largest_by_lines.sort_by_key(|item| std::cmp::Reverse(item.lines));
    let over_500: Vec<&FileMetrics> = per_file.iter().filter(|item| item.lines >= 500).collect();
    let over_1000: Vec<&FileMetrics> = per_file.iter().filter(|item| item.lines >= 1000).collect();

    #[derive(Default)]
    struct ExtTotals {
        files: usize,
        lines: usize,
        code: usize,
    }
    let mut by_ext: std::collections::HashMap<String, ExtTotals> = std::collections::HashMap::new();
    for item in &per_file {
        let entry = by_ext.entry(item.extension.clone()).or_default();
        entry.files += 1;
        entry.lines += item.lines;
        entry.code += item.code;
    }
    let mut by_ext_sorted: Vec<(&String, &ExtTotals)> = by_ext.iter().collect();
    by_ext_sorted.sort_by(|a, b| b.1.lines.cmp(&a.1.lines).then_with(|| a.0.cmp(b.0)));

    let mut out = String::new();
    out.push_str("=== Code Metrics ===\n");
    out.push_str(&format!("Generated: {}\n", ctx.plan.generated_at));
    out.push_str("Line classification is heuristic.\n");
    out.push_str(&section_rule('='));
    out.push_str("\n\n");

    out.push_str(&format!(
        "{:<32}: {}\n",
        "Source files analysed",
        per_file.len()
    ));
    out.push_str(&format!("{:<32}: {}\n", "Total lines", total_lines));
    out.push_str(&format!("{:<32}: {}\n", "Code lines", total_code));
    out.push_str(&format!(
        "{:<32}: {}\n",
        "Comment-like lines", total_comments
    ));
    out.push_str(&format!("{:<32}: {}\n", "Blank lines", total_blank));
    out.push_str(&format!(
        "{:<32}: {}\n",
        "Files >= 500 lines",
        over_500.len()
    ));
    out.push_str(&format!(
        "{:<32}: {}\n",
        "Files >= 1000 lines",
        over_1000.len()
    ));

    out.push_str("\n--- Metrics by extension ---\n");
    out.push_str(&format!(
        "{:<16} {:>8} {:>12} {:>12}\n",
        "Ext", "Files", "Lines", "Code"
    ));
    for (extension, totals) in &by_ext_sorted {
        out.push_str(&format!(
            "{:<16} {:>8} {:>12} {:>12}\n",
            extension, totals.files, totals.lines, totals.code
        ));
    }

    out.push_str("\n--- Largest files by line count ---\n");
    for item in largest_by_lines.iter().take(50) {
        out.push_str(&format!(
            "{:>8} lines  code={:>8}  {}\n",
            item.lines, item.code, item.relative_path
        ));
    }

    out.push_str("\n--- Files >= 500 lines ---\n");
    if over_500.is_empty() {
        out.push_str("None detected.\n");
    } else {
        let mut sorted_over_500 = over_500.clone();
        sorted_over_500.sort_by_key(|item| std::cmp::Reverse(item.lines));
        for item in &sorted_over_500 {
            out.push_str(&format!(
                "{:>8} lines  {}\n",
                item.lines, item.relative_path
            ));
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
    fn counts_code_blank_and_comment_lines() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("main.py"), "x = 1\n\n# a comment\ny = 2\n").unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_code_metrics_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.starts_with("=== Code Metrics ==="));
        assert!(content.contains("Total lines"));
        assert!(content.contains("main.py"));
    }

    #[test]
    fn non_source_extensions_are_excluded() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("README.md"), "# hi\n\n\n\n").unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_code_metrics_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains(&format!("{:<32}: 0", "Source files analysed")));
    }

    #[test]
    fn comment_like_line_recognises_common_prefixes() {
        assert!(comment_like_line("// c++ comment", "cpp"));
        assert!(comment_like_line("# python comment", "py"));
        assert!(comment_like_line("-- sql comment", "sql"));
        // Legacy's own `common` tuple already includes "--", so the extra
        // `suffix == "sql"` branch never actually gets exercised in practice — a
        // faithfully-ported quirk, not a gap in this port.
        assert!(comment_like_line("-- not sql", "py"));
        assert!(!comment_like_line("code();", "js"));
        assert!(!comment_like_line("", "py"));
    }
}
