//! `23_refactoring_opportunities.md`, ported from legacy
//! `reports/insights/refactoring.py::write_refactoring_opportunities_report`. Reuses
//! [`crate::graph::collect`] for its inbound/outbound dependency-count signals — the
//! same shared primitive `14_dependency_graph.md` and `16_key_files_report.md` consume
//! (see `graph.rs`'s module doc for the full reuse list).

use std::path::Path;

use crate::context::ReportContext;
use crate::error::ReportError;
use crate::graph::collect;
use crate::paths::to_native_path;
use crate::plugin::ReportJob;
use crate::profile;
use crate::reports::layout::SOURCE_CODE_EXTENSIONS;
use crate::text::read_text_unredacted;
use crate::wordscan::{CODE_MARKERS, UI_INFRA_SYMBOLS, contains_word};

pub const JOB: ReportJob = ReportJob {
    filename: "23_refactoring_opportunities.md",
    profiles: profile::REFACTORING_OPPORTUNITIES_MD,
    description: "Prioritized refactoring candidates derived from size, dependency fan-in/out, and TODO markers.",
    run: write_refactoring_opportunities_report,
};

const RESULT_LIMIT: usize = 80;

struct Opportunity<'a> {
    score: i64,
    relative_path: &'a str,
    reasons: Vec<String>,
    suggestions: Vec<String>,
}

fn write_refactoring_opportunities_report(
    ctx: &ReportContext<'_>,
    output_file: &Path,
) -> Result<(), ReportError> {
    let graph = collect(ctx);
    let imported_by = graph.in_degree();
    let max_bytes = ctx.config.effective_max_text_file_bytes();

    let mut opportunities: Vec<Opportunity<'_>> = Vec::new();

    for file in &ctx.inventory.files {
        if !SOURCE_CODE_EXTENSIONS.contains(&file.extension.as_str()) {
            continue;
        }
        let native = to_native_path(&file.relative_path);
        if !codepack_scanner::should_consider_text_file(&native) {
            continue;
        }
        let Some(text) = read_text_unredacted(&ctx.staging_root.join(&native), max_bytes) else {
            continue;
        };

        let line_count = text.lines().count();
        let mut score = 0i64;
        let mut reasons = Vec::new();
        let mut suggestions: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

        if line_count >= 500 {
            score += 40;
            reasons.push(format!("very large file ({line_count} lines)"));
            suggestions
                .insert("split by responsibility into smaller modules/components".to_string());
        } else if line_count >= 300 {
            score += 25;
            reasons.push(format!("large file ({line_count} lines)"));
            suggestions.insert(
                "review whether UI, orchestration, and pure helpers can be separated".to_string(),
            );
        }

        let inbound = imported_by
            .get(file.relative_path.as_str())
            .copied()
            .unwrap_or(0);
        let outbound = graph
            .edges
            .get(file.relative_path.as_str())
            .map(|targets| targets.len())
            .unwrap_or(0);
        if inbound >= 5 {
            score += (inbound as i64 * 5).min(35);
            reasons.push(format!(
                "central dependency imported by {inbound} internal file(s)"
            ));
            suggestions.insert(
                "keep public functions stable; extract volatile logic behind small interfaces"
                    .to_string(),
            );
        }
        if outbound >= 10 {
            score += 20;
            reasons.push(format!("high outgoing dependency count ({outbound})"));
            suggestions
                .insert("group related dependencies behind service/helper modules".to_string());
        }
        if contains_word(&text, CODE_MARKERS) {
            score += 8;
            reasons.push("contains technical-debt markers".to_string());
            suggestions.insert("convert repeated TODO/FIXME items into tracked tasks".to_string());
        }
        let lower_rel = file.relative_path.to_lowercase();
        if lower_rel.contains("ui") && contains_word(&text, UI_INFRA_SYMBOLS) {
            score += 25;
            reasons.push(
                "UI code contains infrastructure or worker orchestration concerns".to_string(),
            );
            suggestions.insert(
                "move long-running work and file-system operations behind service/worker classes"
                    .to_string(),
            );
        }

        if score > 0 {
            opportunities.push(Opportunity {
                score,
                relative_path: file.relative_path.as_str(),
                reasons,
                suggestions: suggestions.into_iter().collect(),
            });
        }
    }

    opportunities.sort_by(|a, b| {
        b.score.cmp(&a.score).then_with(|| {
            a.relative_path
                .to_lowercase()
                .cmp(&b.relative_path.to_lowercase())
        })
    });

    let mut out = String::new();
    out.push_str("# Refactoring Opportunities\n\n");
    out.push_str(&format!("Generated: {}\n\n", ctx.plan.generated_at));
    out.push_str(
        "This report translates metrics and dependency signals into practical refactoring candidates.\n\n",
    );

    if opportunities.is_empty() {
        out.push_str(
            "No significant refactoring opportunities detected by the current heuristic rules.\n",
        );
    } else {
        for opportunity in opportunities.iter().take(RESULT_LIMIT) {
            out.push_str(&format!("## `{}`\n\n", opportunity.relative_path));
            out.push_str(&format!("Priority score: **{}**\n\n", opportunity.score));
            out.push_str("Reasons:\n");
            for reason in &opportunity.reasons {
                out.push_str(&format!("- {reason}\n"));
            }
            out.push_str("\nSuggested actions:\n");
            for suggestion in &opportunity.suggestions {
                out.push_str(&format!("- {suggestion}\n"));
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
    fn flags_a_very_large_file_with_a_priority_score() {
        let body = (0..520)
            .map(|i| format!("x{i} = {i}\n"))
            .collect::<String>();
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("big.py"), body).unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_refactoring_opportunities_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.starts_with("# Refactoring Opportunities"));
        assert!(content.contains("## `big.py`"));
        assert!(content.contains("very large file (520 lines)"));
        assert!(content.contains("split by responsibility into smaller modules/components"));
    }

    #[test]
    fn flags_a_central_dependency_imported_by_many_files() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("utils.py"), "").unwrap();
            for i in 0..5 {
                std::fs::write(root.join(format!("m{i}.py")), "import utils\n").unwrap();
            }
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_refactoring_opportunities_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("central dependency imported by 5 internal file(s)"));
    }

    #[test]
    fn reports_no_opportunities_for_a_small_clean_project() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("main.py"), "print('hi')\n").unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_refactoring_opportunities_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("No significant refactoring opportunities detected"));
    }
}
