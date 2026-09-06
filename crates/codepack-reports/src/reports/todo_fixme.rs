//! `07_todo_fixme.txt`, ported from legacy
//! `reports/insights/todos.py::write_todo_fixme_report`.

use std::path::Path;

use crate::context::{ReportContext, redact_line};
use crate::error::ReportError;
use crate::paths::to_native_path;
use crate::plugin::ReportJob;
use crate::profile;
use crate::reports::layout::section_rule;
use crate::text::read_text_unredacted;
use crate::wordscan::{CODE_MARKERS, find_word};

pub const JOB: ReportJob = ReportJob {
    filename: "07_todo_fixme.txt",
    profiles: profile::TODO_FIXME_TXT,
    description: "TODO/FIXME/HACK/XXX/DEPRECATED markers.",
    run: write_todo_fixme_report,
};

const FINDINGS_LIMIT: usize = 1000;

struct Finding {
    relative_path: String,
    line_number: usize,
    kind: String,
    text: String,
}

fn write_todo_fixme_report(ctx: &ReportContext<'_>, output_file: &Path) -> Result<(), ReportError> {
    let max_bytes = ctx.config.effective_max_text_file_bytes();
    let mut findings = Vec::new();

    for file in &ctx.inventory.files {
        let native = to_native_path(&file.relative_path);
        if !codepack_scanner::should_consider_text_file(&native) {
            continue;
        }
        let path = ctx.staging_root.join(&native);
        let Some(text) = read_text_unredacted(&path, max_bytes) else {
            continue;
        };
        for (index, line) in text.lines().enumerate() {
            // `find_word` returns the canonical spelling, so a lowercase `todo` in the
            // source is still reported as the `TODO` kind.
            let Some(kind) = find_word(line, CODE_MARKERS) else {
                continue;
            };
            let kind = kind.to_string();
            findings.push(Finding {
                relative_path: file.relative_path.clone(),
                line_number: index + 1,
                kind,
                text: redact_line(line.trim()),
            });
        }
    }

    let mut by_kind: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for finding in &findings {
        *by_kind.entry(finding.kind.clone()).or_insert(0) += 1;
    }
    let mut kind_counts: Vec<(&String, &usize)> = by_kind.iter().collect();
    kind_counts.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));

    let mut out = String::new();
    out.push_str("=== TODO / FIXME / Technical Debt Report ===\n");
    out.push_str(&format!("Generated: {}\n", ctx.plan.generated_at));
    out.push_str(&section_rule('='));
    out.push_str("\n\n");

    out.push_str("--- Summary ---\n");
    if kind_counts.is_empty() {
        out.push_str("No TODO/FIXME-like markers detected.\n");
    } else {
        for (kind, count) in &kind_counts {
            out.push_str(&format!("{kind:<14} {count:>8}\n"));
        }
    }

    out.push_str("\n--- Findings ---\n");
    if findings.is_empty() {
        out.push_str("None.\n");
    } else {
        for finding in findings.iter().take(FINDINGS_LIMIT) {
            out.push_str(&format!(
                "{}:{}: [{}] {}\n",
                finding.relative_path, finding.line_number, finding.kind, finding.text
            ));
        }
        if findings.len() > FINDINGS_LIMIT {
            out.push_str(&format!(
                "... and {} more\n",
                findings.len() - FINDINGS_LIMIT
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
    fn finds_todo_and_fixme_markers_with_line_numbers() {
        let fixture = Fixture::new(|root| {
            std::fs::write(
                root.join("main.py"),
                "print('hi')\n# TODO: refactor this\n# FIXME: broken\n",
            )
            .unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_todo_fixme_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("TODO"));
        assert!(content.contains("FIXME"));
        assert!(content.contains("main.py:2"));
        assert!(content.contains("main.py:3"));
    }

    /// Invariant I3 (`docs/architecture/invariants.md`): a secret quoted on a TODO
    /// line must never reach the report in clear text.
    #[test]
    fn redacts_a_secret_planted_on_a_todo_line() {
        let fixture = Fixture::new(|root| {
            std::fs::write(
                root.join("config.py"),
                "# TODO: rotate API_KEY=sk-super-secret-value\n",
            )
            .unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_todo_fixme_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("TODO"));
        assert!(!content.contains("sk-super-secret-value"));
        assert!(content.contains("<REDACTED>"));
    }

    #[test]
    fn no_markers_detected_yields_none_marker() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("main.py"), "print('hello world')\n").unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_todo_fixme_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("No TODO/FIXME-like markers detected."));
        assert!(content.contains("None.\n"));
    }
}
