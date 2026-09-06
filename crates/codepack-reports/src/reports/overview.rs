//! `PROJECT_OVERVIEW.html` (BLUEPRINT §B.9, stage S12): a standalone, human-readable
//! answer to "what is this project, how healthy is it, and where are the risks" for a
//! tech lead, a stakeholder, or anyone who has never opened the code. No legacy
//! equivalent exists — legacy's own human-report support was HTML-dashboard-only
//! (`docs/__arch__/BLUEPRINT.md` §B.9 rates PDF support "partial").
//!
//! **No PDF library, permanently.** The bundle stays dependency-light and this page
//! stays fully offline; a reader who wants a PDF uses their browser's own Print
//! dialog, which every modern browser already supports. `@media print` below tunes the
//! result (removes the "how to print this" hint, lets colors survive to paper), so the
//! feature this stage promises is real, not a placeholder for a future crate.
//!
//! Self-contained on purpose, same shape as [`crate::reports::dashboard`]: inline
//! `<style>`, zero remote references, opens correctly from a plain `file://` URL with
//! no network at all (invariant I1's spirit, applied to generated output as well as to
//! this crate's own code).

use std::path::Path;

use crate::context::ReportContext;
use crate::error::ReportError;
use crate::html::escape_html;
use crate::humanize::{self, PlainLanguageSummary, RiskHighlight, StartingPoint};
use crate::plugin::ReportJob;
use crate::profile;

pub const JOB: ReportJob = ReportJob {
    filename: "PROJECT_OVERVIEW.html",
    profiles: profile::PROJECT_OVERVIEW_HTML,
    description: "Plain-language project overview for a reader with no code access: what it is, how healthy it is, where the risks are.",
    run: write_project_overview,
};

fn write_project_overview(ctx: &ReportContext<'_>, output_file: &Path) -> Result<(), ReportError> {
    let summary = humanize::summarize(ctx);
    let html = render(&summary);
    std::fs::write(output_file, html).map_err(|source| ReportError::Write {
        path: output_file.to_path_buf(),
        source,
    })
}

fn render(summary: &PlainLanguageSummary) -> String {
    let stack_line = if summary.stack.is_empty() {
        "no specific stack detected".to_string()
    } else {
        summary.stack.join(", ")
    };

    let security_line = match (summary.total_findings, summary.potential_secrets) {
        (Some(0), Some(_secrets)) => "The security scan found nothing to flag.".to_string(),
        (Some(total), Some(secrets)) => format!(
            "The security scan flagged {total} item(s), including {secrets} potential secret(s) — all redacted in the full security report."
        ),
        _ => "This export did not run a security scan.".to_string(),
    };

    let risks_html = if summary.risks.is_empty() {
        "<p>No specific risks stood out from the automated checks.</p>".to_string()
    } else {
        let items: String = summary.risks.iter().map(risk_item).collect();
        format!("<ul class=\"risks\">{items}</ul>")
    };

    let starting_points_html = if summary.starting_points.is_empty() {
        "<p>No individual files stood out as a clear starting point.</p>".to_string()
    } else {
        let items: String = summary
            .starting_points
            .iter()
            .map(starting_point_item)
            .collect();
        format!("<ol class=\"starting-points\">{items}</ol>")
    };

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{
  color-scheme: light dark;
  --bg: #f6f7fb;
  --fg: #1f2937;
  --muted: #667085;
  --card: #ffffff;
  --border: #d9dee8;
  --accent: #0f766e;
  --danger: #b91c1c;
  --warning: #b45309;
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --bg: #111827;
    --fg: #e5e7eb;
    --muted: #a3aab8;
    --card: #182033;
    --border: #2b364d;
    --accent: #5eead4;
    --danger: #fca5a5;
    --warning: #fcd34d;
  }}
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  padding: 32px;
  background: var(--bg);
  color: var(--fg);
  font-family: "Segoe UI", Arial, sans-serif;
  line-height: 1.6;
}}
main {{ max-width: 820px; margin: 0 auto; }}
h1 {{ margin: 0 0 6px; font-size: 30px; }}
h2 {{ margin: 32px 0 10px; font-size: 20px; }}
.meta {{ margin: 0 0 8px; color: var(--muted); }}
.score {{
  display: inline-flex;
  align-items: baseline;
  gap: 8px;
  font-size: 44px;
  font-weight: 700;
}}
.score small {{ font-size: 16px; font-weight: 400; color: var(--muted); }}
.bar {{
  height: 10px;
  border-radius: 6px;
  background: var(--border);
  overflow: hidden;
  margin: 10px 0 4px;
  max-width: 320px;
}}
.bar-fill {{ height: 100%; background: var(--accent); }}
section.card {{
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 18px 20px;
  background: var(--card);
  margin-bottom: 4px;
}}
ul.risks, ol.starting-points {{ margin: 0; padding-left: 22px; }}
ul.risks li {{ margin: 6px 0; }}
.badge {{
  display: inline-block;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  padding: 2px 7px;
  border-radius: 4px;
  margin-right: 8px;
}}
.badge.high {{ background: var(--danger); color: #fff; }}
.badge.medium {{ background: var(--warning); color: #1f2937; }}
.badge.low {{ background: var(--border); color: var(--fg); }}
.print-hint {{ margin-top: 36px; color: var(--muted); font-size: 13px; }}
code {{ background: rgba(127, 127, 127, 0.15); padding: 1px 5px; border-radius: 4px; }}
@media print {{
  body {{ padding: 0; background: #fff; color: #000; }}
  .print-hint {{ display: none; }}
  section.card {{ border: none; padding: 0; }}
  .bar-fill {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
}}
</style>
</head>
<body>
<main>
<h1>{project_name}</h1>
<p class="meta">{project_type} &middot; {stack_line} &middot; <span class="badge {risk_level}">{risk_level} risk</span></p>

<section class="card">
<h2 style="margin-top:0">Health</h2>
<div class="score">{score}<small>/ 100</small></div>
<div class="bar"><div class="bar-fill" style="width:{score}%"></div></div>
<p>{score_sentence}</p>
</section>

<section class="card">
<h2 style="margin-top:0">What to watch</h2>
{risks_html}
</section>

<section class="card">
<h2 style="margin-top:0">Security</h2>
<p>{security_line}</p>
</section>

<section class="card">
<h2 style="margin-top:0">Where to start reading</h2>
{starting_points_html}
</section>

<section class="card">
<h2 style="margin-top:0">At a glance</h2>
<p>{file_count} file(s), {size_human}.</p>
</section>

<p class="print-hint">To save this page as a PDF, use your browser's Print dialog (Ctrl+P / Cmd+P) and choose "Save as PDF".</p>
</main>
</body>
</html>
"#,
        title = escape_html(&format!("{} — Project Overview", summary.project_name)),
        project_name = escape_html(&summary.project_name),
        project_type = escape_html(&summary.project_type),
        stack_line = escape_html(&stack_line),
        risk_level = escape_html(&summary.risk_level),
        score = summary.health_score.clamp(0, 100),
        score_sentence = escape_html(&score_sentence(summary.health_score)),
        risks_html = risks_html,
        security_line = escape_html(&security_line),
        starting_points_html = starting_points_html,
        file_count = summary.file_count,
        size_human = escape_html(&summary.total_size_human),
    )
}

fn score_sentence(score: i64) -> String {
    if score >= 80 {
        "This project scores well on the automated health checks.".to_string()
    } else if score >= 55 {
        "This project is in reasonable shape, with some areas worth attention.".to_string()
    } else {
        "This project's automated health checks flagged several areas for attention.".to_string()
    }
}

fn risk_item(risk: &RiskHighlight) -> String {
    format!(
        "<li><span class=\"badge {severity}\">{severity}</span>{text}</li>",
        // A fixed identifier from `Severity`, never a value read out of a project.
        severity = risk.severity.as_class(),
        text = escape_html(&risk.text)
    )
}

fn starting_point_item(point: &StartingPoint) -> String {
    format!(
        "<li><code>{path}</code> — {reason}</li>",
        path = escape_html(&point.path),
        reason = escape_html(&point.reason)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::Fixture;

    #[test]
    fn writes_a_self_contained_page_with_no_outbound_references() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("main.py"), "print(1)\n").unwrap();
            std::fs::write(root.join("README.md"), "# demo\n").unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_project_overview(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.starts_with("<!doctype html>"));
        assert!(!content.contains("http://"));
        assert!(!content.contains("https://"));
        assert!(!content.contains("cdn."));
        assert!(content.contains("@media print"));
    }

    #[test]
    fn reflects_the_same_numbers_the_summary_computed() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join(".env"), "KEY=x\n").unwrap();
            std::fs::write(root.join("main.py"), "print(1)\n").unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_project_overview(&ctx, &output_file).unwrap();
        let content = std::fs::read_to_string(&output_file).unwrap();

        let summary = humanize::summarize(&ctx);
        assert!(content.contains(&format!("{}<small>", summary.health_score)));
        for risk in &summary.risks {
            assert!(
                content.contains(&escape_html(&risk.text)),
                "missing risk text: {}",
                risk.text
            );
        }
    }

    #[test]
    fn a_planted_secret_never_reaches_the_overview_page() {
        // Invariant I3, exercised through this specific artifact rather than assumed
        // from humanize.rs's own doc comment.
        let secret = concat!("sk-live-", "ABCDEF1234567890abcdef");
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("config.py"), format!("API_KEY = \"{secret}\"\n")).unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_project_overview(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(
            !content.contains(secret),
            "planted secret leaked into PROJECT_OVERVIEW.html"
        );
    }

    #[test]
    fn no_scan_result_degrades_to_an_honest_sentence_not_a_blank_or_a_panic() {
        // The fixture's own context() always passes scan: None, so this is the default
        // path every other test in this module also exercises — asserted explicitly
        // here rather than left implicit.
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("main.py"), "print(1)\n").unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_project_overview(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("did not run a security scan"));
    }

    #[test]
    fn a_scan_result_is_summarized_by_count_only() {
        use codepack_security::scan::{Finding, FindingKind, ScanResult, ScanSummary};

        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("config.py"), "API_KEY = \"placeholder\"\n").unwrap();
        });
        let base_ctx = fixture.context("full");
        let scan = ScanResult {
            summary: ScanSummary {
                sensitive_files: 0,
                potential_secrets: 1,
                risky_code: 0,
                total_findings: 1,
            },
            findings: vec![Finding {
                kind: FindingKind::PotentialSecret,
                severity: "high".to_string(),
                confidence: "high".to_string(),
                file: ".\\config.py".to_string(),
                line: Some(1),
                rule: "secret_like_line".to_string(),
                message: "API_KEY=<REDACTED>".to_string(),
            }],
        };
        let ctx = ReportContext {
            scan: Some(&scan),
            ..base_ctx
        };
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_project_overview(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("flagged 1 item(s)"));
        assert!(content.contains("1 potential secret(s)"));
        // The finding's own message text must not appear verbatim: this page only
        // ever shows counts (see humanize.rs's own doc comment for why).
        assert!(!content.contains("secret_like_line"));
    }
}
