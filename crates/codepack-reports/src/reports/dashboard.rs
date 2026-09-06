//! `REPORT_DASHBOARD.html`, ported from legacy
//! `reports/insights/dashboard.py::write_html_dashboard`: a self-contained HTML page
//! with metric cards and links to the other generated reports.
//!
//! Legacy's own dashboard runs at the analytics pipeline step — **before** archiving
//! (`27_archive_plan.md`, `codepack-archive`, stage S8) and, depending on wiring,
//! possibly before or independent of `28_export_plan.md` (`codepack-scanner`, stage
//! S2). Both are therefore read as best-effort, optional siblings in the same output
//! directory: legacy's own `_read_text` swallows any I/O error (including "does not
//! exist") and returns `""`, so a missing file degrades to the same fallback text as
//! an empty one — `"n/a"` for the health score, `"single"` for the archive strategy
//! (the `"Split planned: \`True\`"` substring search never matches empty text), and
//! the placeholder panel text for the excerpt panes. This module reproduces that
//! exact fallback *behavior*; report content in this crate is English throughout
//! (the precedent set by every other Group A–E report), so the placeholder/title text
//! itself is an English rendering of legacy's Russian original, not a literal
//! translation requirement.
//!
//! **Stage S12 additions** (BLUEPRINT §B.9): an "Explain in plain words" section, built
//! from [`crate::humanize::summarize`] — the same function [`crate::reports::overview`]
//! uses, so the numbers on this page and on `PROJECT_OVERVIEW.html` can never silently
//! disagree — and a client-side search box that filters the report-links list. The
//! filter is a dozen lines of vanilla inline JS operating on elements already in the
//! page; it is not a library, ships no network reference, and needs no build step,
//! matching this file's own self-contained, offline-first shape.

use std::path::Path;

use crate::context::ReportContext;
use crate::error::ReportError;
use crate::html::escape_html;
use crate::humanize;
use crate::plugin::ReportJob;
use crate::profile;

pub const JOB: ReportJob = ReportJob {
    filename: "REPORT_DASHBOARD.html",
    profiles: profile::REPORT_DASHBOARD_HTML,
    description: "Local HTML dashboard for navigating project health, security and export reports.",
    run: write_html_dashboard,
};

const NOT_GENERATED_YET: &str = "Report not generated yet.";

fn read_text_best_effort(path: &Path, limit: usize) -> String {
    match std::fs::read_to_string(path) {
        Ok(text) => text.chars().take(limit).collect(),
        Err(_) => String::new(),
    }
}

fn extract_overall_score(health_report: &Path) -> String {
    let text = read_text_best_effort(health_report, 5_000);
    match text.find("Overall score:") {
        Some(start) => {
            let tail = &text[start..];
            match (tail.find("**"), tail.find("/100**")) {
                (Some(open), Some(close)) if open < close => {
                    let value_start = open + 2;
                    if value_start <= close {
                        format!("{}/100", tail[value_start..close].trim())
                    } else {
                        "n/a".to_string()
                    }
                }
                _ => "n/a".to_string(),
            }
        }
        None => "n/a".to_string(),
    }
}

fn extract_security_summary(security_json: &Path) -> (String, String) {
    let text = match std::fs::read_to_string(security_json) {
        Ok(text) => text,
        Err(_) => return ("n/a".to_string(), "n/a".to_string()),
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) else {
        return ("n/a".to_string(), "n/a".to_string());
    };
    let total = parsed
        .get("summary")
        .and_then(|s| s.get("total_findings"))
        .and_then(|v| v.as_u64())
        .map(|v| v.to_string())
        .unwrap_or_else(|| "n/a".to_string());
    let secrets = parsed
        .get("summary")
        .and_then(|s| s.get("potential_secrets"))
        .and_then(|v| v.as_u64())
        .map(|v| v.to_string())
        .unwrap_or_else(|| "n/a".to_string());
    (total, secrets)
}

fn write_html_dashboard(ctx: &ReportContext<'_>, output_file: &Path) -> Result<(), ReportError> {
    let reports_dir = output_file
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();

    // The same summary PROJECT_OVERVIEW.html renders, so the two pages' numbers can
    // never silently disagree. Computed from ctx directly (Inventory/ScanResult/
    // Config), not from the best-effort sibling-file reads below — no ordering
    // dependency on another job, unlike the health-score/archive-strategy cards.
    let plain_language = humanize::summarize(ctx);

    let health_report = reports_dir.join("22_project_health_report.md");
    let archive_plan = reports_dir.join("27_archive_plan.md");
    let export_plan = reports_dir.join("28_export_plan.md");
    let security_json = reports_dir.join("06_security_scan.json");

    let score = extract_overall_score(&health_report);
    let (total_findings, potential_secrets) = extract_security_summary(&security_json);
    let archive_strategy =
        if read_text_best_effort(&archive_plan, 2_000).contains("Split planned: `True`") {
            "split"
        } else {
            "single"
        };

    let cards = [
        (
            "Project health",
            score,
            "Heuristic maintainability/AI-readiness score",
        ),
        (
            "Security findings",
            total_findings,
            "JSON + SARIF are generated",
        ),
        (
            "Potential secrets",
            potential_secrets,
            "Redacted secret-like lines",
        ),
        (
            "Archive strategy",
            archive_strategy.to_string(),
            "Logical ZIP planning",
        ),
    ];
    let links = [
        ("Project Profile", "PROJECT_PROFILE.json"),
        ("Export Plan", "28_export_plan.md"),
        ("Archive Plan", "27_archive_plan.md"),
        ("Security Scan", "06_security_scan.txt"),
        ("Security JSON", "06_security_scan.json"),
        ("Security SARIF", "06_security_scan.sarif"),
        ("Architecture Map", "24_architecture_map.md"),
        ("Health Report", "22_project_health_report.md"),
        ("AI Context", "AI_CONTEXT/00_PROJECT_OVERVIEW.md"),
        ("Custom Prompt", "AI_PROMPTS/CUSTOM_PROMPT.md"),
        ("Project Overview (plain language)", "PROJECT_OVERVIEW.html"),
        ("Onboarding Guide", "ONBOARDING_GUIDE.md"),
        ("Review Checklist", "REVIEW_CHECKLIST.md"),
    ];

    let card_html: String = cards
        .iter()
        .map(|(title, value, desc)| {
            format!(
                "<section class=\"card\"><div class=\"label\">{}</div><div class=\"value\">{}</div><p>{}</p></section>",
                escape_html(title),
                escape_html(value),
                escape_html(desc)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let link_html: String = links
        .iter()
        .map(|(label, href)| {
            // `data-search` holds the lowercased label the filter box below matches
            // against; kept separate from the visible text so escaping the two never
            // has to stay in sync by hand.
            format!(
                "<li data-search=\"{}\"><a href=\"{}\">{}</a></li>",
                escape_html(&label.to_lowercase()),
                escape_html(href),
                escape_html(label)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let risks_html: String = if plain_language.risks.is_empty() {
        "<p>No specific risks stood out from the automated checks.</p>".to_string()
    } else {
        let items: String = plain_language
            .risks
            .iter()
            .map(|risk| {
                format!(
                    "<li><span class=\"badge {sev}\">{sev}</span>{text}</li>",
                    // A fixed identifier from `Severity`, never project content.
                    sev = risk.severity.as_class(),
                    text = escape_html(&risk.text)
                )
            })
            .collect();
        format!("<ul class=\"risks\">{items}</ul>")
    };
    let stack_line = escape_html(&if plain_language.stack.is_empty() {
        "no specific stack detected".to_string()
    } else {
        plain_language.stack.join(", ")
    });
    let project_name = escape_html(&plain_language.project_name);
    let project_type = escape_html(&plain_language.project_type);
    let health_score = plain_language.health_score.clamp(0, 100);

    let export_plan_excerpt = read_text_best_effort(&export_plan, 6_000);
    let health_excerpt = read_text_best_effort(&health_report, 6_000);
    let export_plan_panel = if export_plan_excerpt.is_empty() {
        NOT_GENERATED_YET.to_string()
    } else {
        escape_html(&export_plan_excerpt)
    };
    let health_panel = if health_excerpt.is_empty() {
        NOT_GENERATED_YET.to_string()
    } else {
        escape_html(&health_excerpt)
    };

    let html = format!(
        r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Project Reports Dashboard</title>
<style>
:root {{
  color-scheme: light dark;
  --bg: #f6f7fb;
  --fg: #1f2937;
  --muted: #667085;
  --card: #ffffff;
  --border: #d9dee8;
  --accent: #0f766e;
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --bg: #111827;
    --fg: #e5e7eb;
    --muted: #a3aab8;
    --card: #182033;
    --border: #2b364d;
    --accent: #5eead4;
  }}
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  padding: 32px;
  background: var(--bg);
  color: var(--fg);
  font-family: "Segoe UI", Arial, sans-serif;
  line-height: 1.5;
}}
main {{ max-width: 1180px; margin: 0 auto; }}
h1 {{ margin: 0 0 6px; font-size: 30px; }}
.meta {{ margin: 0 0 24px; color: var(--muted); }}
.cards {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 14px;
  margin-bottom: 24px;
}}
.card {{ border: 1px solid var(--border); border-radius: 8px; padding: 16px; background: var(--card); }}
.label {{ color: var(--muted); font-size: 13px; }}
.value {{ margin-top: 8px; font-size: 28px; font-weight: 700; }}
.card p {{ margin: 8px 0 0; color: var(--muted); }}
.grid {{ display: grid; grid-template-columns: minmax(220px, 320px) minmax(0, 1fr); gap: 20px; }}
nav, section.panel {{ border: 1px solid var(--border); border-radius: 8px; padding: 18px; background: var(--card); }}
nav ul {{ margin: 0; padding-left: 20px; }}
nav li {{ margin: 7px 0; }}
nav li.hidden {{ display: none; }}
a {{ color: var(--accent); }}
pre {{ overflow: auto; padding: 14px; border-radius: 8px; background: rgba(127, 127, 127, 0.12); white-space: pre-wrap; }}
input[type="search"] {{
  width: 100%;
  box-sizing: border-box;
  padding: 7px 10px;
  margin-bottom: 12px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--bg);
  color: var(--fg);
  font-size: 13px;
}}
.explain ul.risks {{ margin: 8px 0 0; padding-left: 20px; }}
.explain li {{ margin: 5px 0; }}
.badge {{
  display: inline-block;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  padding: 2px 7px;
  border-radius: 4px;
  margin-right: 8px;
}}
.badge.high {{ background: #b91c1c; color: #fff; }}
.badge.medium {{ background: #b45309; color: #1f2937; }}
.badge.low {{ background: var(--border); color: var(--fg); }}
@media (max-width: 760px) {{
  body {{ padding: 18px; }}
  .grid {{ grid-template-columns: 1fr; }}
}}
</style>
</head>
<body>
<main>
<h1>Project Reports Dashboard</h1>
<p class="meta">Generated report navigation for this export.</p>
<div class="cards">
{card_html}
</div>
<section class="panel explain">
<h2 style="margin-top:0">Explain in plain words</h2>
<p>{project_name} is a {project_type} project ({stack_line}), scoring {health_score}/100 on the automated health checks.</p>
{risks_html}
<p><a href="PROJECT_OVERVIEW.html">Open the full plain-language overview &rarr;</a></p>
</section>
<div class="grid">
<nav>
<h2>Reports</h2>
<input type="search" id="report-filter" placeholder="Filter reports&hellip;" aria-label="Filter reports">
<ul id="report-list">
{link_html}
</ul>
</nav>
<section class="panel">
<h2>Export plan</h2>
<pre>{export_plan_panel}</pre>
<h2>Project health</h2>
<pre>{health_panel}</pre>
</section>
</div>
</main>
<script>
// Filters the report-links list by substring match against each entry's
// data-search attribute. No library, no network reference: this is the entire
// interactive surface of the page.
(function () {{
  var input = document.getElementById("report-filter");
  var items = document.querySelectorAll("#report-list li");
  input.addEventListener("input", function () {{
    var query = input.value.trim().toLowerCase();
    items.forEach(function (item) {{
      var match = query === "" || item.getAttribute("data-search").indexOf(query) !== -1;
      item.classList.toggle("hidden", !match);
    }});
  }});
}})();
</script>
</body>
</html>
"##
    );

    std::fs::write(output_file, html).map_err(|source| ReportError::Write {
        path: output_file.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::Fixture;

    #[test]
    fn falls_back_to_n_a_and_single_when_optional_reports_are_absent() {
        let fixture = Fixture::new(|_root| {});
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_html_dashboard(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("<div class=\"value\">n/a</div>"));
        assert!(content.contains("<div class=\"value\">single</div>"));
        assert!(content.contains(NOT_GENERATED_YET));
    }

    #[test]
    fn reflects_split_strategy_and_excerpts_when_optional_reports_are_present() {
        let fixture = Fixture::new(|_root| {});
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            out_dir.path().join("27_archive_plan.md"),
            "# Archive Plan\n\nSplit planned: `True`\n",
        )
        .unwrap();
        std::fs::write(
            out_dir.path().join("28_export_plan.md"),
            "# Export Plan\n\nIncluded: 42 files\n",
        )
        .unwrap();
        std::fs::write(
            out_dir.path().join("22_project_health_report.md"),
            "# Project Health Report\n\nOverall score: **77/100**\n",
        )
        .unwrap();
        std::fs::write(
            out_dir.path().join("06_security_scan.json"),
            r#"{"summary": {"total_findings": 3, "potential_secrets": 1}}"#,
        )
        .unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_html_dashboard(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("<div class=\"value\">split</div>"));
        assert!(content.contains("<div class=\"value\">77/100</div>"));
        assert!(content.contains("<div class=\"value\">3</div>"));
        assert!(content.contains("<div class=\"value\">1</div>"));
        assert!(content.contains("Included: 42 files"));
        assert!(content.contains("Overall score:"));
    }

    #[test]
    fn the_plain_language_section_uses_the_same_summary_project_overview_renders() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join(".env"), "KEY=x\n").unwrap();
            std::fs::write(root.join("main.py"), "print(1)\n").unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_html_dashboard(&ctx, &output_file).unwrap();
        let content = std::fs::read_to_string(&output_file).unwrap();

        let summary = humanize::summarize(&ctx);
        assert!(content.contains("Explain in plain words"));
        assert!(content.contains(&format!("scoring {}/100", summary.health_score)));
        for risk in &summary.risks {
            assert!(
                content.contains(&escape_html(&risk.text)),
                "missing risk text: {}",
                risk.text
            );
        }
    }

    #[test]
    fn the_search_filter_is_inline_js_with_no_outbound_reference() {
        let fixture = Fixture::new(|_root| {});
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_html_dashboard(&ctx, &output_file).unwrap();
        let content = std::fs::read_to_string(&output_file).unwrap();

        assert!(content.contains("id=\"report-filter\""));
        assert!(content.contains("getElementById(\"report-filter\")"));
        assert!(!content.contains("http://"));
        assert!(!content.contains("https://"));
        assert!(!content.contains("cdn."));
        assert!(
            !content.contains("<script src"),
            "the filter must be inline, not a fetched file"
        );
    }

    #[test]
    fn new_report_links_are_present_and_searchable() {
        let fixture = Fixture::new(|_root| {});
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_html_dashboard(&ctx, &output_file).unwrap();
        let content = std::fs::read_to_string(&output_file).unwrap();

        for href in [
            "PROJECT_OVERVIEW.html",
            "ONBOARDING_GUIDE.md",
            "REVIEW_CHECKLIST.md",
        ] {
            assert!(content.contains(href), "missing link to {href}");
        }
    }

    #[test]
    fn a_planted_secret_never_reaches_the_plain_language_section() {
        let secret = concat!("sk-live-", "ABCDEF1234567890abcdef");
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("config.py"), format!("API_KEY = \"{secret}\"\n")).unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_html_dashboard(&ctx, &output_file).unwrap();
        let content = std::fs::read_to_string(&output_file).unwrap();

        assert!(
            !content.contains(secret),
            "planted secret leaked into REPORT_DASHBOARD.html"
        );
    }
}
