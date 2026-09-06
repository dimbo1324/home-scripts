//! Plain-language synthesis, shared by [`crate::reports::overview`] (the standalone
//! `PROJECT_OVERVIEW.html`) and [`crate::reports::dashboard`]'s "Explain in plain
//! words" section (BLUEPRINT §B.9, stage S12).
//!
//! **Deliberately not a new detector.** Every field here is read from data three
//! earlier stages already computed and already redacted:
//! [`crate::project_profile::build_project_profile`] (stack, type, risk level/reasons),
//! [`crate::reports::project_health::compute_scores`] (the health score), and
//! [`crate::reports::key_files::ranked_key_files`] (which files matter). The one new
//! input is [`codepack_security::ScanResult::summary`] — **counts only**, never
//! [`codepack_security::Finding::message`]. A reader who has never seen the code must
//! still never see a secret value: reading finding text here, even redacted text,
//! would be a second, unaudited path to the same risk invariant I3 exists to close.
//! Counting is enough to say "3 potential secrets were found and redacted" without
//! opening that door.
//!
//! This module produces data, not markup — [`crate::reports::overview`] and
//! [`crate::reports::dashboard`] render it differently (a full page vs. a dashboard
//! section), and a single struct read by both means the numbers can never drift
//! between the two surfaces the way two independent computations could.

use crate::context::ReportContext;
use crate::reports::key_files;
use crate::reports::project_health;

/// One sentence a non-technical reader can act on.
pub(crate) struct RiskHighlight {
    pub severity: Severity,
    pub text: String,
}

/// How serious a highlighted risk is.
///
/// A type rather than a string because this value is interpolated into HTML twice — once
/// into a `class` attribute and once as text — and the surrounding code escapes every
/// other interpolation. Those two were not escaped, which was safe only because the field
/// happened to hold a literal (audit No. 29). With an enum it cannot hold anything else:
/// a string derived from a project's own file has no way in, so the rule is kept by the
/// type instead of by a reader noticing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Severity {
    High,
    Medium,
    Low,
}

impl Severity {
    /// The CSS class and the label, which are the same word. Every value is a fixed
    /// identifier, so no escaping is needed — and none is possible to forget.
    pub(crate) fn as_class(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

/// One file worth reading first, and why.
pub(crate) struct StartingPoint {
    pub path: String,
    pub reason: String,
}

pub(crate) struct PlainLanguageSummary {
    pub project_name: String,
    pub project_type: String,
    pub stack: Vec<String>,
    pub health_score: i64,
    pub risk_level: String,
    pub risks: Vec<RiskHighlight>,
    pub total_findings: Option<usize>,
    pub potential_secrets: Option<usize>,
    pub file_count: usize,
    pub total_size_human: String,
    pub starting_points: Vec<StartingPoint>,
}

/// How many files to suggest as "start here" — enough to be useful, short enough that
/// a non-technical reader does not stop reading.
const STARTING_POINTS_LIMIT: usize = 5;

pub(crate) fn summarize(ctx: &ReportContext<'_>) -> PlainLanguageSummary {
    let profile = crate::project_profile::build_project_profile(ctx);
    let scores = project_health::compute_scores(ctx);

    // Risk highlights combine the profile's own hygiene reasons with the two
    // lowest-scoring health areas — "here is what to look at first", not a restatement
    // of every area. `min(2)` keeps the sentence short; a curious reader still has the
    // full breakdown one click away in 22_project_health_report.md.
    let mut weakest_areas: Vec<&project_health::AreaScore> = scores.areas.iter().collect();
    weakest_areas.sort_by_key(|area| area.score);

    let mut risks: Vec<RiskHighlight> = profile
        .risk_reasons
        .iter()
        .map(|reason| RiskHighlight {
            severity: severity_for(&profile.risk_level),
            text: reason.clone(),
        })
        .collect();
    for area in weakest_areas.into_iter().take(2) {
        if area.score >= 70 {
            // Nothing scored low enough to be worth surfacing as a risk.
            continue;
        }
        if let Some(reason) = area.reasons.first() {
            risks.push(RiskHighlight {
                severity: if area.score < 40 {
                    Severity::High
                } else {
                    Severity::Medium
                },
                text: format!("{}: {reason}", area.name),
            });
        }
    }

    let starting_points = key_files::ranked_key_files(ctx)
        .into_iter()
        .take(STARTING_POINTS_LIMIT)
        .map(|(_, file, reasons)| StartingPoint {
            path: file.relative_path.clone(),
            reason: reasons.into_iter().next().unwrap_or_default(),
        })
        .collect();

    PlainLanguageSummary {
        project_name: ctx
            .staging_root
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
        project_type: profile.project_type,
        stack: profile.detected_stack,
        health_score: scores.overall(),
        risk_level: profile.risk_level,
        risks,
        total_findings: ctx.scan.map(|scan| scan.summary.total_findings),
        potential_secrets: ctx.scan.map(|scan| scan.summary.potential_secrets),
        file_count: ctx.inventory.files.len(),
        total_size_human: codepack_tokens::format_bytes(ctx.inventory.total_size),
        starting_points,
    }
}

fn severity_for(risk_level: &str) -> Severity {
    match risk_level {
        "high" => Severity::High,
        "medium" => Severity::Medium,
        _ => Severity::Low,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::Fixture;

    #[test]
    fn summary_reflects_a_clean_small_project() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("main.py"), "print('hi')\n").unwrap();
            std::fs::write(root.join("README.md"), "# demo\n").unwrap();
        });
        let ctx = fixture.context("full");

        let summary = summarize(&ctx);

        assert_eq!(summary.file_count, 2);
        assert!((0..=100).contains(&summary.health_score));
        assert!(!summary.project_name.is_empty());
    }

    #[test]
    fn env_files_surface_as_a_risk_highlight() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join(".env"), "KEY=x\n").unwrap();
            std::fs::write(root.join("main.py"), "print(1)\n").unwrap();
        });
        let ctx = fixture.context("full");

        let summary = summarize(&ctx);

        assert!(
            summary.risks.iter().any(|risk| risk.text.contains(".env")),
            "expected a .env-related risk highlight, got: {:?}",
            summary.risks.iter().map(|r| &r.text).collect::<Vec<_>>()
        );
    }

    #[test]
    fn starting_points_come_from_the_same_ranking_key_files_report_uses() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("main.py"), "print(1)\n").unwrap();
            std::fs::write(root.join("random_notes.txt"), "x".repeat(10)).unwrap();
        });
        let ctx = fixture.context("full");

        let summary = summarize(&ctx);
        let ranked = key_files::ranked_key_files(&ctx);

        let expected: Vec<String> = ranked
            .iter()
            .take(STARTING_POINTS_LIMIT)
            .map(|(_, file, _)| file.relative_path.clone())
            .collect();
        let actual: Vec<String> = summary
            .starting_points
            .iter()
            .map(|point| point.path.clone())
            .collect();
        assert_eq!(actual, expected);
    }
}
