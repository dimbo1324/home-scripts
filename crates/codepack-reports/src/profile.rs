//! The export-profile gating table, reconstructed directly from the legacy
//! `reports/insights/orchestrator.py::write_project_insight_reports`'s `report_jobs`
//! list (`docs/__arch__/codepack-main.zip`) — not guessed. This is the single source
//! of truth every [`crate::plugin::ReportJob`] and the eventual full-catalog
//! profile-gating test check against; later groups extend this file, they do not
//! duplicate the table elsewhere.
//!
//! Legacy's own gating rule (`ReportPlugin.should_run`): a job with profile set `P`
//! runs when the active profile is `"full"` **or** is a member of `P`. `"full"`
//! therefore always runs every job regardless of what is listed below — see
//! [`should_run`].

/// All five export profiles (`codepack_core::config::EXPORT_PROFILES`, same set).
pub const ALL_PROFILES: &[&str] = &["quick", "full", "ai_review", "security", "minimal"];

pub const PROJECT_PROFILE_JSON: &[&str] = ALL_PROFILES;
pub const SUMMARY_TXT: &[&str] = ALL_PROFILES;
pub const FILE_STATISTICS_TXT: &[&str] = &["quick", "full", "ai_review", "security"];
pub const DEPENDENCIES_TXT: &[&str] = &["quick", "full", "ai_review", "security"];
pub const SCRIPTS_TXT: &[&str] = &["quick", "full", "ai_review"];
pub const GIT_DEEP_TXT: &[&str] = &["ai_review", "security", "full"];
pub const SECURITY_SCAN_TXT: &[&str] = ALL_PROFILES;
pub const TODO_FIXME_TXT: &[&str] = &["quick", "full", "ai_review", "security"];
pub const CODE_METRICS_TXT: &[&str] = &["quick", "full", "ai_review", "security"];
pub const CONFIG_TXT: &[&str] = ALL_PROFILES;
pub const DOCKER_TXT: &[&str] = &["quick", "full", "ai_review", "security"];
pub const ROUTES_AND_PAGES_TXT: &[&str] = &["quick", "full", "ai_review"];
pub const AI_CONTEXT_PACK_MD: &[&str] = &["quick", "full", "ai_review", "minimal"];
pub const RUNBOOK_MD: &[&str] = ALL_PROFILES;
pub const DEPENDENCY_GRAPH_MD: &[&str] = &["quick", "full", "ai_review"];
pub const ARCHITECTURE_REPORT_MD: &[&str] = ALL_PROFILES;
pub const KEY_FILES_REPORT_MD: &[&str] = ALL_PROFILES;
pub const CODE_QUALITY_REPORT_MD: &[&str] = &["quick", "full", "ai_review", "security"];
pub const API_SURFACE_REPORT_MD: &[&str] = &["full", "ai_review", "security"];
pub const FRONTEND_REPORT_MD: &[&str] = &["full", "ai_review"];
pub const BACKEND_REPORT_MD: &[&str] = &["full", "ai_review"];
pub const GIT_TIMELINE_REPORT_MD: &[&str] = &["full", "ai_review", "security"];
pub const PROJECT_HEALTH_REPORT_MD: &[&str] = ALL_PROFILES;
// New in S12 (BLUEPRINT B.9): every profile benefits from a plain-language overview,
// same reasoning ALL_PROFILES already applies to PROJECT_PROFILE_JSON/SUMMARY_TXT.
pub const PROJECT_OVERVIEW_HTML: &[&str] = ALL_PROFILES;
pub const ONBOARDING_GUIDE_MD: &[&str] = ALL_PROFILES;
// Narrower: a review checklist is only useful to the review/ai_review workflow and to
// a full export; a "quick" glance or a "minimal"/"security"-scoped bundle has no room
// for it and legacy's own five profiles never had a review-mode concept to borrow a
// precedent from, so this is a fresh, deliberate choice, not a ported one.
pub const REVIEW_CHECKLIST_MD: &[&str] = &["full", "ai_review"];
pub const REFACTORING_OPPORTUNITIES_MD: &[&str] = &["quick", "full", "ai_review", "security"];
pub const ARCHITECTURE_MAP_MD: &[&str] = &["quick", "full", "ai_review", "minimal"];
pub const LARGE_FILES_REPORT_MD: &[&str] = &["quick", "full", "ai_review", "security"];
pub const DEPENDENCY_INTELLIGENCE_MD: &[&str] = &["quick", "full", "ai_review", "security"];

/// Not per-file `ReportJob`s (they write folders or a dashboard over the already-written
/// reports), but gated by the same rule; kept here so a later group's runner extension
/// reads the same source of truth.
pub const AI_CONTEXT_FOLDER: &[&str] = &["full", "ai_review", "quick", "minimal"];
pub const AI_PROMPTS_FOLDER: &[&str] = &["full", "ai_review", "quick", "minimal", "security"];
pub const REPORT_DASHBOARD_HTML: &[&str] = &["full", "ai_review", "quick", "minimal", "security"];

/// Legacy `ReportPlugin.should_run`/`orchestrator._should_run`: `"full"` always runs;
/// otherwise the active profile must be one of `profiles`.
pub fn should_run(profile: &str, profiles: &[&str]) -> bool {
    profile == "full" || profiles.contains(&profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_always_runs_regardless_of_table() {
        assert!(should_run("full", &["security"]));
        assert!(should_run("full", &[]));
    }

    #[test]
    fn listed_profile_runs_unlisted_does_not() {
        assert!(should_run("quick", FILE_STATISTICS_TXT));
        assert!(!should_run("minimal", FILE_STATISTICS_TXT));
    }
}
