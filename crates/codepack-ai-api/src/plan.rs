//! What is about to leave the machine, and the guards that run before it does.
//!
//! This module is the reason the stage is safe to ship. Everything else here is
//! plumbing; this is where the product's central promise — "nothing sensitive leaves
//! with the bundle" — is either kept or broken, because S13 is the only place a bundle
//! ever crosses the network.
//!
//! Two rules, and the asymmetry between them is deliberate:
//!
//! * **Known critical findings are a hard refusal**, overridable only by an explicit
//!   flag the user has to set. Sending a bundle that the project's own scanner has
//!   already flagged would make the scanner decorative.
//! * **A missing scan is a loud warning, not a refusal.** Some export profiles do not
//!   run the scanner, and refusing there would make the feature unusable for them. What
//!   this module will not do is claim a bundle is clean when nothing checked it — the
//!   plan carries `None`, which the interface renders as "not verified" rather than as
//!   a reassuring zero.

use std::path::{Path, PathBuf};

use codepack_tokens::estimate_tokens_fallback;

use crate::provider::{AiProvider, AiRequest};
use codepack_ai::error::{AiError, Refusal};

/// The AI context folder inside an extracted bundle.
const CONTEXT_DIR: &str = "AI_CONTEXT";

/// Machine-readable scanner output, when the export ran the scanner at all.
const SCAN_JSON: &str = "06_security_scan.json";

/// Reply budget. Generous on purpose: on current models this bounds thinking *and* the
/// visible answer together, so a cap sized for the answer alone truncates mid-sentence.
pub const DEFAULT_MAX_OUTPUT_TOKENS: u32 = 16_000;

/// What the user is asked to confirm. Every field is something a reasonable person
/// would want to know before handing their source code to a third party.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendPlan {
    pub provider: String,
    pub model: String,
    pub context_files: usize,
    pub context_bytes: u64,
    pub estimated_tokens: u64,
    /// `None` means the bundle carries no scanner output — not that it is clean.
    pub critical_findings: Option<u64>,
    /// The model's advertised window, when this build knows the model.
    pub model_context_tokens: Option<u64>,
}

impl SendPlan {
    /// Whether the estimate alone already exceeds the model's window. Advisory: the
    /// estimate is a byte-based approximation, so this is a warning and not a guard.
    pub fn exceeds_context(&self) -> bool {
        match self.model_context_tokens {
            Some(limit) => self.estimated_tokens > limit,
            None => false,
        }
    }

    /// Whether the bundle was checked by the scanner at all.
    pub fn scan_ran(&self) -> bool {
        self.critical_findings.is_some()
    }

    /// The guard that runs before any network call.
    ///
    /// `override_critical` exists so the refusal is a decision the user makes rather
    /// than a wall they cannot get past — but it is a separate, explicit act, never a
    /// default and never implied by pressing send.
    pub fn check(&self, enabled: bool, override_critical: bool) -> Result<(), Refusal> {
        if !enabled {
            return Err(Refusal::Disabled);
        }
        if self.context_files == 0 || self.context_bytes == 0 {
            return Err(Refusal::EmptyContext);
        }
        match self.critical_findings {
            Some(count) if count > 0 && !override_critical => {
                Err(Refusal::CriticalFindings { count })
            }
            _ => Ok(()),
        }
    }
}

/// Read an extracted bundle and describe what sending it would mean.
pub fn build_plan(
    bundle_dir: &Path,
    provider: &dyn AiProvider,
    model: &str,
) -> Result<SendPlan, AiError> {
    let context = read_context(bundle_dir)?;
    let context_bytes: u64 = context.iter().map(|file| file.text.len() as u64).sum();

    let model_context_tokens = provider
        .known_models()
        .iter()
        .find(|known| known.id == model)
        .map(|known| known.context_tokens);

    Ok(SendPlan {
        provider: provider.id().to_string(),
        model: model.to_string(),
        context_files: context.len(),
        context_bytes,
        estimated_tokens: estimate_tokens_fallback(context_bytes),
        critical_findings: count_critical_findings(bundle_dir),
        model_context_tokens,
    })
}

/// One context file, read from the bundle.
struct ContextFile {
    name: String,
    text: String,
}

/// Read `AI_CONTEXT/`, sorted by name so the assembled request is deterministic — the
/// same bundle and question must produce the same bytes, or prompt caching on the
/// provider side never hits and two identical runs are billed twice.
fn read_context(bundle_dir: &Path) -> Result<Vec<ContextFile>, AiError> {
    let dir = bundle_dir.join(CONTEXT_DIR);
    let entries = std::fs::read_dir(&dir).map_err(|source| AiError::Bundle {
        path: dir.clone(),
        source,
    })?;

    let mut files = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        // A file that cannot be read is skipped rather than fatal: the context folder is
        // additive, and one unreadable member should not block a send the rest supports.
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        files.push(ContextFile {
            name: path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default(),
            text,
        });
    }
    files.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(files)
}

/// Count findings the scanner marked critical.
///
/// Only the `severity` field of each finding is read — never `message`, which carries
/// the redacted-but-still-sensitive excerpt. Invariant I3 says a finding's text must not
/// travel to new surfaces, and a count is not text.
///
/// Returns `None` when the bundle has no scanner output, which is distinct from `Some(0)`.
fn count_critical_findings(bundle_dir: &Path) -> Option<u64> {
    let raw = std::fs::read_to_string(bundle_dir.join(SCAN_JSON)).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let findings = parsed.get("findings")?.as_array()?;
    Some(
        findings
            .iter()
            .filter(|finding| {
                finding.get("severity").and_then(|value| value.as_str()) == Some("critical")
            })
            .count() as u64,
    )
}

/// Assemble the request. Call only after [`SendPlan::check`] has passed.
pub fn build_request(bundle_dir: &Path, model: &str, question: &str) -> Result<AiRequest, AiError> {
    let context = read_context(bundle_dir)?;
    if context.is_empty() {
        return Err(AiError::Refused(Refusal::EmptyContext));
    }

    let mut user = String::new();
    user.push_str(
        "Below is an exported snapshot of a software project, one section per context \
         file. Answer the question that follows it.\n\n",
    );
    for file in &context {
        user.push_str("=== ");
        user.push_str(&file.name);
        user.push_str(" ===\n");
        user.push_str(&file.text);
        user.push_str("\n\n");
    }
    user.push_str("=== QUESTION ===\n");
    user.push_str(question);

    Ok(AiRequest {
        model: model.to_string(),
        system: SYSTEM_PROMPT.to_string(),
        user,
        max_output_tokens: DEFAULT_MAX_OUTPUT_TOKENS,
    })
}

/// Framing for the model. Kept short: a long system prompt on a one-shot question buys
/// little and costs tokens on every send.
const SYSTEM_PROMPT: &str = "You are reviewing an exported snapshot of a software \
project. The snapshot is partial by design — files may have been excluded for size or \
safety. Answer from what you can see, and say plainly when something you would need to \
answer properly is not in the snapshot rather than assuming it.";

/// Where an answer is written inside the bundle, so the exchange survives the session.
pub const ANSWER_FILE: &str = "AI_ANSWER.md";

/// Append an answer to the bundle's answer file.
///
/// Appending rather than replacing: a second question about the same bundle should not
/// silently destroy the first answer, which the user may not have read yet.
pub fn save_answer(bundle_dir: &Path, question: &str, answer: &str) -> Result<PathBuf, AiError> {
    let path = bundle_dir.join(ANSWER_FILE);
    let mut body = std::fs::read_to_string(&path).unwrap_or_default();
    if !body.is_empty() {
        body.push_str("\n\n---\n\n");
    }
    body.push_str("## Question\n\n");
    body.push_str(question);
    body.push_str("\n\n## Answer\n\n");
    body.push_str(answer);
    body.push('\n');

    std::fs::write(&path, body).map_err(|source| AiError::Bundle {
        path: path.clone(),
        source,
    })?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::anthropic::Anthropic;

    fn bundle_with(context: &[(&str, &str)], scan_json: Option<&str>) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let context_dir = dir.path().join(CONTEXT_DIR);
        std::fs::create_dir_all(&context_dir).unwrap();
        for (name, body) in context {
            std::fs::write(context_dir.join(name), body).unwrap();
        }
        if let Some(json) = scan_json {
            std::fs::write(dir.path().join(SCAN_JSON), json).unwrap();
        }
        dir
    }

    fn plan_for(dir: &tempfile::TempDir) -> SendPlan {
        build_plan(dir.path(), &Anthropic, "claude-opus-5").unwrap()
    }

    #[test]
    fn a_clean_bundle_passes_the_guard() {
        let dir = bundle_with(&[("00.md", "hello")], Some(r#"{"findings":[]}"#));
        let plan = plan_for(&dir);
        assert_eq!(plan.critical_findings, Some(0));
        assert!(plan.check(true, false).is_ok());
    }

    #[test]
    fn a_critical_finding_refuses_the_send() {
        // The whole product exists to stop this. The default cannot be "send".
        let dir = bundle_with(
            &[("00.md", "hello")],
            Some(r#"{"findings":[{"severity":"critical"},{"severity":"warning"}]}"#),
        );
        let plan = plan_for(&dir);
        assert_eq!(plan.critical_findings, Some(1));
        assert_eq!(
            plan.check(true, false),
            Err(Refusal::CriticalFindings { count: 1 })
        );
    }

    #[test]
    fn the_refusal_can_be_overridden_but_only_explicitly() {
        let dir = bundle_with(
            &[("00.md", "hello")],
            Some(r#"{"findings":[{"severity":"critical"}]}"#),
        );
        assert!(plan_for(&dir).check(true, true).is_ok());
    }

    #[test]
    fn a_missing_scan_is_unknown_rather_than_clean() {
        // `None` and `Some(0)` must not collapse: one means "checked, nothing found",
        // the other means "nothing checked". Rendering the second as the first would be
        // the security artifact stating something false.
        let dir = bundle_with(&[("00.md", "hello")], None);
        let plan = plan_for(&dir);
        assert_eq!(plan.critical_findings, None);
        assert!(!plan.scan_ran());
        assert!(
            plan.check(true, false).is_ok(),
            "a missing scan warns, not blocks"
        );
    }

    #[test]
    fn a_disabled_integration_refuses_before_anything_else() {
        let dir = bundle_with(&[("00.md", "hello")], None);
        assert_eq!(plan_for(&dir).check(false, false), Err(Refusal::Disabled));
    }

    #[test]
    fn an_empty_context_refuses() {
        let dir = bundle_with(&[], None);
        assert_eq!(
            plan_for(&dir).check(true, false),
            Err(Refusal::EmptyContext)
        );
    }

    #[test]
    fn the_request_is_byte_identical_for_the_same_bundle_and_question() {
        // Non-deterministic assembly would defeat provider-side prompt caching and bill
        // two identical runs twice.
        let dir = bundle_with(&[("01.md", "b"), ("00.md", "a")], None);
        let first = build_request(dir.path(), "claude-opus-5", "why?").unwrap();
        let second = build_request(dir.path(), "claude-opus-5", "why?").unwrap();
        assert_eq!(first, second);
        // ...and sorted, so 00 precedes 01 regardless of directory order.
        let a = first.user.find("00.md").unwrap();
        let b = first.user.find("01.md").unwrap();
        assert!(a < b);
    }

    #[test]
    fn the_question_reaches_the_request() {
        let dir = bundle_with(&[("00.md", "context")], None);
        let request = build_request(dir.path(), "claude-opus-5", "what breaks?").unwrap();
        assert!(request.user.contains("what breaks?"));
        assert!(request.user.contains("context"));
    }

    #[test]
    fn a_bundle_without_a_context_folder_is_an_error_naming_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let error = build_plan(dir.path(), &Anthropic, "claude-opus-5").unwrap_err();
        assert!(matches!(error, AiError::Bundle { .. }));
    }

    #[test]
    fn an_unknown_model_has_no_context_limit_and_never_reports_an_overflow() {
        let dir = bundle_with(&[("00.md", "hello")], None);
        let plan = build_plan(dir.path(), &Anthropic, "some-future-model").unwrap();
        assert_eq!(plan.model_context_tokens, None);
        assert!(!plan.exceeds_context());
    }

    #[test]
    fn a_context_larger_than_the_window_is_flagged() {
        let dir = bundle_with(&[("00.md", &"x".repeat(4096))], None);
        let mut plan = plan_for(&dir);
        plan.model_context_tokens = Some(10);
        assert!(plan.exceeds_context());
    }

    #[test]
    fn saving_a_second_answer_keeps_the_first() {
        let dir = tempfile::tempdir().unwrap();
        save_answer(dir.path(), "q1", "a1").unwrap();
        let path = save_answer(dir.path(), "q2", "a2").unwrap();
        let body = std::fs::read_to_string(path).unwrap();
        assert!(body.contains("q1") && body.contains("a1"));
        assert!(body.contains("q2") && body.contains("a2"));
    }
}
