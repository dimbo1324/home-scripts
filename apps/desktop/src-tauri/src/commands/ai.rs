//! Handing a finished bundle to a coding agent running on this machine.
//!
//! This is stage S13's offline path, and the only one the interface offers. The API path
//! exists in `codepack-ai` behind its `api` feature; this crate takes that dependency
//! with `default-features = false`, so the desktop binary contains **no HTTP client and
//! no credential store at all** — invariant I1 held by what is linked, not by what the
//! code chooses to call.
//!
//! Nothing is launched. The command writes `AI_HANDOFF.md` into the bundle and returns
//! the command to run there; the user starts their own agent, in their own terminal,
//! where they can see what it does. Spawning a process would also need a capability the
//! webview deliberately does not have.

use codepack_ai::handoff;

use crate::dto::{HandoffResult, LocalAgentInfo};
use crate::error::{CommandError, CommandResult};

/// The agents this build can describe. Advisory: the handoff file works for any tool
/// that reads the folder, including one not listed here.
#[tauri::command]
pub fn list_local_agents() -> Vec<LocalAgentInfo> {
    handoff::AGENTS
        .iter()
        .map(|agent| LocalAgentInfo {
            id: agent.id.to_string(),
            display_name: agent.display_name.to_string(),
            command: agent.command.to_string(),
        })
        .collect()
}

/// Writes the handoff file into the bundle at `result_path`.
///
/// The bundle is extracted first when it is an archive — an agent cannot read a project
/// inside a ZIP — using the same beside-the-archive directory the report-opening
/// commands already use, so a user who has opened the dashboard and then prepares a
/// handoff does not end up with two copies of their bundle.
#[tauri::command]
pub fn prepare_handoff(
    result_path: String,
    agent_id: String,
    question: String,
) -> CommandResult<HandoffResult> {
    let agent = handoff::agent(&agent_id).ok_or_else(|| {
        let known: Vec<&str> = handoff::AGENTS.iter().map(|entry| entry.id).collect();
        CommandError::new(format!(
            "unknown agent {agent_id:?}. Available: {}",
            known.join(", ")
        ))
    })?;

    let bundle_dir = crate::commands::export::extracted_bundle_dir(&result_path)?;
    let prepared = handoff::prepare(&bundle_dir, agent, &question).map_err(CommandError::new)?;

    Ok(HandoffResult {
        path: prepared.path.display().to_string(),
        working_dir: prepared.working_dir.display().to_string(),
        command: prepared.command,
        agent_name: agent.display_name.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_agent_offered_to_the_ui_can_be_resolved_again() {
        // The frontend sends back an id from this list; one that does not resolve would
        // be a button that always fails.
        for agent in list_local_agents() {
            assert!(handoff::agent(&agent.id).is_some());
            assert!(!agent.display_name.is_empty());
            assert!(!agent.command.is_empty());
        }
    }

    #[test]
    fn an_unknown_agent_is_refused_with_the_alternatives_named() {
        let dir = tempfile::tempdir().unwrap();
        let error = prepare_handoff(
            dir.path().display().to_string(),
            "not-an-agent".to_string(),
            "q".to_string(),
        )
        .unwrap_err();

        assert!(error.message.contains("not-an-agent"), "{}", error.message);
        assert!(error.message.contains("claude-code"), "{}", error.message);
    }

    #[test]
    fn preparing_writes_the_file_into_an_already_extracted_bundle() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("AI_CONTEXT")).unwrap();

        // Through `handoff::prepare` rather than the command: since audit No. 6 the
        // command first checks that the path is an export this installation produced,
        // and a temporary directory is deliberately not one. What is under test here is
        // what gets written into a bundle, which is this half.
        let agent = handoff::agent("claude-code").expect("a known agent");
        let prepared = handoff::prepare(dir.path(), agent, "review the auth flow").unwrap();

        assert_eq!(prepared.working_dir, dir.path());
        assert_eq!(prepared.command, "claude");
        let body = std::fs::read_to_string(&prepared.path).unwrap();
        assert!(body.contains("review the auth flow"));
    }

    #[test]
    fn a_result_path_that_no_longer_exists_is_reported_rather_than_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("gone.zip");

        let error = prepare_handoff(
            missing.display().to_string(),
            "claude-code".to_string(),
            String::new(),
        )
        .unwrap_err();
        assert!(
            error.message.contains("no longer where it was recorded"),
            "{}",
            error.message
        );
    }

    /// The guard the command gained: a directory nobody exported is not a bundle.
    #[test]
    fn preparing_refuses_a_path_no_run_produced() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("AI_CONTEXT")).unwrap();

        let error = prepare_handoff(
            dir.path().display().to_string(),
            "claude-code".to_string(),
            "review the auth flow".to_string(),
        )
        .expect_err("an unrecorded path must not be opened");
        assert!(
            format!("{error:?}").contains("not an export this installation produced"),
            "{error:?}"
        );
    }
}
