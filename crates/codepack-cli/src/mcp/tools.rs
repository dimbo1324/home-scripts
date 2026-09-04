//! The tools an agent can call, and the dispatch onto the commands that already exist.
//!
//! ## Nothing here decides anything
//!
//! Every tool resolves a project the way the CLI does and then calls the *same* builder
//! the corresponding command calls. That is deliberate to the point of being the whole
//! design: what a preset means, why `scan` forces safe mode to `full`, which four
//! layers configuration is resolved from — all of it stays in one place. A second
//! implementation here would drift, and the first symptom of the drift would be an
//! agent confidently reporting something the CLI disagrees with.
//!
//! ## A failed tool is a successful call
//!
//! When a tool fails — a path that is not a project, a `--since` ref that does not
//! exist — the answer is a normal `tools/call` result carrying `isError: true` and the
//! message. A JSON-RPC error would be handled by the client's transport layer and the
//! model would never see it, so it could not correct itself. Protocol-level errors are
//! reserved for protocol-level problems: an unknown method, malformed parameters.

use std::path::PathBuf;

use codepack_core::CancellationToken;
use serde_json::{Value, json};

use crate::cli::{ProjectArgs, ScanArgs, SeverityArg};
use crate::commands::{self, ProjectContext};

/// Files listed by `codepack_preview` before the list is cut short.
///
/// A preview of a large repository lists tens of thousands of paths, and an agent's
/// context is the scarcest resource in the room. The cut is reported (`files_truncated`)
/// rather than silent, for the same reason the history walk reports its own cap: an
/// answer that looks complete and is not is worse than a short one.
const MAX_LISTED_FILES: usize = 400;

/// What a tool produced.
pub(crate) struct ToolOutcome {
    /// The text block the model reads.
    pub text: String,
    /// The same content as data, for clients that consume `structuredContent`.
    pub structured: Option<Value>,
    pub is_error: bool,
}

impl ToolOutcome {
    fn error(message: impl Into<String>) -> Self {
        Self {
            text: message.into(),
            structured: None,
            is_error: true,
        }
    }

    fn report(value: Value) -> Self {
        Self {
            // Pretty-printed JSON rather than prose: this is the payload a model has to
            // reason over, and every field of these reports already exists because
            // somebody needed it. The `--json` output of the matching command is the
            // same shape, so an agent that has seen one has seen the other.
            text: serde_json::to_string_pretty(&value)
                .unwrap_or_else(|error| format!("could not render the report: {error}")),
            structured: Some(value),
            is_error: false,
        }
    }
}

/// The catalogue, exactly as `tools/list` returns it.
pub(crate) fn catalogue() -> Vec<Value> {
    vec![
        json!({
            "name": "codepack_preview",
            "description": "What an export of this project would include, and what it \
                            would leave out and why. Writes nothing at all. Use this \
                            before asking for an export.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "project": project_property(),
                    "list_files": {
                        "type": "boolean",
                        "description": "Include the list of included files. Capped, and \
                                        the answer says when it was capped."
                    },
                    "preset": preset_property(),
                    "profile": profile_property(),
                    "safe_mode": safe_mode_property()
                }
            },
            "annotations": {"readOnlyHint": true, "openWorldHint": false}
        }),
        json!({
            "name": "codepack_scan",
            "description": "Find secrets and risky code. `working_tree` looks at the \
                            files on disk, `staged` at what is about to be committed, \
                            `history` at every version every commit ever carried — the \
                            one that finds a credential deleted from a file but still \
                            in the repository.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "project": project_property(),
                    "mode": {
                        "type": "string",
                        "enum": ["working_tree", "staged", "history"],
                        "description": "Which file set to read. Defaults to working_tree."
                    },
                    "since": {
                        "type": "string",
                        "description": "history mode only: exclude everything reachable \
                                        from this ref, leaving what was added since."
                    },
                    "max_commits": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "history mode only: commits to walk, newest \
                                        first. 0 walks all of them."
                    }
                }
            },
            "annotations": {"readOnlyHint": true, "openWorldHint": false}
        }),
        json!({
            "name": "codepack_explain",
            "description": "Why one specific file would, or would not, end up in an \
                            export. Answers with one of four verdicts and the rule \
                            responsible. Use this instead of guessing why something is \
                            missing from a bundle.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file": {
                        "type": "string",
                        "description": "The file to explain. Absolute, or relative to \
                                        the project."
                    },
                    "project": project_property(),
                    "preset": preset_property(),
                    "profile": profile_property(),
                    "safe_mode": safe_mode_property()
                },
                "required": ["file"]
            },
            "annotations": {"readOnlyHint": true, "openWorldHint": false}
        }),
        json!({
            "name": "codepack_export",
            "description": "Run the full export pipeline and write a bundle. This one \
                            writes files: an archive and its reports land in out_dir, \
                            which must be outside the project. Prefer codepack_preview \
                            unless a bundle is actually wanted.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "out_dir": {
                        "type": "string",
                        "description": "Directory to write the bundle into. Must not be \
                                        inside the project — the source is never \
                                        written to."
                    },
                    "project": project_property(),
                    "preset": preset_property(),
                    "profile": profile_property(),
                    "safe_mode": safe_mode_property()
                },
                "required": ["out_dir"]
            },
            "annotations": {"readOnlyHint": false, "destructiveHint": false, "openWorldHint": false}
        }),
    ]
}

fn project_property() -> Value {
    json!({
        "type": "string",
        "description": "Project directory. Defaults to the working directory the server \
                        was started in."
    })
}

fn preset_property() -> Value {
    json!({
        "type": "string",
        "description": "AI preset to apply, e.g. \"Claude Code\", \"Code Review\", \
                        \"PR Review\"."
    })
}

fn profile_property() -> Value {
    json!({
        "type": "string",
        "enum": ["quick", "full", "ai_review", "security", "minimal"],
        "description": "Export profile — which reports are produced."
    })
}

fn safe_mode_property() -> Value {
    json!({
        "type": "string",
        "enum": ["safe", "balanced", "full"],
        "description": "How aggressively sensitive files are excluded."
    })
}

/// Renders a command's report as a tool result.
///
/// Serialization failure is reported rather than unwrapped: these are plain structs and
/// it cannot happen, but a panic inside a server that talks to an agent would take the
/// whole session down to save one line here.
fn into_outcome<T: serde::Serialize>(report: &T) -> ToolOutcome {
    match serde_json::to_value(report) {
        Ok(value) => ToolOutcome::report(value),
        Err(error) => ToolOutcome::error(format!("could not render the report: {error}")),
    }
}

/// Runs one tool. Never returns `Err` for a tool's own failure — see the module doc.
pub(crate) fn call(name: &str, arguments: &Value) -> ToolOutcome {
    call_with_cancel(name, arguments, &CancellationToken::new())
}

/// [`call`] with a token the loop can trip when the client sends
/// `notifications/cancelled` for this call.
///
/// Only the two long tools take it. `preview` and `explain` plan a tree and answer;
/// they finish in the time it takes to walk it, and wiring a token through them would
/// buy a client nothing it could act on.
pub(crate) fn call_with_cancel(
    name: &str,
    arguments: &Value,
    cancel: &CancellationToken,
) -> ToolOutcome {
    match name {
        "codepack_preview" => preview(arguments),
        "codepack_scan" => scan(arguments, cancel),
        "codepack_explain" => explain(arguments),
        "codepack_export" => export(arguments, cancel),
        other => ToolOutcome::error(format!(
            "unknown tool {other:?}. Available: {}",
            catalogue()
                .iter()
                .filter_map(|tool| tool["name"].as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

fn string_argument<'a>(arguments: &'a Value, key: &str) -> Option<&'a str> {
    arguments
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// Builds the same argument struct the command line would have produced, so the four
/// configuration layers resolve identically for an agent and for a person.
fn project_args(arguments: &Value) -> ProjectArgs {
    ProjectArgs {
        path: PathBuf::from(string_argument(arguments, "project").unwrap_or(".")),
        preset: string_argument(arguments, "preset").map(str::to_string),
        profile: string_argument(arguments, "profile").map(str::to_string),
        // Parsed through the same `ValueEnum`s the flags use, so an unrecognised value
        // is refused with the list of real ones instead of quietly meaning something.
        safe_mode: string_argument(arguments, "safe_mode").and_then(parse_safe_mode),
        diff: string_argument(arguments, "diff").and_then(parse_diff_mode),
        budget: None,
        archive_format: None,
    }
}

fn parse_safe_mode(value: &str) -> Option<crate::cli::SafeMode> {
    use clap::ValueEnum;
    crate::cli::SafeMode::from_str(value, true).ok()
}

fn parse_diff_mode(value: &str) -> Option<crate::cli::DiffMode> {
    use clap::ValueEnum;
    crate::cli::DiffMode::from_str(value, true).ok()
}

/// Resolves the project, turning a failure into a message the model can act on.
fn context_of(arguments: &Value) -> std::result::Result<ProjectContext, ToolOutcome> {
    let args = project_args(arguments);
    // A value the schema declares but this build cannot parse must not be ignored: an
    // agent that asked for `safe_mode: "paranoid"` and silently got `safe` would draw a
    // conclusion about a run that never happened.
    if let Some(raw) = string_argument(arguments, "safe_mode")
        && args.safe_mode.is_none()
    {
        return Err(ToolOutcome::error(format!(
            "unknown safe_mode {raw:?}. Available: safe, balanced, full"
        )));
    }
    commands::prepare(&args).map_err(|error| ToolOutcome::error(error.to_string()))
}

fn preview(arguments: &Value) -> ToolOutcome {
    let context = match context_of(arguments) {
        Ok(context) => context,
        Err(outcome) => return outcome,
    };
    let list_files = arguments
        .get("list_files")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    match commands::preview::build(&context, list_files) {
        Ok(report) => {
            let mut value = match serde_json::to_value(&report) {
                Ok(value) => value,
                Err(error) => return ToolOutcome::error(error.to_string()),
            };
            cap_file_list(&mut value);
            ToolOutcome::report(value)
        }
        Err(error) => ToolOutcome::error(error.to_string()),
    }
}

/// Shortens an over-long file list and records that it happened.
fn cap_file_list(value: &mut Value) {
    let Some(files) = value.get_mut("files").and_then(Value::as_array_mut) else {
        return;
    };
    if files.len() <= MAX_LISTED_FILES {
        return;
    }
    let total = files.len();
    files.truncate(MAX_LISTED_FILES);
    if let Some(object) = value.as_object_mut() {
        object.insert("files_truncated".to_string(), Value::Bool(true));
        object.insert(
            "files_total".to_string(),
            Value::from(u64::try_from(total).unwrap_or(u64::MAX)),
        );
    }
}

fn scan(arguments: &Value, cancel: &CancellationToken) -> ToolOutcome {
    let context = match context_of(arguments) {
        Ok(context) => context,
        Err(outcome) => return outcome,
    };

    let mode = string_argument(arguments, "mode").unwrap_or("working_tree");
    let built = match mode {
        // No baseline from here: an agent asking "is there a secret in this project"
        // wants every answer, not the ones a file says are old news.
        "working_tree" => commands::scan::build_with_cancel(
            &context,
            SeverityArg::Critical,
            commands::scan::BaselineOptions::default(),
            cancel,
        ),
        "staged" => commands::scan::build_staged_with_cancel(
            &context,
            SeverityArg::Critical,
            commands::scan::BaselineOptions::default(),
            cancel,
        ),
        "history" => {
            let args = ScanArgs {
                project: project_args(arguments),
                staged: false,
                history: true,
                since: string_argument(arguments, "since").map(str::to_string),
                max_commits: arguments
                    .get("max_commits")
                    .and_then(Value::as_u64)
                    .and_then(|value| usize::try_from(value).ok()),
                baseline: None,
                write_baseline: None,
                sarif: None,
                fail_on: SeverityArg::Critical,
            };
            commands::scan::build_history_with_cancel(&context, &args, cancel)
        }
        other => {
            return ToolOutcome::error(format!(
                "unknown mode {other:?}. Available: working_tree, staged, history"
            ));
        }
    };

    match built {
        Ok(report) => into_outcome(&report),
        Err(error) => ToolOutcome::error(error.to_string()),
    }
}

fn explain(arguments: &Value) -> ToolOutcome {
    let Some(file) = string_argument(arguments, "file") else {
        return ToolOutcome::error("explain needs a `file` to explain");
    };
    let context = match context_of(arguments) {
        Ok(context) => context,
        Err(outcome) => return outcome,
    };

    match commands::explain::build(&context, std::path::Path::new(file)) {
        Ok(report) => into_outcome(&report),
        Err(error) => ToolOutcome::error(error.to_string()),
    }
}

fn export(arguments: &Value, cancel: &CancellationToken) -> ToolOutcome {
    let Some(out_dir) = string_argument(arguments, "out_dir") else {
        return ToolOutcome::error(
            "export needs an `out_dir` to write into. It is required rather than \
             defaulted because a bundle written somewhere nobody expected is worse than \
             one not written at all.",
        );
    };
    let context = match context_of(arguments) {
        Ok(context) => context,
        Err(outcome) => return outcome,
    };

    // Quiet: progress would otherwise be printed, and although it goes to stderr and
    // could not corrupt the protocol, a tool call is not a place a user is watching a
    // log scroll past.
    match commands::export::build_with_cancel(
        &context,
        Some(std::path::Path::new(out_dir)),
        true,
        cancel,
    ) {
        Ok(report) => {
            // The bundle's own reports become readable over the same pipe, so an agent
            // that just produced thirty analyses does not have to leave the protocol to
            // look at one.
            super::resources::register_bundle(std::path::Path::new(&report.staging_dir));
            into_outcome(&report)
        }
        Err(error) => ToolOutcome::error(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project_with_a_secret() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src").join("main.py"), "print(1)\n").unwrap();
        std::fs::write(
            dir.path().join(".env"),
            concat!("API_KEY=", "totally-fake-value-0001\n"),
        )
        .unwrap();
        dir
    }

    fn arguments(dir: &tempfile::TempDir, extra: Value) -> Value {
        let mut value = json!({"project": dir.path().display().to_string()});
        if let (Some(target), Some(source)) = (value.as_object_mut(), extra.as_object()) {
            for (key, item) in source {
                target.insert(key.clone(), item.clone());
            }
        }
        value
    }

    #[test]
    fn every_tool_declares_a_name_a_description_and_an_object_schema() {
        // A tool whose schema is not an object is one a client cannot call at all.
        for tool in catalogue() {
            assert!(tool["name"].as_str().is_some_and(|name| !name.is_empty()));
            assert!(
                tool["description"]
                    .as_str()
                    .is_some_and(|text| text.len() > 40),
                "{tool}"
            );
            assert_eq!(tool["inputSchema"]["type"], "object", "{tool}");
        }
    }

    #[test]
    fn the_only_tool_that_writes_is_the_one_that_says_it_writes() {
        for tool in catalogue() {
            let read_only = tool["annotations"]["readOnlyHint"].as_bool().unwrap();
            let name = tool["name"].as_str().unwrap();
            assert_eq!(
                read_only,
                name != "codepack_export",
                "{name} claims the wrong thing about writing"
            );
        }
    }

    #[test]
    fn an_unknown_tool_names_the_ones_that_exist() {
        let outcome = call("codepack_delete_everything", &json!({}));
        assert!(outcome.is_error);
        assert!(
            outcome.text.contains("codepack_preview"),
            "{}",
            outcome.text
        );
    }

    #[test]
    fn preview_answers_with_the_same_report_the_command_produces() {
        let dir = project_with_a_secret();
        let outcome = call("codepack_preview", &arguments(&dir, json!({})));

        assert!(!outcome.is_error, "{}", outcome.text);
        let value = outcome.structured.unwrap();
        assert!(value["included_files"].as_u64().unwrap() >= 1);
        // The reason a preview exists: `.env` is excluded and says so.
        assert!(
            !value["sensitive_exclusions"].as_array().unwrap().is_empty(),
            "{value:#}"
        );
    }

    #[test]
    fn explain_answers_for_one_file_with_a_verdict() {
        let dir = project_with_a_secret();
        let outcome = call(
            "codepack_explain",
            &arguments(&dir, json!({"file": "src/main.py"})),
        );

        assert!(!outcome.is_error, "{}", outcome.text);
        assert_eq!(outcome.structured.unwrap()["verdict"], "included");
    }

    #[test]
    fn explain_without_a_file_says_so_rather_than_guessing() {
        let dir = project_with_a_secret();
        let outcome = call("codepack_explain", &arguments(&dir, json!({})));
        assert!(outcome.is_error);
        assert!(outcome.text.contains("file"), "{}", outcome.text);
    }

    #[test]
    fn scan_sees_the_credential_the_export_would_have_excluded() {
        // The same reasoning the command records: scanning what an export would ship
        // always answers "clean", because safe mode removed the dangerous file first.
        let dir = project_with_a_secret();
        let outcome = call("codepack_scan", &arguments(&dir, json!({})));

        assert!(!outcome.is_error, "{}", outcome.text);
        let value = outcome.structured.unwrap();
        assert_eq!(value["safe_mode"], "full");
        assert!(
            value["summary"]["critical"].as_u64().unwrap() > 0,
            "{value:#}"
        );
    }

    #[test]
    fn a_history_scan_outside_a_repository_is_an_error_the_model_can_read() {
        // `isError: true` in a successful result, not a JSON-RPC error: the transport
        // would swallow the latter and the model would never learn what went wrong.
        let dir = project_with_a_secret();
        let outcome = call(
            "codepack_scan",
            &arguments(&dir, json!({"mode": "history"})),
        );
        assert!(outcome.is_error);
        assert!(outcome.text.contains("git repository"), "{}", outcome.text);
    }

    #[test]
    fn an_unknown_scan_mode_lists_the_real_ones() {
        let dir = project_with_a_secret();
        let outcome = call(
            "codepack_scan",
            &arguments(&dir, json!({"mode": "everything"})),
        );
        assert!(outcome.is_error);
        assert!(outcome.text.contains("working_tree"), "{}", outcome.text);
    }

    #[test]
    fn an_unknown_safe_mode_is_refused_rather_than_silently_ignored() {
        let dir = project_with_a_secret();
        let outcome = call(
            "codepack_preview",
            &arguments(&dir, json!({"safe_mode": "paranoid"})),
        );
        assert!(outcome.is_error);
        assert!(outcome.text.contains("balanced"), "{}", outcome.text);
    }

    #[test]
    fn a_project_that_does_not_exist_is_an_error_naming_it() {
        let outcome = call(
            "codepack_preview",
            &json!({"project": "/no/such/project/anywhere"}),
        );
        assert!(outcome.is_error);
    }

    #[test]
    fn export_without_an_output_directory_refuses_instead_of_choosing_one() {
        let dir = project_with_a_secret();
        let outcome = call("codepack_export", &arguments(&dir, json!({})));
        assert!(outcome.is_error);
        assert!(outcome.text.contains("out_dir"), "{}", outcome.text);
    }

    #[test]
    fn the_preview_file_list_is_capped_and_says_when_it_was() {
        let mut value = json!({"files": (0..MAX_LISTED_FILES + 10)
            .map(|index| format!("file{index}.rs"))
            .collect::<Vec<_>>()});

        cap_file_list(&mut value);

        assert_eq!(value["files"].as_array().unwrap().len(), MAX_LISTED_FILES);
        assert_eq!(value["files_truncated"], true);
        assert_eq!(value["files_total"], (MAX_LISTED_FILES + 10) as u64);
    }

    #[test]
    fn a_short_file_list_is_left_alone_and_not_marked_truncated() {
        let mut value = json!({"files": ["a.rs", "b.rs"]});
        cap_file_list(&mut value);
        assert_eq!(value["files"].as_array().unwrap().len(), 2);
        assert!(value.get("files_truncated").is_none());
    }
}
