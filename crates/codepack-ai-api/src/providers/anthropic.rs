//! Anthropic Messages API (`POST /v1/messages`), over raw HTTP.
//!
//! There is no official Anthropic SDK for Rust, so this is hand-written against the
//! documented wire format rather than generated. The surface used here is the smallest
//! that answers one question: model, system, one user message, a token cap.
//!
//! Two behaviours of the current models shape this code and are not obvious:
//!
//! * **`max_tokens` bounds thinking *and* the reply together.** Recent models think by
//!   default, so a cap sized for the answer alone truncates mid-sentence. The default
//!   here is deliberately generous.
//! * **A refusal is a successful HTTP 200**, carrying `stop_reason: "refusal"` and an
//!   empty or partial `content`. Code that reads `content[0]` without checking
//!   `stop_reason` first breaks on exactly the responses a user most needs explained,
//!   so the parse below checks the stop reason before it touches the content.

use std::time::Duration;

use serde::Deserialize;

use crate::provider::{AiAnswer, AiProvider, AiRequest, ModelInfo};
use codepack_ai::error::AiError;

const ENDPOINT: &str = "https://api.anthropic.com/v1/messages";

/// The API version header. Pinned, not tracked: Anthropic versions its API by date and
/// an unpinned client is one that breaks on somebody else's release schedule.
const API_VERSION: &str = "2023-06-01";

/// Generous on purpose. A large bundle plus thinking is a request measured in minutes,
/// and a client that gives up early turns a working call into a mysterious failure.
const TIMEOUT: Duration = Duration::from_secs(600);

pub const ID: &str = "anthropic";

const MODELS: &[ModelInfo] = &[
    ModelInfo {
        id: "claude-opus-5",
        display_name: "Claude Opus 5",
        context_tokens: 1_000_000,
    },
    ModelInfo {
        id: "claude-sonnet-5",
        display_name: "Claude Sonnet 5",
        context_tokens: 1_000_000,
    },
    ModelInfo {
        id: "claude-haiku-4-5",
        display_name: "Claude Haiku 4.5",
        context_tokens: 200_000,
    },
];

/// The default when no model is configured — the most capable of the three above.
pub const DEFAULT_MODEL: &str = "claude-opus-5";

pub struct Anthropic;

impl AiProvider for Anthropic {
    fn id(&self) -> &'static str {
        ID
    }

    fn display_name(&self) -> &'static str {
        "Anthropic (Claude)"
    }

    fn known_models(&self) -> &'static [ModelInfo] {
        MODELS
    }

    fn ask(&self, key: &str, request: &AiRequest) -> Result<AiAnswer, AiError> {
        let body = serde_json::json!({
            "model": request.model,
            "max_tokens": request.max_output_tokens,
            "system": request.system,
            "messages": [{ "role": "user", "content": request.user }],
        });

        let response = ureq::post(ENDPOINT)
            .config()
            .timeout_global(Some(TIMEOUT))
            .build()
            .header("x-api-key", key)
            .header("anthropic-version", API_VERSION)
            .header("content-type", "application/json")
            .send_json(&body);

        let mut response = match response {
            Ok(response) => response,
            Err(ureq::Error::StatusCode(status)) => {
                return Err(AiError::Status {
                    provider: ID.to_string(),
                    status,
                });
            }
            // The error's own Display is used rather than the response body: a provider
            // error payload can quote the request back, and the request is the user's
            // source code.
            Err(other) => {
                return Err(AiError::Transport {
                    provider: ID.to_string(),
                    kind: transport_kind(&other),
                });
            }
        };

        let parsed: MessageResponse =
            response
                .body_mut()
                .read_json()
                .map_err(|_| AiError::Malformed {
                    provider: ID.to_string(),
                })?;

        Ok(parsed.into_answer())
    }
}

/// A short, stable description of a transport failure — never the response body.
fn transport_kind(error: &ureq::Error) -> String {
    match error {
        ureq::Error::Timeout(_) => "timed out".to_string(),
        ureq::Error::ConnectionFailed => "could not connect".to_string(),
        ureq::Error::HostNotFound => "host not found".to_string(),
        _ => "transport error".to_string(),
    }
}

#[derive(Debug, Deserialize)]
struct MessageResponse {
    model: String,
    #[serde(default)]
    content: Vec<ContentBlock>,
    #[serde(default)]
    stop_reason: Option<String>,
    #[serde(default)]
    usage: Option<Usage>,
}

#[derive(Debug, Deserialize)]
struct ContentBlock {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Usage {
    #[serde(default)]
    input_tokens: Option<u64>,
    #[serde(default)]
    output_tokens: Option<u64>,
}

impl MessageResponse {
    fn into_answer(self) -> AiAnswer {
        // Only `text` blocks are joined. A response can also carry `thinking` blocks,
        // whose text is empty by default on current models and is not the answer in any
        // case — concatenating everything would surface reasoning as if it were output.
        let text = self
            .content
            .iter()
            .filter(|block| block.kind == "text")
            .filter_map(|block| block.text.as_deref())
            .collect::<Vec<_>>()
            .join("\n");

        let stopped_early = match self.stop_reason.as_deref() {
            // Not an error: the model finished normally.
            Some("end_turn") | Some("stop_sequence") | None => None,
            Some("max_tokens") => Some("max_tokens".to_string()),
            Some("refusal") => Some("refusal".to_string()),
            Some(other) => Some(other.to_string()),
        };

        AiAnswer {
            text,
            model: self.model,
            input_tokens: self.usage.as_ref().and_then(|u| u.input_tokens),
            output_tokens: self.usage.as_ref().and_then(|u| u.output_tokens),
            stopped_early,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> AiAnswer {
        serde_json::from_str::<MessageResponse>(json)
            .unwrap()
            .into_answer()
    }

    #[test]
    fn a_normal_reply_yields_its_text_and_no_early_stop() {
        let answer = parse(
            r#"{"model":"claude-opus-5","stop_reason":"end_turn",
                "content":[{"type":"text","text":"hello"}],
                "usage":{"input_tokens":10,"output_tokens":2}}"#,
        );
        assert_eq!(answer.text, "hello");
        assert_eq!(answer.stopped_early, None);
        assert_eq!(answer.input_tokens, Some(10));
        assert_eq!(answer.output_tokens, Some(2));
    }

    #[test]
    fn thinking_blocks_are_not_mistaken_for_the_answer() {
        // Current models return thinking blocks whose text is empty by default. Joining
        // every block would put reasoning — or a blank line standing in for it — into
        // what the user reads as the reply.
        let answer = parse(
            r#"{"model":"claude-opus-5","stop_reason":"end_turn",
                "content":[{"type":"thinking","thinking":""},
                           {"type":"text","text":"the answer"}]}"#,
        );
        assert_eq!(answer.text, "the answer");
    }

    #[test]
    fn a_refusal_is_reported_rather_than_read_as_an_empty_answer() {
        // A refusal arrives as HTTP 200 with empty content. Without the stop-reason
        // check this would surface to the user as "the model replied with nothing".
        let answer = parse(r#"{"model":"claude-opus-5","stop_reason":"refusal","content":[]}"#);
        assert_eq!(answer.text, "");
        assert_eq!(answer.stopped_early, Some("refusal".to_string()));
    }

    #[test]
    fn hitting_the_output_cap_is_surfaced() {
        let answer = parse(
            r#"{"model":"claude-opus-5","stop_reason":"max_tokens",
                "content":[{"type":"text","text":"partial"}]}"#,
        );
        assert_eq!(answer.stopped_early, Some("max_tokens".to_string()));
    }

    #[test]
    fn a_response_missing_optional_fields_still_parses() {
        // Defensive: a provider adding or omitting an optional field must not turn a
        // successful call into a parse failure the user cannot act on.
        let answer = parse(r#"{"model":"claude-opus-5","content":[]}"#);
        assert_eq!(answer.text, "");
        assert_eq!(answer.input_tokens, None);
    }

    #[test]
    fn the_default_model_is_one_this_build_knows() {
        assert!(MODELS.iter().any(|m| m.id == DEFAULT_MODEL));
    }
}
