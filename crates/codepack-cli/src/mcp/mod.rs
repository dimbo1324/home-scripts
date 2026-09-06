//! `codepack mcp` — the third entry point, for an agent rather than a person.
//!
//! ## What it is for
//!
//! Until this existed, handing a project to an assistant was a manual gesture: a human
//! exported a bundle and passed it over. The assistant could read what it was given and
//! nothing else — so when a file was missing from the bundle it had no way to ask why,
//! and its only options were to guess or to assume the file does not exist.
//!
//! This closes that loop without a single network call. An agent already running on
//! this machine speaks JSON-RPC over a pipe and can ask the same four questions a
//! person asks at the terminal: what would an export include, is there a secret here,
//! why is this one file missing, produce the bundle.
//!
//! ## Why it is not a new crate
//!
//! It was scoped as "a thin crate over `codepack-engine`", and reading the code changed
//! that. `preview`, `scan` and `explain` are not engine calls: they are this binary's
//! four-layer configuration resolution, the deliberate forcing of safe mode to `full`
//! for scanning, budget handling, and the report shapes other people's pipelines
//! already consume. A separate crate would have had to restate all of it, and the two
//! would have drifted — the first symptom being an agent contradicting the CLI about
//! the same project.
//!
//! So the transport lives here and calls the same builders the commands call. The whole
//! module is protocol plumbing; it decides nothing about exporting.
//!
//! ## Invariant I1 is untouched
//!
//! stdio, not HTTP. No dependency was added — `serde_json` was already here — so no
//! manifest gained a network client and the gate's `network isolation` step reads
//! exactly what it read before. A tool call runs locally and writes only where the
//! command it wraps would write.
//!
//! ## stdout is the protocol
//!
//! Nothing but JSON-RPC may ever reach stdout, which is the rule `--json` already lives
//! by, applied to a stream a machine parses continuously rather than once. Diagnostics
//! go to stderr. This is why the export tool runs quiet.

mod protocol;
mod resources;
mod tools;

use std::io::{BufRead, Write};

use serde_json::{Value, json};

use protocol::{
    INVALID_PARAMS, INVALID_REQUEST, METHOD_NOT_FOUND, PARSE_ERROR, PROTOCOL_VERSION, Request,
    Response, SERVER_NAME,
};

use crate::error::Result;
use crate::exit::Outcome;

/// Serves until stdin closes.
///
/// Closing stdin is how an MCP client shuts a server down, so end-of-input is a normal
/// exit and not an error. A server that treated it as one would make every clean
/// disconnect look like a crash in the client's logs.
pub(crate) fn run() -> Result<Outcome> {
    // The reader thread is **detached**, not scoped. `serve` uses `thread::scope`, which
    // must join the reader before it can return — and the reader is blocked in
    // `read_line` until stdin closes. So a session that ended because *stdout* broke (a
    // client that stopped listening) left the process alive, holding its stdio and its
    // temporary directories, while the client believed it had gone away (audit No. 18).
    //
    // Nothing is lost by not joining: the thread owns its own stdin handle and does
    // nothing but forward lines, so the process exiting is a complete and correct end for
    // it. `serve` keeps the scoped form because a test drives it with a finite input,
    // where the join always returns.
    //
    // A `BufReader` over `Stdin` rather than `stdin().lock()`: a `StdinLock` holds a
    // mutex guard that cannot cross a thread boundary.
    let (sender, receiver) = std::sync::mpsc::channel::<std::io::Result<String>>();
    std::thread::spawn(move || {
        forward_lines(&mut std::io::BufReader::new(std::io::stdin()), &sender);
    });

    let mut stdout = std::io::stdout();
    // A broken pipe is how a client that has stopped listening looks from here, and it
    // is a normal end of session rather than a failure to report to nobody.
    match session(&mut Incoming::new(&receiver), &mut stdout) {
        Ok(()) => Ok(Outcome::Success),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(Outcome::Success),
        Err(error) => Err(crate::error::CliError::message(format!(
            "the MCP session ended: {error}"
        ))),
    }
}

/// The read/dispatch/write loop, over any pair of streams so it can be driven by a test
/// without a process.
///
/// Test-only since audit No. 18: the real session runs from [`run`], which detaches its
/// reader instead of scoping it. A scope must join, and joining a thread blocked in
/// `read_line` is what kept a process alive after its stdout had gone. A test's input is
/// finite, so the join always returns there.
///
/// ## Why there is a second thread
///
/// A tool call used to hold this loop, which meant `notifications/cancelled` could not
/// be seen until the call it wanted to cancel had already finished. Input is therefore
/// read by its own thread and handed over a channel, so the loop can watch for that
/// notification *while* a call runs.
///
/// Still one request at a time. Anything else arriving mid-call is queued and answered
/// in order afterwards, exactly as it would have been before — the change buys
/// cancellation, not concurrency, and pretending otherwise would mean two exports
/// writing into one staging directory.
#[cfg(test)]
fn serve(input: &mut (dyn BufRead + Send), output: &mut dyn Write) -> std::io::Result<()> {
    std::thread::scope(|scope| {
        let (sender, receiver) = std::sync::mpsc::channel::<std::io::Result<String>>();
        scope.spawn(move || forward_lines(input, &sender));
        session(&mut Incoming::new(&receiver), output)
    })
}

/// Reads lines from `input` and forwards them until the input ends or nobody is
/// listening. The body of the reader thread, shared by [`run`] and [`serve`].
fn forward_lines(
    input: &mut (dyn BufRead + Send),
    sender: &std::sync::mpsc::Sender<std::io::Result<String>>,
) {
    let mut line = String::new();
    loop {
        line.clear();
        match input.read_line(&mut line) {
            // End of input: the client closed the pipe, which is a normal shutdown.
            // Dropping the sender is what tells the loop.
            Ok(0) => break,
            Ok(_) => {
                if sender.send(Ok(line.clone())).is_err() {
                    break;
                }
            }
            Err(error) => {
                let _ = sender.send(Err(error));
                break;
            }
        }
    }
}

/// Lines waiting to be handled: from the reader thread, and from mid-call arrivals.
struct Incoming<'a> {
    lines: &'a std::sync::mpsc::Receiver<std::io::Result<String>>,
    /// Read while a tool call was running, to be handled in arrival order once it ends.
    queued: std::collections::VecDeque<String>,
    /// The reader thread has stopped: end of input, or the error below.
    closed: bool,
    /// A read failure, reported once the current call has been answered. Answering
    /// first matters — the client is blocked on that response, and dropping it to
    /// report an error nobody is reading would be the worse of the two.
    error: Option<std::io::Error>,
}

impl<'a> Incoming<'a> {
    fn new(lines: &'a std::sync::mpsc::Receiver<std::io::Result<String>>) -> Self {
        Self {
            lines,
            queued: std::collections::VecDeque::new(),
            closed: false,
            error: None,
        }
    }

    fn absorb(&mut self, message: std::io::Result<String>) {
        match message {
            Ok(line) => self.queued.push_back(line),
            Err(error) => {
                self.error = Some(error);
                self.closed = true;
            }
        }
    }

    /// The next line, waiting for one if necessary. `None` ends the session.
    fn next_line(&mut self) -> Option<String> {
        if let Some(line) = self.queued.pop_front() {
            return Some(line);
        }
        if self.closed {
            return None;
        }
        match self.lines.recv() {
            Ok(message) => {
                self.absorb(message);
                self.queued.pop_front()
            }
            Err(_) => {
                self.closed = true;
                None
            }
        }
    }

    /// Whatever has arrived, without waiting long. For use while a call is running.
    ///
    /// What is already in hand comes first, and only then does `closed` end the answer.
    /// The other order dropped a line that had arrived just before the input closed —
    /// including a `notifications/cancelled`, which is the one message this function
    /// exists to catch (audit No. 18).
    fn poll(&mut self) -> Option<String> {
        if let Some(line) = self.queued.pop_front() {
            return Some(line);
        }
        if self.closed {
            return None;
        }
        match self
            .lines
            .recv_timeout(std::time::Duration::from_millis(25))
        {
            Ok(message) => {
                self.absorb(message);
                self.queued.pop_front()
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => None,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                self.closed = true;
                None
            }
        }
    }
}

fn session(incoming: &mut Incoming<'_>, output: &mut dyn Write) -> std::io::Result<()> {
    while let Some(line) = incoming.next_line() {
        let trimmed = line.trim().to_string();
        // Blank lines between messages are not a protocol error; ignoring them costs
        // nothing and refusing them would break a client that pads its output.
        if trimmed.is_empty() {
            continue;
        }

        let response = match pending_tool_call(&trimmed) {
            Some(call) => Some(run_tool_call(call, incoming)),
            None => handle_line(&trimmed),
        };

        if let Some(response) = response {
            output.write_all(response.to_line().as_bytes())?;
            // Flushed per message: a client is blocked waiting for this answer, and a
            // buffered response is indistinguishable from a hung server.
            output.flush()?;
        }
    }
    match incoming.error.take() {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// A `tools/call` request this loop should run on a worker thread.
struct ToolCall {
    id: Value,
    name: String,
    arguments: Value,
}

/// Recognises a well-formed `tools/call`, and nothing else.
///
/// A malformed one falls through to [`handle_line`], which already knows how to say what
/// is wrong with it. This function's only job is deciding what needs a worker thread.
fn pending_tool_call(line: &str) -> Option<ToolCall> {
    let request: Request = serde_json::from_str(line).ok()?;
    if !request.is_valid_envelope() || request.is_notification() || request.method != "tools/call" {
        return None;
    }
    let params = request.params.as_ref()?;
    let name = params.get("name").and_then(Value::as_str)?.to_string();
    Some(ToolCall {
        id: request.id.clone().unwrap_or(Value::Null),
        name,
        arguments: params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({})),
    })
}

/// Runs one tool call while staying able to hear the client.
///
/// Everything arriving meanwhile is queued, except a cancellation naming *this* request,
/// which trips the token the tool is holding. A cancelled tool still answers: the
/// pipeline returns what it managed to do and says it was cancelled, which is more use
/// to a client than silence and is what the contract already promises.
fn run_tool_call(call: ToolCall, incoming: &mut Incoming<'_>) -> Response {
    let cancel = codepack_core::CancellationToken::new();
    let name = call.name.clone();
    let arguments = call.arguments.clone();
    let worker = {
        let cancel = cancel.clone();
        std::thread::spawn(move || tools::call_with_cancel(&name, &arguments, &cancel))
    };

    // Lines that are not this call's cancellation are held aside rather than put back
    // into `queued`. `poll` now answers from `queued` first, so returning them there
    // would hand the same line out again on the next turn of this loop, forever.
    let mut deferred: Vec<String> = Vec::new();
    while !worker.is_finished() {
        match incoming.poll() {
            Some(line) if cancels(&line, &call.id) => cancel.cancel(),
            Some(line) => deferred.push(line),
            // Nothing arrived. When input is still open the poll already waited; once it
            // has closed there is nothing left to wait on, so wait deliberately rather
            // than spinning a core until the worker finishes.
            None => {
                if incoming.closed {
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
            }
        }
    }
    // Back at the front, in arrival order, so the session handles them before anything
    // that arrives after this call.
    for line in deferred.into_iter().rev() {
        incoming.queued.push_front(line);
    }

    let result = match worker.join() {
        Ok(outcome) => outcome_to_result(outcome),
        // A panicking tool is a defect in this binary, not a protocol fault, so it comes
        // back the way any other tool failure does: a successful result carrying a
        // message the model can read.
        Err(_) => json!({
            "content": [{
                "type": "text",
                "text": "the tool panicked; this is a bug in codepack, not in the request"
            }],
            "isError": true
        }),
    };
    Response::success(call.id, result)
}

/// Whether `line` is `notifications/cancelled` naming `id`.
///
/// A cancellation for some other request is not this call's business and is queued like
/// anything else; acting on it here would stop work the client still wants.
fn cancels(line: &str, id: &Value) -> bool {
    let Ok(request) = serde_json::from_str::<Request>(line) else {
        return false;
    };
    if request.method != "notifications/cancelled" {
        return false;
    }
    request
        .params
        .as_ref()
        .and_then(|params| params.get("requestId"))
        .is_some_and(|requested| requested == id)
}

/// One incoming line to at most one outgoing response. `None` means silence is the
/// correct answer, which is the case for every notification.
fn handle_line(line: &str) -> Option<Response> {
    let request: Request = match serde_json::from_str(line) {
        Ok(request) => request,
        Err(error) => {
            // The id is unknown for unparseable input, and the specification says to
            // answer with a null id rather than to stay silent — otherwise a client
            // that mis-sent one message waits forever.
            return Some(Response::failure(
                Value::Null,
                PARSE_ERROR,
                format!("could not parse the message: {error}"),
            ));
        }
    };

    if !request.is_valid_envelope() {
        let id = request.id.clone().unwrap_or(Value::Null);
        return Some(Response::failure(
            id,
            INVALID_REQUEST,
            "this transport speaks JSON-RPC 2.0",
        ));
    }

    if request.is_notification() {
        // `notifications/initialized`, `notifications/cancelled` and anything else a
        // client announces. Nothing here is long-running enough to interrupt between
        // messages — a tool call blocks the loop — so cancellation is acknowledged by
        // being ignored rather than pretended to.
        return None;
    }

    let id = request.id.clone().unwrap_or(Value::Null);
    Some(match request.method.as_str() {
        "initialize" => Response::success(id, initialize_result()),
        "ping" => Response::success(id, json!({})),
        "tools/list" => Response::success(id, json!({"tools": tools::catalogue()})),
        "resources/list" => Response::success(id, json!({"resources": resources::list()})),
        "resources/read" => match read_resource(request.params.as_ref()) {
            Ok(result) => Response::success(id, result),
            Err(message) => Response::failure(id, INVALID_PARAMS, message),
        },
        "tools/call" => match call_result(request.params.as_ref()) {
            Ok(result) => Response::success(id, result),
            Err(message) => Response::failure(id, INVALID_PARAMS, message),
        },
        other => Response::failure(
            id,
            METHOD_NOT_FOUND,
            format!("this server does not implement {other:?}"),
        ),
    })
}

/// Turns `resources/read` parameters into contents.
///
/// A URI this session did not produce is an `Err`, which the caller turns into a
/// JSON-RPC error rather than an empty success — asking for something that is not there
/// is a mistake in the request, and answering it with silence would leave a model
/// believing the file was empty.
fn read_resource(params: Option<&Value>) -> std::result::Result<Value, String> {
    let uri = params
        .and_then(|params| params.get("uri"))
        .and_then(Value::as_str)
        .ok_or("resources/read needs a `uri`")?;
    resources::read(uri)
}

fn initialize_result() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        // Tools and resources. Still no prompts and no sampling: declaring a
        // capability this build does not implement would have clients calling into
        // nothing.
        //
        // `subscribe` is false and `listChanged` is false because the list only ever
        // changes as the direct result of a `codepack_export` the client itself asked
        // for — it already knows.
        "capabilities": {
            "tools": {"listChanged": false},
            "resources": {"subscribe": false, "listChanged": false}
        },
        "serverInfo": {
            "name": SERVER_NAME,
            "version": env!("CARGO_PKG_VERSION")
        },
        "instructions": "Ask codepack_preview what an export would contain before \
                         asking for one, and codepack_explain when a file you expected \
                         is missing from a bundle. After codepack_export, that bundle's \
                         reports are readable through resources/list and \
                         resources/read. Everything runs locally; nothing is uploaded."
    })
}

/// Turns `tools/call` parameters into a result.
///
/// `Err` here is a **protocol** failure — the parameters were not shaped like a tool
/// call at all. A tool that ran and failed comes back as `Ok` carrying `isError`, so
/// the model sees the message and can correct itself.
fn call_result(params: Option<&Value>) -> std::result::Result<Value, String> {
    let params = params.ok_or("tools/call needs params")?;
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or("tools/call needs a tool `name`")?;
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    Ok(outcome_to_result(tools::call(name, &arguments)))
}

/// One tool outcome in `tools/call` result shape.
fn outcome_to_result(outcome: tools::ToolOutcome) -> Value {
    let mut result = json!({
        "content": [{"type": "text", "text": outcome.text}],
        "isError": outcome.is_error
    });
    if let Some(structured) = outcome.structured
        && let Some(object) = result.as_object_mut()
    {
        object.insert("structuredContent".to_string(), structured);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A line already in hand is returned even after the input has closed. `poll`
    /// checked `closed` first, so a `notifications/cancelled` that arrived in the same
    /// breath as the client closing its pipe was dropped — the one message `poll` exists
    /// to catch (audit No. 18).
    #[test]
    fn a_queued_line_survives_the_input_closing() {
        let (sender, receiver) = std::sync::mpsc::channel::<std::io::Result<String>>();
        drop(sender);
        let mut incoming = Incoming::new(&receiver);
        incoming
            .queued
            .push_back("{\"method\":\"notifications/cancelled\"}".to_string());
        incoming.closed = true;

        assert_eq!(
            incoming.poll().as_deref(),
            Some("{\"method\":\"notifications/cancelled\"}")
        );
        // And once it has been handed over, the closed input is the answer again.
        assert!(incoming.poll().is_none());
    }

    /// Lines come back in the order they arrived, not reversed. `poll` used to take the
    /// newest of what it had, which would reorder a client's messages.
    #[test]
    fn polled_lines_keep_their_arrival_order() {
        let (sender, receiver) = std::sync::mpsc::channel::<std::io::Result<String>>();
        let mut incoming = Incoming::new(&receiver);
        incoming.queued.push_back("first".to_string());
        incoming.queued.push_back("second".to_string());
        drop(sender);

        assert_eq!(incoming.poll().as_deref(), Some("first"));
        assert_eq!(incoming.poll().as_deref(), Some("second"));
    }

    fn drive(input: &str) -> Vec<Value> {
        let mut output = Vec::new();
        serve(&mut input.as_bytes(), &mut output).unwrap();
        String::from_utf8(output)
            .unwrap()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("every line must be one JSON object"))
            .collect()
    }

    #[test]
    fn initialize_reports_the_version_the_tools_and_the_server() {
        let responses = drive("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n");

        assert_eq!(responses.len(), 1);
        let result = &responses[0]["result"];
        assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(result["serverInfo"]["name"], SERVER_NAME);
        assert!(result["capabilities"]["tools"].is_object());
        // Resources arrived with the bundle registry, so the declaration has to match:
        // a client either never asks for what is there, or asks for what is not.
        assert!(result["capabilities"]["resources"].is_object());
        assert_eq!(result["capabilities"]["resources"]["subscribe"], false);
        // Capabilities this build still does not implement must not be advertised.
        assert!(result["capabilities"].get("prompts").is_none());
        assert!(result["capabilities"].get("sampling").is_none());
    }

    #[test]
    fn a_notification_is_answered_with_silence() {
        // Answering one is a protocol violation some clients treat as fatal.
        let responses = drive(
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n\
             {\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n",
        );
        assert_eq!(responses.len(), 1, "the notification drew a reply");
        assert_eq!(responses[0]["id"], 1);
    }

    #[test]
    fn every_response_carries_the_id_it_was_asked_with() {
        let responses = drive(
            "{\"jsonrpc\":\"2.0\",\"id\":\"a\",\"method\":\"ping\"}\n\
             {\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n",
        );
        assert_eq!(responses[0]["id"], "a");
        assert_eq!(responses[1]["id"], 2);
    }

    #[test]
    fn tools_list_offers_the_four_tools() {
        let responses = drive("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n");
        let names: Vec<&str> = responses[0]["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "codepack_preview",
                "codepack_scan",
                "codepack_explain",
                "codepack_export"
            ]
        );
    }

    #[test]
    fn an_unknown_method_is_a_protocol_error_not_a_crash() {
        // `resources/list` used to stand in for "unknown" here; it is implemented now, so
        // the example moved to one that genuinely is not. The rule under test never
        // changed: a method this build does not know is answered, not crashed on.
        let responses = drive("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"prompts/list\"}\n");
        assert_eq!(responses[0]["error"]["code"], METHOD_NOT_FOUND);
    }

    #[test]
    fn unparseable_input_answers_with_a_null_id_rather_than_silence() {
        // Silence would leave the client waiting forever on a message it mis-sent.
        let responses = drive("this is not json\n");
        assert_eq!(responses[0]["error"]["code"], PARSE_ERROR);
        assert_eq!(responses[0]["id"], Value::Null);
    }

    #[test]
    fn a_blank_line_between_messages_is_not_an_error() {
        let responses = drive("\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n\n");
        assert_eq!(responses.len(), 1);
    }

    #[test]
    fn a_call_without_a_tool_name_is_a_parameter_error() {
        let responses =
            drive("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{}}\n");
        assert_eq!(responses[0]["error"]["code"], INVALID_PARAMS);
    }

    #[test]
    fn a_tool_that_fails_comes_back_as_a_result_the_model_can_read() {
        let responses = drive(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":\
             {\"name\":\"codepack_preview\",\"arguments\":{\"project\":\"/nowhere/at/all\"}}}\n",
        );
        assert!(responses[0]["error"].is_null(), "{}", responses[0]);
        assert_eq!(responses[0]["result"]["isError"], true);
        assert!(responses[0]["result"]["content"][0]["text"].is_string());
    }

    #[test]
    fn a_tool_that_succeeds_carries_both_text_and_structured_content() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.py"), "print(1)\n").unwrap();
        let line = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":\
             {{\"name\":\"codepack_explain\",\"arguments\":\
             {{\"project\":{project},\"file\":\"main.py\"}}}}}}\n",
            project = serde_json::to_string(&dir.path().display().to_string()).unwrap()
        );

        let responses = drive(&line);
        let result = &responses[0]["result"];
        assert_eq!(result["isError"], false, "{result}");
        assert_eq!(result["structuredContent"]["verdict"], "included");
        assert!(
            result["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("included")
        );
    }

    #[test]
    fn a_session_survives_a_bad_message_in_the_middle_of_it() {
        // A client that mis-sends one message must not lose the connection: the
        // failure is per-message, not per-session.
        let responses = drive(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n\
             {oops\n\
             {\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n",
        );
        assert_eq!(responses.len(), 3);
        assert_eq!(responses[0]["id"], 1);
        assert_eq!(responses[1]["error"]["code"], PARSE_ERROR);
        assert_eq!(responses[2]["id"], 2);
    }

    #[test]
    fn closing_the_input_ends_the_session_cleanly() {
        // How an MCP client shuts a server down. Treating it as an error would make
        // every clean disconnect look like a crash.
        assert!(drive("").is_empty());
    }

    // --- The loop's new shape (2026-09-05) -------------------------------------------

    #[test]
    fn a_tool_call_is_recognised_as_needing_a_worker() {
        let call = pending_tool_call(
            r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"codepack_preview","arguments":{"project":"."}}}"#,
        )
        .expect("a well-formed tool call");
        assert_eq!(call.id, json!(7));
        assert_eq!(call.name, "codepack_preview");
        assert_eq!(call.arguments["project"], ".");
    }

    /// Everything else falls through to the ordinary handler, which already knows how to
    /// say what is wrong with it.
    #[test]
    fn anything_that_is_not_a_tool_call_falls_through() {
        for line in [
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x"}}"#, // a notification
            r#"{"jsonrpc":"1.0","id":1,"method":"tools/call","params":{"name":"x"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#, // no params
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}"#, // no name
            "not json",
        ] {
            assert!(pending_tool_call(line).is_none(), "{line}");
        }
    }

    #[test]
    fn a_cancellation_matches_only_the_request_it_names() {
        let for_seven =
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7}}"#;
        assert!(cancels(for_seven, &json!(7)));
        assert!(!cancels(for_seven, &json!(8)));
        // A string id is a legal JSON-RPC id, and must match on its own terms.
        let for_abc =
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"abc"}}"#;
        assert!(cancels(for_abc, &json!("abc")));
        assert!(!cancels(for_abc, &json!(7)));
    }

    #[test]
    fn anything_that_is_not_a_cancellation_is_not_one() {
        for line in [
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled"}"#, // no params
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
            "not json",
        ] {
            assert!(!cancels(line, &json!(1)), "{line}");
        }
    }

    /// A cancellation for a call that is already over is simply a notification: answered
    /// with silence, never with an error.
    #[test]
    fn a_late_cancellation_is_answered_with_silence() {
        let responses = drive(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n\
             {\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":1}}\n",
        );
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0]["id"], 1);
    }

    /// Messages that arrive while a call runs are queued and answered afterwards, in
    /// order — the loop buys cancellation, not concurrency.
    #[test]
    fn messages_arriving_during_a_call_are_answered_in_order() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.py"), "print(1)\n").unwrap();
        let project = dir.path().display().to_string().replace('\\', "\\\\");

        let responses = drive(&format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{{\"name\":\"codepack_preview\",\"arguments\":{{\"project\":\"{project}\"}}}}}}\n\
             {{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}}\n\
             {{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\"}}\n"
        ));

        let ids: Vec<&Value> = responses.iter().map(|response| &response["id"]).collect();
        assert_eq!(ids, vec![&json!(1), &json!(2), &json!(3)]);
    }

    #[test]
    fn resources_are_listed_and_read_over_the_protocol() {
        // The registry is process-wide; without this the resources tests replace it
        // while this one is mid-session.
        let _lock = resources::test_guard();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("manifest.json"), "{\"listed\":true}").unwrap();
        super::resources::register_bundle(dir.path(), None);

        let responses = drive(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/list\"}\n\
             {\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"resources/read\",\"params\":{\"uri\":\"codepack://bundle/manifest.json\"}}\n",
        );

        let listed = responses[0]["result"]["resources"].as_array().unwrap();
        assert!(
            listed
                .iter()
                .any(|entry| entry["uri"] == "codepack://bundle/manifest.json"),
            "{listed:?}"
        );
        assert_eq!(
            responses[1]["result"]["contents"][0]["text"],
            "{\"listed\":true}"
        );
    }

    #[test]
    fn reading_a_resource_that_is_not_registered_is_a_protocol_error() {
        let _lock = resources::test_guard();
        let responses = drive(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\",\"params\":{\"uri\":\"file:///etc/passwd\"}}\n",
        );
        assert_eq!(responses[0]["error"]["code"], INVALID_PARAMS);
    }

    #[test]
    fn reading_without_a_uri_says_what_is_missing() {
        let responses =
            drive("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\",\"params\":{}}\n");
        assert_eq!(responses[0]["error"]["code"], INVALID_PARAMS);
        assert!(
            responses[0]["error"]["message"]
                .as_str()
                .unwrap()
                .contains("uri")
        );
    }
}
