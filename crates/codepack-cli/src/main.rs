//! Headless command-line interface for codepack (stage S10, `docs/__arch__/ROADMAP.md` §3).
//!
//! Everything this file does is: parse arguments, dispatch, turn the result into an
//! exit code. The work lives in [`commands`], and the contracts a caller depends on —
//! exit codes and the `--json` schema — live in [`exit`] and [`output`].

// A CLI is expected to write to stdout; the workspace lint targets library crates.
#![allow(clippy::print_stdout)]

mod allow;
mod baseline;
mod cli;
mod commands;
mod error;
mod exit;
mod history_scan;
mod mcp;
mod output;
mod settings;
mod staged;

use clap::Parser;

use crate::cli::{Cli, Command};
use crate::output::Format;

fn main() -> std::process::ExitCode {
    // Argument errors exit with code 2. Handled explicitly rather than letting `clap`
    // call `exit` for us: the code is part of this binary's published contract
    // (`docs/__arch__/ROADMAP.md` §3), so it should be visible here and not depend on a default in a
    // dependency that could change.
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let _ = error.print();
            // `--help` and `--version` arrive here as "errors" too, and asking for help
            // is not a usage error: a script running `codepack --help` to check the
            // binary works must see 0.
            let code = match error.kind() {
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => {
                    exit::SUCCESS
                }
                _ => exit::BAD_ARGUMENTS,
            };
            return std::process::ExitCode::from(code as u8);
        }
    };
    let format = Format::from_flag(cli.json);

    let result = match cli.command {
        Command::Export(args) => commands::export::run(&args, format),
        Command::Preview(args) => commands::preview::run(&args, format),
        Command::Scan(args) => commands::scan::run(&args, format),
        Command::History(args) => commands::history::run(&args, format),
        Command::Doctor => commands::doctor::run(format),
        Command::Sanitize(args) => commands::sanitize::run(&args, format),
        Command::Completions(args) => Ok(commands::completions::run(&args)),
        Command::Verify(args) => commands::verify::run(&args, format),
        Command::Explain(args) => commands::explain::run(&args, format),
        Command::Handoff(args) => commands::handoff::run(&args, format),
        Command::Init(args) => commands::init::run(&args, format),
        Command::Mcp => mcp::run(),
    };

    if let Err(error) = &result {
        report_error(error, format);
    }

    // `u8` is what ExitCode carries; every code in the contract fits.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    std::process::ExitCode::from(exit::resolve(&result) as u8)
}

/// An error message that has been through redaction, and the only thing
/// [`report_error`] will print.
///
/// A newtype rather than a rule to remember. The desktop shell reached this conclusion
/// first and wrote down why: an I/O error names the path it failed on, a parse error can
/// quote the line it choked on, and both reach a screen. The CLI's version of that screen
/// is a CI build log, which is stored and often public — shared at least as readily as
/// the crash screenshots the GUI protects against (audit No. 11).
///
/// The private field is the point: outside this module there is no way to construct one
/// except through [`RenderedError::of`], so "somebody printed the error directly" is not
/// a mistake that can be made here.
struct RenderedError(String);

impl RenderedError {
    /// `redact_secrets`, not the wider `redacted_line` the desktop uses.
    ///
    /// `redacted_line` collapses everything after the first separator whenever the line
    /// mentions a scan keyword. That is right for a quoted line of somebody's source and
    /// wrong for this binary's own prose: it turned "nothing to do: pass --hook to
    /// install the pre-commit hook" into "nothing to do: <REDACTED>", because `pass`
    /// carries a keyword root. An unreadable error is its own kind of failure.
    ///
    /// The narrower function still masks the `KEY=value` shape a leaked credential
    /// actually takes, and the concrete leak audit No. 11 found — `serde_json::Error`
    /// quoting the value it choked on — is fixed at its source in
    /// `CoreError::invalid_json`, which now carries a position instead. This pass is the
    /// second line, not the only one.
    fn of(error: &error::CliError) -> Self {
        Self(codepack_security::redact_secrets(&error.to_string()))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

/// Errors always go to stderr, in both modes: a `--json` consumer parsing stdout must
/// not receive an error object where a result was promised, and a human redirecting
/// stdout to a file still wants to see what went wrong.
fn report_error(error: &error::CliError, format: Format) {
    let rendered = RenderedError::of(error);
    if format.is_json() {
        let payload = serde_json::json!({
            "schema_version": output::JSON_SCHEMA_VERSION,
            "error": rendered.as_str(),
        });
        output::note(
            serde_json::to_string_pretty(&payload)
                .unwrap_or_else(|_| rendered.as_str().to_string()),
        );
    } else {
        output::note(format!("error: {}", rendered.as_str()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The twin of the desktop shell's own test. An error message reaches stderr and, in
    /// CI, a stored build log; a credential must not travel with it.
    #[test]
    fn a_secret_in_an_error_message_is_redacted_before_it_can_be_printed() {
        let error =
            error::CliError::message("cannot parse API_KEY=totally-fake-value-0001 from settings");

        let rendered = RenderedError::of(&error);

        assert!(
            !rendered.as_str().contains("totally-fake-value-0001"),
            "{}",
            rendered.as_str()
        );
        assert!(
            rendered.as_str().contains("<REDACTED>"),
            "{}",
            rendered.as_str()
        );
    }

    /// Over-redaction would make errors useless, so the ordinary case has to survive
    /// intact — the same balance the desktop's test strikes.
    #[test]
    fn an_ordinary_error_is_left_readable() {
        let error = error::CliError::message("no such file or directory: reports/insights");
        assert_eq!(
            RenderedError::of(&error).as_str(),
            "no such file or directory: reports/insights"
        );
    }

    /// The regression that picked the redactor. The wide `redacted_line` collapses a
    /// line that mentions a scan keyword, and this message mentions `pass` — it came out
    /// as "nothing to do: <REDACTED>", which tells the user nothing at all. This is the
    /// binary's own prose, not a quoted line of somebody's source.
    #[test]
    fn a_message_that_merely_mentions_a_keyword_is_not_collapsed() {
        let error =
            error::CliError::message("nothing to do: pass --hook to install the pre-commit hook");
        assert_eq!(
            RenderedError::of(&error).as_str(),
            "nothing to do: pass --hook to install the pre-commit hook"
        );
    }
}
