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

/// Errors always go to stderr, in both modes: a `--json` consumer parsing stdout must
/// not receive an error object where a result was promised, and a human redirecting
/// stdout to a file still wants to see what went wrong.
fn report_error(error: &error::CliError, format: Format) {
    if format.is_json() {
        let payload = serde_json::json!({
            "schema_version": output::JSON_SCHEMA_VERSION,
            "error": error.to_string(),
        });
        output::note(serde_json::to_string_pretty(&payload).unwrap_or_else(|_| error.to_string()));
    } else {
        output::note(format!("error: {error}"));
    }
}
