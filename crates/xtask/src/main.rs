//! Task runner and quality gate for the codepack workspace.
//!
//! Run with `cargo xtask <command>`; see `.ai/project/11-commands.md`.

// A task runner is expected to write to stdout; the workspace lint targets libraries.
#![allow(clippy::print_stdout)]

mod ai_api;
mod frontend;
mod golden;
mod hooks;
mod ignored_advisories;
mod network_isolation;
mod report_redaction;
mod scripts;
mod sync_agents;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const USAGE: &str = "\
codepack task runner

Usage: cargo xtask <command> [options]

Commands:
  gate [--quick]          Full quality gate; --quick skips the test and dev-scripts runs
  fmt                     Format Rust and frontend sources in place
  lint                    Clippy across the workspace with warnings denied
  test                    Run workspace tests
  deny                    cargo-deny: advisories, bans, licenses, sources
  sync-agents [--check]   Regenerate AGENTS.md from the .ai/ modules
  install-hooks           Install the formatting pre-commit hook
  package                 Build the Windows NSIS installer
  golden                  Regenerate golden references by running legacy (needs Python)
  ai-api                  Format, lint and test codepack-ai-api, which the gate cannot see
  doctor                  Read-only environment diagnostics
";

fn repo_root() -> PathBuf {
    // crates/xtask -> crates -> repository root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("xtask always lives two levels below the repository root")
        .to_path_buf()
}

fn run(root: &Path, program: &str, args: &[&str]) -> bool {
    println!("$ {program} {}", args.join(" "));
    match Command::new(program).args(args).current_dir(root).status() {
        Ok(status) => status.success(),
        Err(error) => {
            eprintln!("failed to launch `{program}`: {error}");
            false
        }
    }
}

/// The `tests` section, with the names of whatever failed.
///
/// `step` would do, and did — but a failing test section under CI then reported only that
/// the section failed. The log that holds the test names needs admin rights on the
/// repository to read, which is the same wall that left Q21 unresolved one level up. So
/// this one captures cargo's output, prints it through unchanged for anyone who *can* read
/// the log, and additionally emits one annotation per failed test.
///
/// Capturing means the output arrives at the end rather than streaming. That is a real
/// cost and it is why only this section pays it: the test run is the one whose failure is
/// a list of names rather than a single message.
///
/// `--no-fail-fast` for the same reason. Without it cargo stops at the first failing test
/// binary, so a red run names one crate's failures and hides the rest — and each CI round
/// then reveals exactly one crate's worth. When a round costs a push and a wait, the list
/// has to be complete the first time.
fn run_tests(root: &Path) -> Result<(), String> {
    println!("\n=== tests ===");
    println!("$ cargo test --workspace --no-fail-fast");

    let output = Command::new("cargo")
        .args(["test", "--workspace", "--no-fail-fast"])
        .current_dir(root)
        .output()
        .map_err(|error| format!("failed to launch `cargo`: {error}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    print!("{stdout}");
    eprint!("{stderr}");

    if output.status.success() {
        return Ok(());
    }

    if std::env::var_os("CI").is_some() {
        let details = failure_details(&stdout);
        for name in failed_test_names(&stdout) {
            match details.get(&name) {
                Some(reason) if !reason.is_empty() => {
                    println!(
                        "::error title=failing test::{name}%0A{}",
                        annotation_body(reason)
                    );
                }
                _ => println!("::error title=failing test::{name}"),
            }
        }
    }
    Err("tests".to_string())
}

/// What each failed test printed, keyed by name.
///
/// The name says which test broke; this says why. Without it every diagnosis costs
/// another push and another CI round, which is the same shape of problem the annotations
/// were added to solve one level up — the assertion message exists only in the log, and
/// the log needs admin rights on the repository.
///
/// Cargo prints a failed test's captured output under `---- <name> stdout ----`, which is
/// where the panic line and any assertion message land.
fn failure_details(stdout: &str) -> BTreeMap<String, String> {
    let mut details: BTreeMap<String, String> = BTreeMap::new();
    let mut current: Option<(String, Vec<&str>)> = None;
    let finish = |current: Option<(String, Vec<&str>)>, details: &mut BTreeMap<_, _>| {
        if let Some((name, body)) = current {
            details.insert(name, body.join("\n").trim().to_string());
        }
    };

    for line in stdout.lines() {
        if let Some(name) = line
            .strip_prefix("---- ")
            .and_then(|rest| rest.strip_suffix(" stdout ----"))
        {
            finish(current.take(), &mut details);
            current = Some((name.to_string(), Vec::new()));
        } else if line.trim() == "failures:" {
            // The name list follows, and it is not part of the last test's output.
            finish(current.take(), &mut details);
        } else if let Some((_, body)) = current.as_mut() {
            body.push(line);
        }
    }
    finish(current, &mut details);
    details
}

/// One captured output, made safe and short enough to travel as an annotation.
///
/// A workflow command reads `%`, CR and LF as its own structure, so an unescaped panic
/// message silently truncates the annotation at the first newline. The clip keeps the
/// first lines, which is where the panic and the assertion message are; a backtrace below
/// them is not worth the width.
fn annotation_body(reason: &str) -> String {
    const LIMIT: usize = 600;
    let clipped: String = reason.chars().take(LIMIT).collect();
    let clipped = if clipped.len() < reason.len() {
        format!("{clipped}…")
    } else {
        clipped
    };
    clipped
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

/// Test names from cargo's `failures:` block.
///
/// That block rather than the `test x ... FAILED` lines: the block is printed once per
/// binary as a plain list, so it needs no parsing of cargo's status formatting, and it
/// omits the tests that merely ran. A name is a line indented by four spaces inside the
/// block; the block ends at the blank line before the result summary.
fn failed_test_names(stdout: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_block = false;
    for line in stdout.lines() {
        if line.trim() == "failures:" {
            // Cargo prints `failures:` twice per binary — once heading the output of each
            // failed test, once heading the name list. Only the second is a list of bare
            // names, and the first is followed by `---- name stdout ----` lines, which do
            // not match the four-space rule below.
            in_block = true;
            continue;
        }
        if !in_block {
            continue;
        }
        match line.strip_prefix("    ") {
            Some(name) if !name.is_empty() && !name.starts_with('-') => {
                let name = name.trim().to_string();
                if !names.contains(&name) {
                    names.push(name);
                }
            }
            _ => in_block = false,
        }
    }
    names
}

fn step(root: &Path, label: &str, program: &str, args: &[&str]) -> Result<(), String> {
    println!("\n=== {label} ===");
    if run(root, program, args) {
        Ok(())
    } else {
        Err(label.to_string())
    }
}

fn gate(root: &Path, quick: bool) -> Result<(), String> {
    step(root, "format", "cargo", &["fmt", "--all", "--check"])?;
    // `--all` covers workspace members; `codepack-ai-api` is excluded, so it needs its
    // own invocation. Formatting compiles nothing, so this costs none of what the
    // exclusion bought — and without it the one crate nobody builds routinely would be
    // the one crate whose formatting nobody checks.
    step(
        root,
        "format (ai-api)",
        "cargo",
        &[
            "fmt",
            "--manifest-path",
            "crates/codepack-ai-api/Cargo.toml",
            "--",
            "--check",
        ],
    )?;
    step(
        root,
        "clippy",
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    if !quick {
        run_tests(root)?;
    }
    step(root, "deny", "cargo", &["deny", "check"])?;
    if !quick {
        // Reporting only: an ignore entry that has stopped matching is housekeeping,
        // and turning a dependency update into a red gate would teach people to delete
        // the check rather than the entry. Out of the quick gate because it runs
        // `cargo deny` a second time.
        println!("\n=== ignored advisories ===");
        ignored_advisories::check(root)?;
    }
    println!("\n=== frontend ===");
    if frontend::require_or_skip(root)? {
        frontend::gate_checks(root)?;
    }
    if !quick {
        println!("\n=== dev scripts ===");
        scripts::gate_checks(root)?;
    }
    println!("\n=== agents sync ===");
    sync_agents::run(root, true).map_err(|error| format!("sync-agents: {error}"))?;
    // Source-only, so it runs in the quick gate too: a report that starts reading raw
    // file content looks like any other line of code, and the cost of missing one is a
    // credential in a bundle somebody hands out.
    println!("\n=== report redaction ===");
    report_redaction::check(root)?;
    // Cheap and manifest-only, so it runs in the quick gate too: a crate that gains a
    // network client changes no behaviour until the day it makes a request, which is far
    // too late to notice.
    println!("\n=== network isolation ===");
    network_isolation::check(root)?;
    Ok(())
}

fn doctor(root: &Path) {
    println!("repository root: {}", root.display());
    for (label, program, args) in [
        ("cargo", "cargo", ["--version"]),
        ("rustc", "rustc", ["--version"]),
        ("cargo-deny", "cargo-deny", ["--version"]),
        ("node", "node", ["--version"]),
        // Not a bare "pnpm": see `frontend::PNPM`. `doctor` exists to answer "is my
        // environment ready", and the gate depends on pnpm — reporting "not found" for an
        // installed pnpm is the one wrong answer this command must not give.
        ("pnpm", frontend::PNPM, ["--version"]),
    ] {
        let reported = Command::new(program)
            .args(args)
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string());
        match reported {
            Some(version) => println!("  {label:<6} {version}"),
            None => println!("  {label:<6} not found"),
        }
    }
    let tauri = root.join("apps/desktop/src-tauri");
    println!(
        "  tauri  {}",
        if tauri.is_dir() {
            "present"
        } else {
            "absent (arrives in stage S11)"
        }
    );
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first() else {
        println!("{USAGE}");
        return ExitCode::from(2);
    };
    let root = repo_root();
    let has = |flag: &str| args.iter().any(|arg| arg == flag);

    let outcome = match command.as_str() {
        "gate" => gate(&root, has("--quick")),
        "fmt" => step(&root, "format", "cargo", &["fmt", "--all"])
            .and_then(|()| {
                step(
                    &root,
                    "format (ai-api)",
                    "cargo",
                    &[
                        "fmt",
                        "--manifest-path",
                        "crates/codepack-ai-api/Cargo.toml",
                    ],
                )
            })
            .and_then(|()| {
                println!("\n=== frontend format ===");
                if frontend::dependencies_installed(&root) {
                    frontend::format_write(&root)
                } else {
                    frontend::skip_notice();
                    Ok(())
                }
            }),
        "lint" => step(
            &root,
            "clippy",
            "cargo",
            &[
                "clippy",
                "--workspace",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ],
        ),
        "test" => step(&root, "tests", "cargo", &["test", "--workspace"]),
        "deny" => step(&root, "deny", "cargo", &["deny", "check"]),
        "sync-agents" => {
            sync_agents::run(&root, has("--check")).map_err(|error| format!("sync-agents: {error}"))
        }
        "install-hooks" => hooks::install(&root).map_err(|error| format!("install-hooks: {error}")),
        "package" => frontend::package(&root).map_err(|error| format!("package: {error}")),
        "golden" => golden::run(&root).map_err(|error| format!("golden: {error}")),
        "ai-api" => ai_api::check(&root),
        "doctor" => {
            doctor(&root);
            Ok(())
        }
        "-h" | "--help" | "help" => {
            println!("{USAGE}");
            Ok(())
        }
        unknown => {
            eprintln!("unknown command: {unknown}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(failed) => {
            eprintln!("\nFAILED: {failed}");
            // Under CI, say it again as a workflow annotation. The gate is one step made
            // of ten, and a step's log is readable only with admin rights on the
            // repository — so from outside, a failure is "exit code 1" and nothing more.
            // That is exactly why Q21 sat unresolved: the Unix gate failed and nobody
            // could see which of the ten sections did it. An annotation carries the name
            // out through the public API, where anyone looking at the run can read it.
            if std::env::var_os("CI").is_some() {
                println!("::error title=xtask gate::the `{failed}` section failed");
            }
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cargo's real shape, abbreviated: `failures:` appears twice per binary — once
    /// heading each failed test's captured output, once heading the list of names. Only
    /// the second is a list, and mistaking the first for one would annotate `---- … stdout
    /// ----` as a test name.
    const CARGO_OUTPUT: &str = "\
running 3 tests
test a_passing_one ... ok
test a_failing_one ... FAILED
test another_failing_one ... FAILED

failures:

---- a_failing_one stdout ----
thread 'a_failing_one' panicked at src/lib.rs:10:5:
assertion failed

---- another_failing_one stdout ----
thread 'another_failing_one' panicked at src/lib.rs:20:5:

failures:
    a_failing_one
    another_failing_one

test result: FAILED. 1 passed; 2 failed; 0 ignored
";

    #[test]
    fn the_failing_test_names_are_taken_from_the_name_list() {
        assert_eq!(
            failed_test_names(CARGO_OUTPUT),
            vec!["a_failing_one", "another_failing_one"]
        );
    }

    /// A green run names nothing, so a passing gate emits no annotations.
    #[test]
    fn a_run_with_no_failures_yields_no_names() {
        let green = "running 2 tests\ntest one ... ok\ntest two ... ok\n\n\
                     test result: ok. 2 passed; 0 failed; 0 ignored\n";
        assert!(failed_test_names(green).is_empty());
    }

    /// The name alone was never the useful half. This is the reason travelling with it.
    #[test]
    fn each_failing_test_carries_the_output_it_printed() {
        let details = failure_details(CARGO_OUTPUT);
        assert_eq!(details.len(), 2);
        assert!(
            details["a_failing_one"].starts_with("thread 'a_failing_one' panicked"),
            "{:?}",
            details["a_failing_one"]
        );
        assert!(details["a_failing_one"].ends_with("assertion failed"));
        // The `failures:` name list is not part of the last test's captured output.
        assert!(!details["another_failing_one"].contains("a_failing_one"));
    }

    /// A workflow command ends at the first newline, so an unescaped panic message would
    /// arrive as one line of a multi-line reason and the rest would vanish.
    #[test]
    fn an_annotation_body_escapes_what_a_workflow_command_would_eat() {
        let body = annotation_body("100%_PANIC\nsecond line");
        assert_eq!(body, "100%25_PANIC%0Asecond line");
    }

    /// Clipping keeps the head — the panic line and the assertion message — and says so.
    #[test]
    fn an_over_long_reason_is_clipped_rather_than_sent_whole() {
        let long = "x".repeat(1_000);
        let body = annotation_body(&long);
        assert_eq!(body.chars().count(), 601);
        assert!(body.ends_with('…'));
    }

    /// Several test binaries in one `cargo test --workspace` run each print their own
    /// block; every name is collected, and a name repeated across binaries is listed once.
    #[test]
    fn names_from_several_binaries_are_collected_without_duplicates() {
        let two_binaries = format!("{CARGO_OUTPUT}\n{CARGO_OUTPUT}");
        assert_eq!(
            failed_test_names(&two_binaries),
            vec!["a_failing_one", "another_failing_one"]
        );
    }
}
