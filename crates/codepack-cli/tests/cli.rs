//! End-to-end tests that run the real binary.
//!
//! Unit tests cover the pieces; these cover the thing a user actually invokes —
//! argument parsing, exit codes, which stream output lands on, and the JSON contract —
//! none of which can be verified by calling a function, because they are properties of
//! the process.
//!
//! Every test points `HOME`/`APPDATA` at a temporary directory. Without that the suite
//! would read and write the developer's real settings, profiles and export history, and
//! `history` would report their actual projects.

use std::path::Path;
use std::process::{Command, Output};

/// Path of the binary under test. Cargo builds it before running this target and hands
/// us the path, so this never runs a stale copy or a different installation.
fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_codepack")
}

struct Sandbox {
    home: tempfile::TempDir,
    project: tempfile::TempDir,
    out: tempfile::TempDir,
}

impl Sandbox {
    fn new() -> Self {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(project.path().join("src")).unwrap();
        std::fs::write(project.path().join("src/main.py"), "print('hello')\n").unwrap();
        std::fs::write(project.path().join("README.md"), "# Demo\n").unwrap();
        std::fs::write(project.path().join("requirements.txt"), "requests\n").unwrap();
        Self {
            home: tempfile::tempdir().unwrap(),
            project,
            out: tempfile::tempdir().unwrap(),
        }
    }

    /// Adds a file containing a credential-shaped value. Synthetic and obviously fake.
    fn with_secret(self) -> Self {
        std::fs::write(
            self.project.path().join(".env"),
            concat!("API_KEY=", "totally-fake-value-0001\n"),
        )
        .unwrap();
        self
    }

    fn project_config(self, contents: &str) -> Self {
        std::fs::write(self.project.path().join(".codepack.toml"), contents).unwrap();
        self
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut command = Command::new(binary());
        command
            .args(args)
            .env("HOME", self.home.path())
            .env("APPDATA", self.home.path())
            .env("LOCALAPPDATA", self.home.path())
            .env("USERPROFILE", self.home.path())
            .env("XDG_CONFIG_HOME", self.home.path());
        command.output().unwrap()
    }

    fn project(&self) -> &Path {
        self.project.path()
    }

    fn out(&self) -> &Path {
        self.out.path()
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn json(output: &Output) -> serde_json::Value {
    serde_json::from_str(&stdout(output)).unwrap_or_else(|error| {
        panic!(
            "stdout was not valid JSON ({error}).\nstdout:\n{}\nstderr:\n{}",
            stdout(output),
            stderr(output)
        )
    })
}

fn code(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("process was killed by a signal")
}

// --- exit codes: the contract ROADMAP §3 fixes -------------------------------------

#[test]
fn a_clean_project_exits_zero() {
    let sandbox = Sandbox::new();
    assert_eq!(
        code(&sandbox.run(&["scan", &sandbox.project().display().to_string()])),
        0
    );
}

#[test]
fn critical_secrets_exit_three() {
    let sandbox = Sandbox::new().with_secret();
    let output = sandbox.run(&["scan", &sandbox.project().display().to_string()]);
    assert_eq!(
        code(&output),
        3,
        "a .env with a credential must gate a pipeline.\nstdout:\n{}",
        stdout(&output)
    );
}

#[test]
fn a_missing_project_exits_one_not_three() {
    // The distinction matters: 3 means "scanned successfully, found secrets". A failed
    // run reporting 3 would tell a pipeline the result is trustworthy.
    let sandbox = Sandbox::new();
    let output = sandbox.run(&["scan", "definitely-not-a-directory-9f3b"]);
    assert_eq!(code(&output), 1);
    assert!(stderr(&output).contains("definitely-not-a-directory-9f3b"));
}

#[test]
fn unknown_arguments_exit_two() {
    let sandbox = Sandbox::new();
    assert_eq!(code(&sandbox.run(&["--not-a-flag"])), 2);
    assert_eq!(code(&sandbox.run(&["frobnicate"])), 2);
    assert_eq!(
        code(&sandbox.run(&["scan", ".", "--safe-mode", "paranoid"])),
        2
    );
}

// --- the --json contract ------------------------------------------------------------

#[test]
fn every_command_emits_a_versioned_envelope() {
    let sandbox = Sandbox::new();
    let project = sandbox.project().display().to_string();

    for (args, command) in [
        (vec!["--json", "preview", project.as_str()], "preview"),
        (vec!["--json", "scan", project.as_str()], "scan"),
        (vec!["--json", "history"], "history"),
        (vec!["--json", "doctor"], "doctor"),
        (
            vec!["--json", "explain", "src/main.py", project.as_str()],
            "explain",
        ),
    ] {
        let output = sandbox.run(&args);
        let parsed = json(&output);
        assert_eq!(parsed["schema_version"], 1, "for {command}");
        assert_eq!(parsed["command"], command);
    }
}

#[test]
fn json_stdout_stays_parseable_even_though_the_export_logs_progress() {
    // The single most breakable property of `--json`: an export emits progress for
    // every step, and if any of it reached stdout the document would not parse.
    let sandbox = Sandbox::new();
    let output = sandbox.run(&[
        "--json",
        "export",
        &sandbox.project().display().to_string(),
        "--out",
        &sandbox.out().display().to_string(),
    ]);

    let parsed = json(&output);
    assert_eq!(parsed["command"], "export");
    assert_eq!(parsed["successful"], true);
    assert!(
        !stderr(&output).is_empty(),
        "progress should still be reported"
    );
}

#[test]
fn errors_go_to_stderr_so_stdout_never_carries_an_error_where_a_result_was_promised() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&["--json", "scan", "definitely-not-a-directory-9f3b"]);

    assert_eq!(code(&output), 1);
    assert!(
        stdout(&output).trim().is_empty(),
        "stdout must stay empty on failure, got: {}",
        stdout(&output)
    );
    assert!(stderr(&output).contains("error") || stderr(&output).contains("does not exist"));
}

// --- export -------------------------------------------------------------------------

#[test]
fn export_writes_an_archive_and_records_it_in_history() {
    let sandbox = Sandbox::new();
    let project = sandbox.project().display().to_string();
    let out = sandbox.out().display().to_string();

    let exported = sandbox.run(&["--json", "export", &project, "--out", &out]);
    assert_eq!(code(&exported), 0);

    let report = json(&exported);
    let archive = report["result_path"].as_str().expect("an archive path");
    assert!(Path::new(archive).is_file(), "{archive} should exist");

    let history = json(&sandbox.run(&["--json", "history"]));
    let runs = history["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0]["successful"], true);
    assert_eq!(runs[0]["run_id"], report["run_id"]);
}

#[test]
fn an_exported_bundle_does_not_contain_the_secret_file() {
    // Invariant I3's whole promise, verified through the binary a user runs.
    let sandbox = Sandbox::new().with_secret();
    let exported = sandbox.run(&[
        "--json",
        "export",
        &sandbox.project().display().to_string(),
        "--out",
        &sandbox.out().display().to_string(),
    ]);

    let report = json(&exported);
    let archive = report["result_path"].as_str().unwrap();
    let file = std::fs::File::open(archive).unwrap();
    let mut zip = zip::ZipArchive::new(file).unwrap();

    let names: Vec<String> = (0..zip.len())
        .map(|index| zip.by_index(index).unwrap().name().to_string())
        .collect();
    assert!(
        !names.iter().any(|name| name.ends_with(".env")),
        "the bundle must not carry .env: {names:?}"
    );
}

// --- preview ------------------------------------------------------------------------

#[test]
fn preview_reports_the_sensitive_file_without_writing_anything() {
    let sandbox = Sandbox::new().with_secret();
    let before = listing(sandbox.project());

    let output = sandbox.run(&[
        "--json",
        "preview",
        &sandbox.project().display().to_string(),
    ]);
    let report = json(&output);

    assert_eq!(code(&output), 0);
    let flagged = report["sensitive_exclusions"].as_array().unwrap();
    assert_eq!(flagged.len(), 1);
    assert!(flagged[0]["path"].as_str().unwrap().contains(".env"));

    assert_eq!(
        before,
        listing(sandbox.project()),
        "preview must not create or remove anything in the project"
    );
}

#[test]
fn preview_lists_files_only_when_asked() {
    let sandbox = Sandbox::new();
    let project = sandbox.project().display().to_string();

    let quiet = json(&sandbox.run(&["--json", "preview", &project]));
    assert!(quiet.get("files").is_none());

    let listed = json(&sandbox.run(&["--json", "preview", &project, "--list-files"]));
    assert!(!listed["files"].as_array().unwrap().is_empty());
}

// --- configuration layering ---------------------------------------------------------

#[test]
fn a_project_config_changes_behaviour_and_is_reported() {
    let sandbox = Sandbox::new()
        .with_secret()
        .project_config("safe_export_mode = \"full\"\n");

    let report = json(&sandbox.run(&[
        "--json",
        "preview",
        &sandbox.project().display().to_string(),
    ]));

    assert_eq!(report["safe_mode"], "full");
    assert!(
        report["sensitive_exclusions"]
            .as_array()
            .unwrap()
            .is_empty(),
        "in full mode nothing is excluded on safety grounds"
    );
    assert!(
        report["resolution"]["project_config"]
            .as_str()
            .unwrap()
            .ends_with(".codepack.toml")
    );
}

#[test]
fn a_flag_overrides_the_project_config() {
    let sandbox = Sandbox::new().project_config("safe_export_mode = \"full\"\n");
    let report = json(&sandbox.run(&[
        "--json",
        "preview",
        &sandbox.project().display().to_string(),
        "--safe-mode",
        "safe",
    ]));
    assert_eq!(report["safe_mode"], "safe");
}

#[test]
fn a_broken_project_config_fails_loudly_rather_than_being_ignored() {
    let sandbox = Sandbox::new().project_config("safe_moed = \"safe\"\n");
    let output = sandbox.run(&["preview", &sandbox.project().display().to_string()]);

    assert_eq!(code(&output), 1);
    assert!(
        stderr(&output).contains(".codepack.toml"),
        "the message must point at the file: {}",
        stderr(&output)
    );
}

#[test]
fn an_unknown_preset_is_rejected_and_names_the_real_ones() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&[
        "preview",
        &sandbox.project().display().to_string(),
        "--preset",
        "clade",
    ]);

    assert_eq!(code(&output), 1);
    let message = stderr(&output);
    assert!(message.contains("clade"));
    assert!(message.contains("available presets"));
}

#[test]
fn a_budget_drops_files_and_says_so() {
    let sandbox = Sandbox::new();
    for index in 0..8 {
        std::fs::write(
            sandbox.project().join(format!("filler_{index}.txt")),
            "x".repeat(4_000),
        )
        .unwrap();
    }

    let report = json(&sandbox.run(&[
        "--json",
        "preview",
        &sandbox.project().display().to_string(),
        "--budget",
        "2k",
    ]));

    assert!(
        report["dropped_by_budget"].as_u64().unwrap() > 0,
        "a 2k budget cannot fit 32k of filler: {report}"
    );
}

// --- history and doctor -------------------------------------------------------------

#[test]
fn history_on_a_fresh_machine_is_empty_rather_than_an_error() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&["--json", "history"]);
    assert_eq!(code(&output), 0);
    assert!(json(&output)["runs"].as_array().unwrap().is_empty());
}

#[test]
fn history_for_a_never_exported_project_lists_nothing_and_creates_no_record() {
    let sandbox = Sandbox::new();
    let project = sandbox.project().display().to_string();

    let listed = json(&sandbox.run(&["--json", "history", "--path", &project]));
    assert!(listed["runs"].as_array().unwrap().is_empty());

    // The `runs` list alone cannot prove the second half of this test's name:
    // `list_export_runs` joins runs to projects, so a stray project row carrying no
    // runs would never appear there. Ask the table directly.
    for database in find_databases(sandbox.home.path()) {
        let conn = rusqlite::Connection::open(&database).unwrap();
        let projects: i64 = conn
            .query_row("SELECT COUNT(*) FROM project", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            projects,
            0,
            "a read-only command registered a project in {}",
            database.display()
        );
    }
}

#[test]
fn doctor_states_the_privacy_guarantee_and_lists_the_presets() {
    let sandbox = Sandbox::new();
    let report = json(&sandbox.run(&["--json", "doctor"]));

    assert!(report["network_access"].as_str().unwrap().contains("local"));
    // Every preset the binary knows, not a fixed five: `ai_presets()` pins the legacy
    // five and its own additions, and duplicating that count here would only mean two
    // places to update.
    let listed = report["presets"].as_array().unwrap();
    assert!(!listed.is_empty(), "doctor listed no presets at all");
    assert_eq!(listed.len(), codepack_core::config::ai_presets().len());
    assert_eq!(report["project_config_file"], ".codepack.toml");
}

// --- explain, --budget by model, and the PR Review preset ---------------------------

#[test]
fn explain_answers_for_an_included_file_and_exits_zero() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&[
        "--json",
        "explain",
        "src/main.py",
        &sandbox.project().display().to_string(),
    ]);

    assert_eq!(code(&output), 0);
    let report = json(&output);
    assert_eq!(report["verdict"], "included");
    assert_eq!(report["file"], "src\\main.py");
    assert_eq!(report["exists_on_disk"], true);
}

#[test]
fn explain_is_a_successful_answer_even_when_the_file_was_excluded() {
    // The whole reason `explain` exists: "it was excluded, here is the rule" is the
    // answer working, not a failure, so a script asking about a file must not have to
    // treat a non-zero exit as a normal case.
    let sandbox = Sandbox::new().with_secret();
    let output = sandbox.run(&[
        "--json",
        "explain",
        ".env",
        &sandbox.project().display().to_string(),
    ]);

    assert_eq!(code(&output), 0);
    let report = json(&output);
    assert_eq!(report["verdict"], "excluded");
    assert!(!report["reason"].as_str().unwrap().is_empty());
}

#[test]
fn explain_writes_nothing_into_the_source_project() {
    let sandbox = Sandbox::new();
    let before = listing(sandbox.project());
    let output = sandbox.run(&[
        "--json",
        "explain",
        "src/main.py",
        &sandbox.project().display().to_string(),
    ]);
    // Asserted before the tree comparison: a build where `explain` failed outright
    // would leave the tree untouched too, and pass an I2 test it never exercised.
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert_eq!(json(&output)["verdict"], "included");
    assert_eq!(before, listing(sandbox.project()));
}

#[test]
fn a_mistyped_budget_that_looks_like_a_model_fails_at_resolution_not_at_parsing() {
    // Behaviour change worth pinning: `--budget lots` used to be a clap usage error
    // (exit 2). Now anything not digit- or sign-leading is a model name, so it is a
    // resolution failure (exit 1). Only values claiming to be numbers stay exit 2.
    let sandbox = Sandbox::new();
    let project = sandbox.project().display().to_string();

    assert_eq!(
        code(&sandbox.run(&["preview", &project, "--budget", "lots"])),
        1
    );
    assert_eq!(
        code(&sandbox.run(&["preview", &project, "--budget", "12kb"])),
        2
    );
}

#[test]
fn a_budget_named_by_model_resolves_through_the_table() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&[
        "--json",
        "preview",
        &sandbox.project().display().to_string(),
        "--budget",
        "Claude",
    ]);

    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert_eq!(json(&output)["resolution"]["budget_model"], "Claude");
}

#[test]
fn an_unknown_model_fails_by_name_rather_than_silently_running_unbudgeted() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&[
        "preview",
        &sandbox.project().display().to_string(),
        "--budget",
        "no-such-model-9f3b",
    ]);

    assert_eq!(code(&output), 1);
    let message = stderr(&output);
    assert!(message.contains("no-such-model-9f3b"), "{message}");
}

#[test]
fn the_pr_review_preset_is_selectable_from_the_command_line() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&[
        "--json",
        "preview",
        &sandbox.project().display().to_string(),
        "--preset",
        "PR Review",
    ]);

    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let report = json(&output);
    assert_eq!(report["resolution"]["preset"], "PR Review");
    assert_eq!(report["profile"], "ai_review");
}

#[test]
fn help_and_version_work_and_exit_zero() {
    let sandbox = Sandbox::new();
    for args in [vec!["--help"], vec!["--version"], vec!["export", "--help"]] {
        let output = sandbox.run(&args);
        assert_eq!(code(&output), 0, "for {args:?}");
        assert!(!stdout(&output).is_empty(), "for {args:?}");
    }
}

#[test]
fn completions_prints_a_script_for_every_supported_shell() {
    let sandbox = Sandbox::new();
    for shell in ["bash", "zsh", "fish", "powershell", "elvish"] {
        let output = sandbox.run(&["completions", shell]);
        assert_eq!(code(&output), 0, "for shell {shell}");
        let script = stdout(&output);
        assert!(!script.is_empty(), "for shell {shell}");
        assert!(
            script.contains("codepack"),
            "the generated script should reference the binary name for {shell}"
        );
    }
}

/// Every path under `root`, recursively. A non-recursive listing would not notice a
/// file written into a subdirectory, which is exactly what "writes nothing anywhere"
/// has to rule out.
fn listing(root: &Path) -> Vec<String> {
    fn walk(dir: &Path, prefix: &str, found: &mut Vec<String>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap())
            .collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let name = format!("{prefix}{}", entry.file_name().to_string_lossy());
            if entry.file_type().unwrap().is_dir() {
                walk(&entry.path(), &format!("{name}/"), found);
            }
            found.push(name);
        }
    }
    let mut found = Vec::new();
    walk(root, "", &mut found);
    found
}

/// Every `.db` under the sandboxed home, so a test need not know where `AppPaths`
/// decided to put it on this platform.
fn find_databases(root: &Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(find_databases(&path));
        } else if path.extension().is_some_and(|ext| ext == "db") {
            found.push(path);
        }
    }
    found
}

// --- gaps the review found in this suite's own coverage ------------------------------

#[test]
fn an_export_whose_bundle_holds_critical_findings_exits_three() {
    // `scan`'s exit-3 path was covered; export's was not, and the CI acceptance step
    // only *tolerates* 3 rather than demonstrating it.
    let sandbox = Sandbox::new();
    // Inside a source file rather than a `.pem`: safe mode excludes a `.pem` outright,
    // so the bundle would be clean and exiting 0 would be right. What this test needs is
    // a critical finding in a file that really is exported.
    std::fs::write(
        sandbox.project().join("bootstrap.py"),
        "KEY = \"\"\"-----BEGIN RSA PRIVATE KEY-----\nnot-a-real-key\n\"\"\"\n",
    )
    .unwrap();

    let output = sandbox.run(&[
        "--json",
        "export",
        &sandbox.project().display().to_string(),
        "--out",
        &sandbox.out().display().to_string(),
    ]);

    let report = json(&output);
    assert!(
        report["critical_findings"].as_u64().unwrap() > 0,
        "expected the PEM header to be reported: {report}"
    );
    assert_eq!(code(&output), 3);
}

#[test]
fn a_preset_is_applied_and_reported() {
    let sandbox = Sandbox::new();
    let report = json(&sandbox.run(&[
        "--json",
        "preview",
        &sandbox.project().display().to_string(),
        "--preset",
        "Security Audit",
    ]));

    assert_eq!(report["resolution"]["preset"], "Security Audit");
    assert_eq!(report["profile"], "security");
    assert_eq!(report["safe_mode"], "safe");
}

#[test]
fn an_unknown_profile_is_rejected_the_way_an_unknown_preset_is() {
    // Without validation, apply_custom_profile's legacy fallback turns a typo into a
    // *wider* export than the user asked for, while still reporting the typed name.
    let sandbox = Sandbox::new();
    let output = sandbox.run(&[
        "preview",
        &sandbox.project().display().to_string(),
        "--profile",
        "minimul",
    ]);

    assert_eq!(code(&output), 1);
    assert!(stderr(&output).contains("minimul"));
    assert!(stderr(&output).contains("available profiles"));
}

#[test]
fn a_diff_flag_reaches_the_plan() {
    let sandbox = Sandbox::new();
    let report = json(&sandbox.run(&[
        "--json",
        "preview",
        &sandbox.project().display().to_string(),
        "--diff",
        "uncommitted",
    ]));
    // The fixture is not a git repository, so codepack-diff degrades to "all" and says
    // so; the point here is that the flag was carried into the plan at all.
    assert!(report["diff_mode"].is_string());
}

#[test]
fn the_default_output_location_never_lands_inside_the_project() {
    // Invariant I2. This defaulted to the current directory at first, which for the
    // documented `cd project && codepack export` is the project itself: two runs left
    // two archives in the tree, and the second had to skip the first one's output as if
    // it were source.
    let sandbox = Sandbox::new();
    let before = listing(sandbox.project());

    let output = Command::new(binary())
        .args(["export", "--json"])
        .current_dir(sandbox.project())
        .env("HOME", sandbox.home.path())
        .env("APPDATA", sandbox.home.path())
        .env("LOCALAPPDATA", sandbox.home.path())
        .env("USERPROFILE", sandbox.home.path())
        .env("XDG_CONFIG_HOME", sandbox.home.path())
        .output()
        .unwrap();

    assert_eq!(code(&output), 0, "stderr:\n{}", stderr(&output));
    assert_eq!(
        before,
        listing(sandbox.project()),
        "the export wrote into the project it was exporting"
    );
}

#[test]
fn an_explicit_out_inside_the_project_is_refused() {
    let sandbox = Sandbox::new();
    let inside = sandbox.project().join("dist");
    let output = sandbox.run(&[
        "export",
        &sandbox.project().display().to_string(),
        "--out",
        &inside.display().to_string(),
    ]);

    assert_eq!(code(&output), 1);
    assert!(
        stderr(&output).contains("refusing"),
        "stderr:\n{}",
        stderr(&output)
    );
}

// --- `sanitize` (the "Sterile copy" standalone action) -----------------------------

#[test]
fn sanitize_strips_comments_and_redacts_a_planted_secret() {
    let sandbox = Sandbox::new().with_secret();
    let output = sandbox.run(&[
        "sanitize",
        "--source",
        &sandbox.project().display().to_string(),
        "--out",
        &sandbox.out().display().to_string(),
    ]);

    assert_eq!(code(&output), 0, "stderr:\n{}", stderr(&output));

    // Quote style may differ (`ruff`/`black`, if present on the developer's `PATH`,
    // normalise quotes) — the content, not the exact formatter output, is what matters
    // here; formatter-specific behavior is covered in `codepack-sanitize`'s own tests.
    let written = std::fs::read_to_string(sandbox.out().join("src/main.py")).unwrap();
    assert!(
        written.contains("print(") && written.contains("hello"),
        "written content: {written:?}"
    );

    // .env is excluded by safe mode, exactly like a normal export, and never appears in
    // the destination folder at all.
    assert!(!sandbox.out().join(".env").exists());

    assert!(sandbox.out().join("STERILE_COPY_REPORT.json").is_file());
    assert!(sandbox.out().join("STERILE_COPY_REPORT.md").is_file());
}

#[test]
fn sanitize_destination_inside_the_source_is_refused() {
    let sandbox = Sandbox::new();
    let inside = sandbox.project().join("sterile");
    let output = sandbox.run(&[
        "sanitize",
        "--source",
        &sandbox.project().display().to_string(),
        "--out",
        &inside.display().to_string(),
    ]);

    assert_eq!(code(&output), 1);
    assert!(
        stderr(&output).contains("refusing"),
        "stderr:\n{}",
        stderr(&output)
    );
}

#[test]
fn sanitize_json_output_is_a_versioned_envelope() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&[
        "sanitize",
        "--source",
        &sandbox.project().display().to_string(),
        "--out",
        &sandbox.out().display().to_string(),
        "--json",
    ]);

    assert_eq!(code(&output), 0, "stderr:\n{}", stderr(&output));
    let payload = json(&output);
    assert_eq!(payload["command"], "sanitize");
    assert!(payload["summary"]["total_files"].as_u64().unwrap() > 0);
}

#[test]
fn sanitize_can_produce_a_7z_archive_next_to_the_folder() {
    let sandbox = Sandbox::new().with_secret();
    let archive = sandbox.out().join("sterile.7z");
    let folder = sandbox.out().join("folder");

    let output = sandbox.run(&[
        "--json",
        "sanitize",
        "--source",
        &sandbox.project().display().to_string(),
        "--out",
        &folder.display().to_string(),
        "--archive",
        &archive.display().to_string(),
    ]);

    assert_eq!(code(&output), 0, "stderr:\n{}", stderr(&output));
    assert!(archive.is_file(), "no archive at {}", archive.display());

    let payload = json(&output);
    assert_eq!(payload["archive"]["path"], archive.display().to_string());
    assert!(payload["archive"]["bytes"].as_u64().unwrap() > 0);

    // Both results exist: the archive is an addition, not a replacement.
    assert!(folder.join("STERILE_COPY_REPORT.json").is_file());
}

#[test]
fn sanitize_with_only_an_archive_leaves_no_folder_to_clean_up() {
    // The actual complaint this feature answers: wanting a shareable archive should not
    // require inventing a destination folder and deleting it afterwards.
    let sandbox = Sandbox::new();
    let archive = sandbox.out().join("only.7z");
    let before = listing(sandbox.out());

    let output = sandbox.run(&[
        "sanitize",
        "--source",
        &sandbox.project().display().to_string(),
        "--archive",
        &archive.display().to_string(),
    ]);

    assert_eq!(code(&output), 0, "stderr:\n{}", stderr(&output));
    assert!(archive.is_file());

    let mut after = listing(sandbox.out());
    after.retain(|name| name != "only.7z");
    assert_eq!(before, after, "a scratch folder was left behind");
}

#[test]
fn sanitize_reports_no_destination_when_the_folder_was_only_scratch() {
    // Naming a path that has already been deleted is worse than saying nothing — and
    // that path was also being written into STERILE_COPY_REPORT.json *inside* the
    // archive, where a recipient could make nothing of it. Found by review 2026-07-29.
    let sandbox = Sandbox::new();
    let archive = sandbox.out().join("only.7z");

    let output = sandbox.run(&[
        "--json",
        "sanitize",
        "--source",
        &sandbox.project().display().to_string(),
        "--archive",
        &archive.display().to_string(),
    ]);

    assert_eq!(code(&output), 0, "stderr:\n{}", stderr(&output));
    let payload = json(&output);
    assert!(
        payload.get("destination").is_none(),
        "a scratch folder that no longer exists was reported as the destination: {payload}"
    );
    assert_eq!(payload["archive"]["path"], archive.display().to_string());
}

#[test]
fn sanitize_writes_a_zip_by_default_and_says_so() {
    // ZIP is the default everywhere (owner decision 2026-07-30); the extension picks
    // the container when the user names the file.
    let sandbox = Sandbox::new();
    let archive = sandbox.out().join("sterile.zip");

    let output = sandbox.run(&[
        "--json",
        "sanitize",
        "--source",
        &sandbox.project().display().to_string(),
        "--archive",
        &archive.display().to_string(),
    ]);

    assert_eq!(code(&output), 0, "stderr:\n{}", stderr(&output));
    assert_eq!(json(&output)["archive"]["format"], "zip");

    // Really a ZIP, not merely a file with that name.
    let file = std::fs::File::open(&archive).unwrap();
    assert!(!zip::ZipArchive::new(file).unwrap().is_empty());
}

#[test]
fn sanitize_writes_a_7z_when_the_file_name_asks_for_one() {
    let sandbox = Sandbox::new();
    let archive = sandbox.out().join("sterile.7z");

    let output = sandbox.run(&[
        "--json",
        "sanitize",
        "--source",
        &sandbox.project().display().to_string(),
        "--archive",
        &archive.display().to_string(),
    ]);

    assert_eq!(code(&output), 0, "stderr:\n{}", stderr(&output));
    assert_eq!(json(&output)["archive"]["format"], "7z");
    assert_eq!(
        &std::fs::read(&archive).unwrap()[..6],
        b"7z\xbc\xaf\x27\x1c"
    );
}

#[test]
fn an_explicit_archive_format_beats_the_file_extension() {
    // The extension is a guess; `--archive-format` is a statement.
    let sandbox = Sandbox::new();
    let archive = sandbox.out().join("named-wrong.7z");

    let output = sandbox.run(&[
        "--json",
        "sanitize",
        "--source",
        &sandbox.project().display().to_string(),
        "--archive",
        &archive.display().to_string(),
        "--archive-format",
        "zip",
    ]);

    assert_eq!(code(&output), 0, "stderr:\n{}", stderr(&output));
    assert_eq!(json(&output)["archive"]["format"], "zip");
    let file = std::fs::File::open(&archive).unwrap();
    assert!(zip::ZipArchive::new(file).is_ok(), "should be a real ZIP");
}

#[test]
fn rar_is_offered_but_refused_with_a_message_that_names_the_alternatives() {
    // Offered on purpose: `--archive-format rar` must not read like a typo. It is a
    // real choice that is not implemented yet, and the message has to say so.
    let sandbox = Sandbox::new();
    let archive = sandbox.out().join("sterile.rar");

    let output = sandbox.run(&[
        "sanitize",
        "--source",
        &sandbox.project().display().to_string(),
        "--archive",
        &archive.display().to_string(),
        "--archive-format",
        "rar",
    ]);

    assert_eq!(
        code(&output),
        1,
        "a reserved format is a failure, not a usage error"
    );
    let message = stderr(&output);
    assert!(message.contains("not implemented"), "{message}");
    assert!(
        message.contains("zip") && message.contains("7z"),
        "{message}"
    );
    assert!(
        !archive.exists(),
        "nothing may be written for a refused format"
    );
}

#[test]
fn export_writes_a_zip_by_default_and_a_7z_on_request() {
    for (format, expected_extension) in [("zip", "zip"), ("7z", "7z")] {
        let sandbox = Sandbox::new();
        let output = sandbox.run(&[
            "--json",
            "export",
            &sandbox.project().display().to_string(),
            "--out",
            &sandbox.out().display().to_string(),
            "--archive-format",
            format,
        ]);

        assert_eq!(code(&output), 0, "{format}: {}", stderr(&output));
        let produced = json(&output)["result_path"].as_str().unwrap().to_string();
        assert!(
            produced.ends_with(expected_extension),
            "{format}: bundle landed at {produced}"
        );
        assert!(std::path::Path::new(&produced).is_file(), "{produced}");
    }
}

#[test]
fn sanitize_without_out_or_archive_is_a_usage_error() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&[
        "sanitize",
        "--source",
        &sandbox.project().display().to_string(),
    ]);
    assert_eq!(code(&output), 2);
}

#[test]
fn sanitize_refuses_an_archive_path_inside_the_source() {
    let sandbox = Sandbox::new();
    let inside = sandbox.project().join("sterile.7z");
    let output = sandbox.run(&[
        "sanitize",
        "--source",
        &sandbox.project().display().to_string(),
        "--out",
        &sandbox.out().display().to_string(),
        "--archive",
        &inside.display().to_string(),
    ]);

    assert_eq!(code(&output), 1);
    assert!(stderr(&output).contains("refusing"), "{}", stderr(&output));
    assert!(
        !inside.exists(),
        "the source project must be left as it was found (invariant I2)"
    );
}

// --- verify: checking a bundle that already exists ---------------------------------

#[test]
fn verify_reports_a_clean_bundle_as_clean() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&[
        "export",
        &sandbox.project().display().to_string(),
        "--out",
        &sandbox.out().display().to_string(),
        "--json",
    ]);
    assert_eq!(code(&output), 0, "stderr:\n{}", stderr(&output));

    let bundle = json(&output)["result_path"].as_str().unwrap().to_string();
    let verified = sandbox.run(&["verify", &bundle, "--json"]);

    assert_eq!(
        code(&verified),
        0,
        "a bundle exported from a clean project must verify clean.\nstderr:\n{}",
        stderr(&verified)
    );
    let payload = json(&verified);
    assert_eq!(payload["command"], "verify");
    assert!(payload["scanned_files"].as_u64().unwrap() > 0);

    // The assertion the command's name actually promises. Written weakly at first (only
    // `critical == 0`), it passed while a real export produced two dozen findings from
    // codepack's own reports — the reason those are now classified separately.
    assert_eq!(
        payload["findings"].as_array().unwrap().len(),
        0,
        "a clean project's bundle must report no findings in its exported content.\nstdout:\n{}",
        stdout(&verified)
    );
    assert_eq!(payload["summary"]["total_findings"], 0);
    assert_eq!(payload["summary"]["critical"], 0);
}

#[test]
fn verify_finds_a_secret_that_reached_the_bundle() {
    // `full` safe mode keeps the `.env` the other modes would drop, so this produces the
    // situation `verify` exists to catch: a bundle that really does carry a credential.
    let sandbox = Sandbox::new().with_secret();
    let output = sandbox.run(&[
        "export",
        &sandbox.project().display().to_string(),
        "--out",
        &sandbox.out().display().to_string(),
        "--safe-mode",
        "full",
        "--json",
    ]);
    let bundle = json(&output)["result_path"].as_str().unwrap().to_string();

    let verified = sandbox.run(&["verify", &bundle, "--json"]);
    assert_eq!(
        code(&verified),
        3,
        "a credential inside the bundle must gate a pipeline.\nstdout:\n{}",
        stdout(&verified)
    );
    assert!(json(&verified)["summary"]["critical"].as_u64().unwrap() > 0);
}

#[test]
fn verify_refuses_a_file_that_is_not_an_archive_instead_of_calling_it_clean() {
    let sandbox = Sandbox::new();
    let broken = sandbox.out().join("not-really.zip");
    std::fs::write(&broken, b"definitely not a zip").unwrap();

    let output = sandbox.run(&["verify", &broken.display().to_string()]);
    assert_eq!(
        code(&output),
        1,
        "an unreadable bundle must not read as clean.\nstdout:\n{}",
        stdout(&output)
    );
}

#[test]
fn verify_rejects_a_path_that_does_not_exist() {
    let sandbox = Sandbox::new();
    let missing = sandbox.out().join("no-such-bundle.zip");
    assert_eq!(
        code(&sandbox.run(&["verify", &missing.display().to_string()])),
        1
    );
}

// --- .codepack-allow: reviewed findings stop being re-reported ----------------------

#[test]
fn an_allowlisted_finding_is_suppressed_and_reported_as_suppressed() {
    let sandbox = Sandbox::new().with_secret();
    let first = sandbox.run(&["scan", &sandbox.project().display().to_string(), "--json"]);
    assert_eq!(code(&first), 3);

    let payload = json(&first);
    let findings = payload["findings"].as_array().unwrap();
    let fingerprint = findings[0]["fingerprint"].as_str().unwrap().to_string();
    let before = findings.len();

    std::fs::write(
        sandbox.project().join(".codepack-allow"),
        format!(
            "[[allow]]\nfingerprint = \"{fingerprint}\"\nreason = \"reviewed: sample fixture\"\n"
        ),
    )
    .unwrap();

    let second = sandbox.run(&["scan", &sandbox.project().display().to_string(), "--json"]);
    let payload = json(&second);

    assert_eq!(
        payload["findings"].as_array().unwrap().len(),
        before - 1,
        "the accepted finding should be gone from the list"
    );
    let suppressed = payload["suppressed"].as_array().unwrap();
    assert_eq!(
        suppressed.len(),
        1,
        "and counted as suppressed, not dropped"
    );
    assert_eq!(suppressed[0]["reason"], "reviewed: sample fixture");
    assert!(
        payload["allowlist"].is_string(),
        "the file must be named in the report"
    );
}

#[test]
fn a_malformed_allowlist_fails_the_run_rather_than_being_ignored() {
    let sandbox = Sandbox::new();
    std::fs::write(
        sandbox.project().join(".codepack-allow"),
        "[[allow]]\nfingerprint = \"not-a-fingerprint\"\nreason = \"typo\"\n",
    )
    .unwrap();

    let output = sandbox.run(&["scan", &sandbox.project().display().to_string()]);
    assert_eq!(
        code(&output),
        1,
        "a file that silently matches nothing would leave a reviewer misinformed.\nstderr:\n{}",
        stderr(&output)
    );
}

// --- scan --staged: the pre-commit guard -------------------------------------------

/// Builds a git repository in `root` through `git2` — never by shelling out to `git`,
/// which `.ai/project/12-domain-rules.md` forbids tests from depending on.
fn init_repository_with_commit(root: &Path) -> git2::Repository {
    let repository = git2::Repository::init(root).unwrap();
    let mut index = repository.index().unwrap();
    index
        .add_all(["README.md"], git2::IndexAddOption::DEFAULT, None)
        .unwrap();
    index.write().unwrap();
    let tree_id = index.write_tree().unwrap();
    let signature = git2::Signature::now("Test", "test@example.local").unwrap();
    {
        let tree = repository.find_tree(tree_id).unwrap();
        repository
            .commit(Some("HEAD"), &signature, &signature, "seed", &tree, &[])
            .unwrap();
    }
    repository
}

fn stage(repository: &git2::Repository, relative: &str) {
    let mut index = repository.index().unwrap();
    index
        .add_all([relative], git2::IndexAddOption::DEFAULT, None)
        .unwrap();
    index.write().unwrap();
}

#[test]
fn staged_scan_with_nothing_staged_exits_zero() {
    let sandbox = Sandbox::new();
    init_repository_with_commit(sandbox.project());

    let output = sandbox.run(&["scan", &sandbox.project().display().to_string(), "--staged"]);
    assert_eq!(code(&output), 0, "stderr:\n{}", stderr(&output));
    assert!(
        stdout(&output).contains("Nothing staged"),
        "an empty result must say why.\nstdout:\n{}",
        stdout(&output)
    );
}

#[test]
fn staged_scan_gates_the_commit_on_a_critical_finding() {
    let sandbox = Sandbox::new();
    let repository = init_repository_with_commit(sandbox.project());

    std::fs::write(
        sandbox.project().join(".env"),
        concat!("API_KEY=", "totally-fake-value-0002\n"),
    )
    .unwrap();
    stage(&repository, ".env");

    let output = sandbox.run(&[
        "scan",
        &sandbox.project().display().to_string(),
        "--staged",
        "--json",
    ]);
    assert_eq!(
        code(&output),
        3,
        "a credential file about to be committed must stop the commit.\nstdout:\n{}",
        stdout(&output)
    );
    assert_eq!(json(&output)["source"], "staged");
}

#[test]
fn staged_scan_reports_a_high_finding_without_gating_on_it() {
    // Honest coverage of the exit-code contract's edge, not an endorsement of it.
    // `secret_like_line` is `high`, and exit code 3 is reserved for `critical`
    // (`exit.rs`, fixed by ROADMAP §3), so a credential in a staged *script* is
    // reported but does not by itself fail the hook. Whether a pre-commit guard should
    // gate on `high` too is a real question, recorded in `open-questions.md` rather
    // than answered by quietly widening a frozen contract.
    let sandbox = Sandbox::new();
    let repository = init_repository_with_commit(sandbox.project());

    std::fs::write(
        sandbox.project().join("deploy.sh"),
        concat!("#!/bin/sh\nexport API_KEY=", "totally-fake-value-0004\n"),
    )
    .unwrap();
    stage(&repository, "deploy.sh");

    let output = sandbox.run(&[
        "scan",
        &sandbox.project().display().to_string(),
        "--staged",
        "--json",
    ]);
    let payload = json(&output);

    assert_eq!(code(&output), 0, "high alone does not gate today");
    assert_eq!(
        payload["summary"]["potential_secrets"],
        1,
        "but it is still reported, never hidden.\nstdout:\n{}",
        stdout(&output)
    );
    assert_eq!(payload["findings"][0]["severity"], "high");
}

#[test]
fn staged_scan_ignores_a_secret_that_was_never_staged() {
    // The property that makes this a pre-commit guard rather than a working-tree scan.
    let sandbox = Sandbox::new();
    init_repository_with_commit(sandbox.project());

    std::fs::write(
        sandbox.project().join("scratch.env"),
        concat!("API_KEY=", "totally-fake-value-0003\n"),
    )
    .unwrap();

    let output = sandbox.run(&["scan", &sandbox.project().display().to_string(), "--staged"]);
    assert_eq!(
        code(&output),
        0,
        "an unstaged file is not part of the commit being checked.\nstdout:\n{}",
        stdout(&output)
    );
}

#[test]
fn staged_scan_outside_a_repository_is_an_error_not_a_clean_result() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&["scan", &sandbox.project().display().to_string(), "--staged"]);
    assert_eq!(
        code(&output),
        1,
        "answering `clean` outside a repository would be a lie.\nstderr:\n{}",
        stderr(&output)
    );
}

// --- history scanning, the hook, SARIF and the handoff ------------------------------

/// Commits `relative` with `contents`, then commits its removal. The credential is gone
/// from the working tree and still in the history — the exact situation `--history`
/// exists for.
fn commit_then_delete(repository: &git2::Repository, relative: &str, contents: &str) {
    let root = repository.workdir().unwrap().to_path_buf();
    std::fs::write(root.join(relative), contents).unwrap();
    stage(repository, relative);
    commit_index(repository, "add the file");

    std::fs::remove_file(root.join(relative)).unwrap();
    let mut index = repository.index().unwrap();
    index.remove_path(Path::new(relative)).unwrap();
    index.write().unwrap();
    commit_index(repository, "remove the file");
}

fn commit_index(repository: &git2::Repository, message: &str) {
    let mut index = repository.index().unwrap();
    let tree_id = index.write_tree().unwrap();
    let tree = repository.find_tree(tree_id).unwrap();
    let signature = git2::Signature::now("Test", "test@example.local").unwrap();
    let parents = match repository
        .head()
        .ok()
        .and_then(|head| head.peel_to_commit().ok())
    {
        Some(parent) => vec![parent],
        None => Vec::new(),
    };
    let refs: Vec<&git2::Commit<'_>> = parents.iter().collect();
    repository
        .commit(Some("HEAD"), &signature, &signature, message, &tree, &refs)
        .unwrap();
    drop(tree);
}

#[test]
fn a_history_scan_finds_a_credential_the_working_tree_no_longer_has() {
    let sandbox = Sandbox::new();
    let repository = init_repository_with_commit(sandbox.project());
    commit_then_delete(
        &repository,
        "settings.py",
        concat!(
            "AWS_SECRET_ACCESS_KEY = \"",
            "wJalrXUtnFEMIfake7MDENGbPxRfiCYKEY\"\n"
        ),
    );

    let plain = sandbox.run(&["--json", "scan", &sandbox.project().display().to_string()]);
    assert_eq!(
        json(&plain)["summary"]["potential_secrets"],
        0,
        "the working tree really is clean"
    );

    let output = sandbox.run(&[
        "--json",
        "scan",
        &sandbox.project().display().to_string(),
        "--history",
    ]);
    let report = json(&output);

    assert_eq!(report["source"], "history");
    assert!(
        report["summary"]["potential_secrets"].as_u64().unwrap() > 0,
        "the credential is still in the history:\n{report:#}"
    );
    let finding = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["kind"] == "potential_secret")
        .expect("a historical finding");
    assert!(finding["commit"].is_string(), "{finding:#}");
    assert!(
        finding["committed_at"].as_str().unwrap().ends_with(" UTC"),
        "{finding:#}"
    );
    assert!(report["history"]["commits_walked"].as_u64().unwrap() >= 2);
}

#[test]
fn a_history_scan_outside_a_repository_is_an_error_not_a_clean_result() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&[
        "scan",
        &sandbox.project().display().to_string(),
        "--history",
    ]);
    assert_eq!(code(&output), 1, "stderr:\n{}", stderr(&output));
}

#[test]
fn history_and_staged_cannot_be_asked_for_together() {
    // They answer different questions and would produce one report claiming to be both.
    let sandbox = Sandbox::new();
    let output = sandbox.run(&[
        "scan",
        &sandbox.project().display().to_string(),
        "--history",
        "--staged",
    ]);
    assert_eq!(code(&output), 2, "stderr:\n{}", stderr(&output));
}

#[test]
fn fail_on_raises_the_gate_without_changing_the_default() {
    let sandbox = Sandbox::new();
    // `high`, not `critical`: an assignment in a shell script.
    std::fs::write(
        sandbox.project().join("deploy.sh"),
        concat!("export API_KEY=\"", "abcdef1234567890\"\n"),
    )
    .unwrap();

    let default_run = sandbox.run(&["scan", &sandbox.project().display().to_string()]);
    assert_eq!(
        code(&default_run),
        0,
        "the published contract gates on critical only.\nstdout:\n{}",
        stdout(&default_run)
    );

    let raised = sandbox.run(&[
        "scan",
        &sandbox.project().display().to_string(),
        "--fail-on",
        "high",
    ]);
    assert_eq!(code(&raised), 3, "stdout:\n{}", stdout(&raised));
}

#[test]
fn an_unknown_fail_on_severity_is_a_usage_error_listing_the_valid_ones() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&[
        "scan",
        &sandbox.project().display().to_string(),
        "--fail-on",
        "catastrophic",
    ]);
    assert_eq!(code(&output), 2);
    assert!(stderr(&output).contains("critical"), "{}", stderr(&output));
}

#[test]
fn scan_writes_sarif_a_pipeline_can_upload() {
    let sandbox = Sandbox::new().with_secret();
    let sarif = sandbox.out().join("nested").join("codepack.sarif");

    let output = sandbox.run(&[
        "scan",
        &sandbox.project().display().to_string(),
        "--sarif",
        &sarif.display().to_string(),
    ]);
    assert_eq!(code(&output), 3, "stdout:\n{}", stdout(&output));

    let text = std::fs::read_to_string(&sarif).expect("the SARIF file was not written");
    let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(parsed["version"], "2.1.0");
    assert!(!parsed["runs"][0]["results"].as_array().unwrap().is_empty());
    assert!(
        !text.contains("totally-fake-value-0001"),
        "invariant I3: the value must not reach the SARIF file"
    );
}

#[test]
fn init_installs_a_hook_that_runs_the_staged_scan() {
    let sandbox = Sandbox::new();
    let repository = init_repository_with_commit(sandbox.project());

    let output = sandbox.run(&[
        "--json",
        "init",
        &sandbox.project().display().to_string(),
        "--hook",
    ]);
    assert_eq!(code(&output), 0, "stderr:\n{}", stderr(&output));
    let report = json(&output);
    assert_eq!(report["action"], "installed");

    let hook = repository.path().join("hooks").join("pre-commit");
    let body = std::fs::read_to_string(&hook).unwrap();
    assert!(body.contains("codepack scan --staged"));
}

#[test]
fn init_without_hook_says_what_it_expected_rather_than_doing_nothing() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&["init", &sandbox.project().display().to_string()]);
    assert_eq!(code(&output), 1);
    assert!(stderr(&output).contains("--hook"), "{}", stderr(&output));
}

#[test]
fn init_refuses_to_replace_a_hook_it_did_not_write() {
    let sandbox = Sandbox::new();
    let repository = init_repository_with_commit(sandbox.project());
    let hooks = repository.path().join("hooks");
    std::fs::create_dir_all(&hooks).unwrap();
    std::fs::write(hooks.join("pre-commit"), "#!/bin/sh\nmake lint\n").unwrap();

    let output = sandbox.run(&["init", &sandbox.project().display().to_string(), "--hook"]);
    assert_eq!(code(&output), 1);
    assert!(
        std::fs::read_to_string(hooks.join("pre-commit"))
            .unwrap()
            .contains("make lint"),
        "someone else's hook was destroyed"
    );
}

#[test]
fn handoff_writes_the_briefing_and_prints_the_command_without_sending_anything() {
    let sandbox = Sandbox::new();
    let bundle = sandbox.out().join("bundle");
    std::fs::create_dir_all(bundle.join("AI_CONTEXT")).unwrap();

    let output = sandbox.run(&[
        "--json",
        "handoff",
        &bundle.display().to_string(),
        "--agent",
        "claude-code",
        "--question",
        "review the export pipeline",
    ]);
    assert_eq!(code(&output), 0, "stderr:\n{}", stderr(&output));

    let report = json(&output);
    assert_eq!(report["command"], "claude");
    assert_eq!(report["extracted"], false);
    let briefing = std::fs::read_to_string(report["handoff_file"].as_str().unwrap()).unwrap();
    assert!(briefing.contains("review the export pipeline"));
}

#[test]
fn handoff_names_the_available_agents_when_asked_for_one_that_does_not_exist() {
    let sandbox = Sandbox::new();
    let bundle = sandbox.out().join("bundle");
    std::fs::create_dir_all(&bundle).unwrap();

    let output = sandbox.run(&[
        "handoff",
        &bundle.display().to_string(),
        "--agent",
        "gpt-typo",
    ]);
    assert_eq!(code(&output), 1);
    assert!(
        stderr(&output).contains("claude-code"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn an_exported_bundle_can_be_handed_to_an_agent_end_to_end() {
    // The realistic path: export, then point an agent at what came out. A `.zip` has to
    // be unpacked first, because an agent cannot read a project inside an archive.
    let sandbox = Sandbox::new();
    let export = sandbox.run(&[
        "--json",
        "export",
        &sandbox.project().display().to_string(),
        "--out",
        &sandbox.out().display().to_string(),
    ]);
    assert_eq!(code(&export), 0, "stderr:\n{}", stderr(&export));
    let archive = json(&export)["result_path"].as_str().unwrap().to_string();

    let output = sandbox.run(&["--json", "handoff", &archive]);
    assert_eq!(code(&output), 0, "stderr:\n{}", stderr(&output));

    let report = json(&output);
    assert_eq!(report["extracted"], true);
    let briefing = std::fs::read_to_string(report["handoff_file"].as_str().unwrap()).unwrap();
    assert!(briefing.contains("partial by design"));
}

// --- the MCP server, spoken to over real pipes --------------------------------------

/// Runs `codepack mcp` as a process, writes `lines` to its stdin, closes it, and parses
/// every response line.
///
/// A process, not the loop called in-process: the framing, the flushing and the promise
/// that nothing but protocol reaches stdout are properties of the program, and an
/// in-process test cannot observe any of them.
fn mcp_session(sandbox: &Sandbox, lines: &[String]) -> (Vec<serde_json::Value>, String, i32) {
    use std::io::Write;

    let mut child = Command::new(binary())
        .arg("mcp")
        .env("HOME", sandbox.home.path())
        .env("APPDATA", sandbox.home.path())
        .env("LOCALAPPDATA", sandbox.home.path())
        .env("USERPROFILE", sandbox.home.path())
        .env("XDG_CONFIG_HOME", sandbox.home.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    {
        let stdin = child.stdin.as_mut().unwrap();
        for line in lines {
            writeln!(stdin, "{line}").unwrap();
        }
    }
    // Dropping stdin is how a client shuts the server down; the process must then exit
    // on its own rather than having to be killed.
    drop(child.stdin.take());

    let output = child.wait_with_output().unwrap();
    let stdout_text = String::from_utf8_lossy(&output.stdout).into_owned();
    let responses = stdout_text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line).unwrap_or_else(|error| {
                panic!("stdout carried something that is not JSON-RPC ({error}): {line}")
            })
        })
        .collect();

    (
        responses,
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code().unwrap_or(-1),
    )
}

fn rpc(id: u32, method: &str, params: serde_json::Value) -> String {
    serde_json::json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string()
}

#[test]
fn the_mcp_server_completes_a_handshake_and_lists_its_tools() {
    let sandbox = Sandbox::new();
    let (responses, _stderr, code) = mcp_session(
        &sandbox,
        &[
            rpc(
                1,
                "initialize",
                serde_json::json!({"protocolVersion": "2025-06-18"}),
            ),
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_string(),
            rpc(2, "tools/list", serde_json::json!({})),
        ],
    );

    assert_eq!(code, 0, "closing stdin must end the session cleanly");
    // Two requests and one notification: the notification must draw no reply.
    assert_eq!(responses.len(), 2, "{responses:#?}");
    assert!(responses[0]["result"]["serverInfo"]["name"].is_string());
    assert!(
        !responses[1]["result"]["tools"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn an_agent_can_ask_why_a_file_is_missing_from_the_export() {
    // The scenario the server exists for: a `.env` is absent from a bundle, and the
    // agent finds out why instead of assuming the project does not have one.
    let sandbox = Sandbox::new().with_secret();
    let project = sandbox.project().display().to_string();

    let (responses, _stderr, code) = mcp_session(
        &sandbox,
        &[
            rpc(1, "initialize", serde_json::json!({})),
            rpc(
                2,
                "tools/call",
                serde_json::json!({
                    "name": "codepack_explain",
                    "arguments": {"project": project, "file": ".env"}
                }),
            ),
        ],
    );

    assert_eq!(code, 0);
    let result = &responses[1]["result"];
    assert_eq!(result["isError"], false, "{result:#}");
    assert_eq!(result["structuredContent"]["verdict"], "excluded");
    let reason = result["structuredContent"]["reason"].as_str().unwrap();
    assert!(
        !reason.is_empty(),
        "a verdict with no reason explains nothing"
    );
}

#[test]
fn a_scan_through_the_server_reports_what_the_command_reports() {
    let sandbox = Sandbox::new().with_secret();
    let project = sandbox.project().display().to_string();

    let (responses, _stderr, _code) = mcp_session(
        &sandbox,
        &[rpc(
            1,
            "tools/call",
            serde_json::json!({
                "name": "codepack_scan",
                "arguments": {"project": project}
            }),
        )],
    );

    let structured = &responses[0]["result"]["structuredContent"];
    assert_eq!(structured["safe_mode"], "full");
    assert!(structured["summary"]["critical"].as_u64().unwrap() > 0);
    // Invariant I3 does not stop applying because the reader is a program.
    let text = responses[0]["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    assert!(
        !text.contains("totally-fake-value-0001"),
        "the secret reached the agent: {text}"
    );
}

#[test]
fn an_export_through_the_server_writes_a_bundle_and_keeps_stdout_clean() {
    // The export prints progress. If any of it reached stdout the JSON-RPC stream would
    // stop parsing mid-session, which is why `mcp_session` fails on a non-JSON line.
    let sandbox = Sandbox::new();
    let project = sandbox.project().display().to_string();
    let out = sandbox.out().display().to_string();

    let (responses, _stderr, code) = mcp_session(
        &sandbox,
        &[rpc(
            1,
            "tools/call",
            serde_json::json!({
                "name": "codepack_export",
                "arguments": {"project": project, "out_dir": out}
            }),
        )],
    );

    assert_eq!(code, 0);
    let structured = &responses[0]["result"]["structuredContent"];
    assert_eq!(structured["successful"], true, "{structured:#}");
    let archive = structured["result_path"].as_str().unwrap();
    assert!(Path::new(archive).is_file(), "no bundle at {archive}");
}

#[test]
fn a_tool_failure_reaches_the_model_instead_of_the_transport() {
    let sandbox = Sandbox::new();
    let (responses, _stderr, code) = mcp_session(
        &sandbox,
        &[rpc(
            1,
            "tools/call",
            serde_json::json!({
                "name": "codepack_preview",
                "arguments": {"project": "/definitely/not/a/project"}
            }),
        )],
    );

    assert_eq!(code, 0, "a failed tool must not end the session");
    assert!(responses[0]["error"].is_null(), "{}", responses[0]);
    assert_eq!(responses[0]["result"]["isError"], true);
}

#[test]
fn the_server_survives_a_malformed_message_and_keeps_answering() {
    let sandbox = Sandbox::new();
    let (responses, _stderr, code) = mcp_session(
        &sandbox,
        &[
            rpc(1, "ping", serde_json::json!({})),
            "{not json at all".to_string(),
            rpc(2, "ping", serde_json::json!({})),
        ],
    );

    assert_eq!(code, 0);
    assert_eq!(responses.len(), 3);
    assert_eq!(responses[0]["id"], 1);
    assert_eq!(responses[1]["error"]["code"], -32700);
    assert_eq!(responses[2]["id"], 2);
}

// --- scan --baseline (2026-09-05) ---------------------------------------------------

/// The question a team has on day one: fail on the next finding, not on the ones that
/// were already here.
#[test]
fn a_recorded_baseline_holds_back_what_it_recorded() {
    let sandbox = Sandbox::new().with_secret();
    let project = sandbox.project().display().to_string();
    let baseline = sandbox.out().join("baseline.json").display().to_string();

    // Before: the secret is reported and gates.
    let before = sandbox.run(&["scan", &project, "--json"]);
    assert_eq!(code(&before), 3, "a critical finding must gate");
    let before_total = json(&before)["summary"]["total_findings"].as_u64().unwrap();
    assert!(before_total > 0);

    // Record it.
    let recorded = sandbox.run(&["scan", &project, "--write-baseline", &baseline]);
    assert_eq!(
        code(&recorded),
        3,
        "recording does not change this run's verdict"
    );
    assert!(Path::new(&baseline).is_file());

    // After: nothing new, so nothing to report and nothing to fail on.
    let after = sandbox.run(&["scan", &project, "--baseline", &baseline, "--json"]);
    assert_eq!(code(&after), 0, "stdout: {}", stdout(&after));
    let payload = json(&after);
    assert_eq!(payload["summary"]["total_findings"], 0);
    assert_eq!(
        payload["baselined"].as_array().unwrap().len() as u64,
        before_total
    );
    assert!(
        payload["baseline"]
            .as_str()
            .unwrap()
            .contains("baseline.json")
    );
}

/// And a finding that arrived after the baseline was taken is exactly what should get
/// through it.
#[test]
fn a_new_finding_is_not_held_back_by_an_older_baseline() {
    let sandbox = Sandbox::new().with_secret();
    let project = sandbox.project().display().to_string();
    let baseline = sandbox.out().join("baseline.json").display().to_string();

    sandbox.run(&["scan", &project, "--write-baseline", &baseline]);

    // A second credential appears, in a file the baseline never saw.
    std::fs::write(
        sandbox.project().join("src").join("settings.py"),
        "DATABASE_URL = \"postgres://user:hunter2hunter2@db.internal/app\"\n",
    )
    .unwrap();

    let after = sandbox.run(&["scan", &project, "--baseline", &baseline, "--json"]);
    let payload = json(&after);
    assert!(
        payload["summary"]["total_findings"].as_u64().unwrap() > 0,
        "the new finding must survive the baseline: {payload}"
    );
}

#[test]
fn the_human_output_says_a_baseline_was_used() {
    let sandbox = Sandbox::new().with_secret();
    let project = sandbox.project().display().to_string();
    let baseline = sandbox.out().join("baseline.json").display().to_string();
    sandbox.run(&["scan", &project, "--write-baseline", &baseline]);

    let after = sandbox.run(&["scan", &project, "--baseline", &baseline]);
    let text = stdout(&after);
    assert!(text.contains("Baseline:"), "{text}");
    assert!(text.contains("already recorded"), "{text}");
}

#[test]
fn a_missing_baseline_file_is_an_error_rather_than_a_silent_pass() {
    let sandbox = Sandbox::new().with_secret();
    let project = sandbox.project().display().to_string();
    let absent = sandbox.out().join("nope.json").display().to_string();

    let output = sandbox.run(&["scan", &project, "--baseline", &absent]);
    assert_eq!(code(&output), 1, "stderr: {}", stderr(&output));
}

/// `.codepack-allow` means "reviewed"; a baseline means "already present". They stack,
/// and the report keeps them apart.
#[test]
fn an_allowlist_and_a_baseline_are_reported_separately() {
    let sandbox = Sandbox::new().with_secret();
    let project = sandbox.project().display().to_string();

    // Accept the first finding through the allowlist.
    let listed = json(&sandbox.run(&["scan", &project, "--json"]));
    let fingerprint = listed["findings"][0]["fingerprint"].as_str().unwrap();
    std::fs::write(
        sandbox.project().join(".codepack-allow"),
        format!("[[allow]]\nfingerprint = \"{fingerprint}\"\nreason = \"reviewed\"\n"),
    )
    .unwrap();

    let baseline = sandbox.out().join("baseline.json").display().to_string();
    sandbox.run(&["scan", &project, "--write-baseline", &baseline]);

    let payload = json(&sandbox.run(&["scan", &project, "--baseline", &baseline, "--json"]));
    assert_eq!(
        payload["suppressed"].as_array().unwrap().len(),
        1,
        "the allowlist keeps its own list: {payload}"
    );
    assert!(payload["baselined"].is_array());
    assert_eq!(payload["summary"]["total_findings"], 0);
}

/// The baseline records what survives the allowlist, so an accepted finding is not
/// frozen twice.
#[test]
fn a_baseline_does_not_record_what_the_allowlist_already_accepts() {
    let sandbox = Sandbox::new().with_secret();
    let project = sandbox.project().display().to_string();

    let listed = json(&sandbox.run(&["scan", &project, "--json"]));
    let all = listed["summary"]["total_findings"].as_u64().unwrap();
    let fingerprint = listed["findings"][0]["fingerprint"].as_str().unwrap();
    std::fs::write(
        sandbox.project().join(".codepack-allow"),
        format!("[[allow]]\nfingerprint = \"{fingerprint}\"\nreason = \"reviewed\"\n"),
    )
    .unwrap();

    let baseline = sandbox.out().join("baseline.json").display().to_string();
    sandbox.run(&["scan", &project, "--write-baseline", &baseline]);

    let body = std::fs::read_to_string(&baseline).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        parsed["fingerprints"].as_array().unwrap().len() as u64,
        all - 1
    );
    assert!(!body.contains(fingerprint));
}

// --- init --hook --strict (Q35) ------------------------------------------------------

#[test]
fn the_strict_hook_is_installed_and_says_so() {
    let sandbox = Sandbox::new();
    git2::Repository::init(sandbox.project()).unwrap();
    let project = sandbox.project().display().to_string();

    let output = sandbox.run(&["init", &project, "--hook", "--strict", "--json"]);
    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));

    let payload = json(&output);
    assert_eq!(payload["strict"], true);
    let hook = std::fs::read_to_string(payload["hook"].as_str().unwrap()).unwrap();
    assert!(hook.contains("exit 1"));
}

#[test]
fn the_default_hook_is_still_the_permissive_one() {
    let sandbox = Sandbox::new();
    git2::Repository::init(sandbox.project()).unwrap();
    let project = sandbox.project().display().to_string();

    let payload = json(&sandbox.run(&["init", &project, "--hook", "--json"]));
    assert_eq!(payload["strict"], false);
    let hook = std::fs::read_to_string(payload["hook"].as_str().unwrap()).unwrap();
    assert!(hook.contains("NOT checked"));
}

/// A finding listed in *both* files is a case neither file's documentation answers.
///
/// The order settles it: the allowlist runs first, so the finding leaves the set before
/// the baseline is consulted, and it is reported as reviewed rather than as merely old.
/// That is the right way round — "somebody read this" is the stronger statement — but it
/// is a decision, so it is pinned here.
#[test]
fn a_finding_in_both_files_is_reported_as_reviewed_not_as_old() {
    let sandbox = Sandbox::new().with_secret();
    let project = sandbox.project().display().to_string();

    let listed = json(&sandbox.run(&["scan", &project, "--json"]));
    let fingerprint = listed["findings"][0]["fingerprint"].as_str().unwrap();

    // The same fingerprint in both files.
    std::fs::write(
        sandbox.project().join(".codepack-allow"),
        format!("[[allow]]\nfingerprint = \"{fingerprint}\"\nreason = \"reviewed\"\n"),
    )
    .unwrap();
    let baseline = sandbox.out().join("baseline.json").display().to_string();
    std::fs::write(
        &baseline,
        format!(
            r#"{{"schema_version":1,"generated_at":"now","project":"p","fingerprints":["{fingerprint}"]}}"#
        ),
    )
    .unwrap();

    let payload = json(&sandbox.run(&["scan", &project, "--baseline", &baseline, "--json"]));
    let suppressed = payload["suppressed"].as_array().unwrap();
    assert!(
        suppressed
            .iter()
            .any(|entry| entry["fingerprint"] == fingerprint),
        "the allowlist should claim it: {payload}"
    );
    assert!(
        !payload["baselined"]
            .as_array()
            .is_some_and(|entries| entries
                .iter()
                .any(|entry| entry["fingerprint"] == fingerprint)),
        "and the baseline should not claim it twice: {payload}"
    );
}

/// Fingerprints are relative to the project, not absolute — which is the property that
/// makes a committed `.codepack-allow` work at all.
///
/// The consequence is worth stating plainly, because it surprises: two checkouts with
/// the same relative path and the same content produce the *same* fingerprint, so a
/// baseline is portable between them. That is deliberate — a clone at a different path
/// is the same repository — and it also means pointing `--baseline` at an unrelated
/// project's file will silence findings there. The file is named explicitly on the
/// command line, so that is a user's choice rather than a silent trap, but it is a real
/// edge and this is where it is recorded.
#[test]
fn a_fingerprint_follows_the_relative_path_so_it_survives_a_clone() {
    let original = Sandbox::new().with_secret();
    let baseline = original.out().join("baseline.json").display().to_string();
    original.run(&[
        "scan",
        &original.project().display().to_string(),
        "--write-baseline",
        &baseline,
    ]);

    // A second checkout: a different directory, the same relative layout and contents.
    let clone = Sandbox::new().with_secret();
    let payload = json(&clone.run(&[
        "scan",
        &clone.project().display().to_string(),
        "--baseline",
        &baseline,
        "--json",
    ]));
    assert_eq!(
        payload["summary"]["total_findings"], 0,
        "a clone at another path is the same repository: {payload}"
    );

    // Rotating the value in place does *not* move the fingerprint, and that deserves
    // stating rather than discovering. The fingerprint is computed from the **redacted**
    // message, because a fingerprint derived from the value would be a checkable
    // commitment to it — the same reason a hash was rejected for the labels (invariant
    // I3). So it identifies "this rule, in this file, in this shape", not "this
    // credential".
    //
    // The consequence: an entry a team accepted survives a key rotation. For an accepted
    // `.env` that is arguably right — the acceptance was about the file, not the byte
    // string — but it is a real property with a security flavour, and it is recorded here
    // rather than left to be found by someone relying on the opposite.
    std::fs::write(
        clone.project().join(".env"),
        concat!(
            "API_KEY=",
            "a-completely-different-value
"
        ),
    )
    .unwrap();
    let after = json(&clone.run(&[
        "scan",
        &clone.project().display().to_string(),
        "--baseline",
        &baseline,
        "--json",
    ]));
    assert_eq!(
        after["summary"]["total_findings"], 0,
        "the redacted shape is unchanged, so the fingerprint is too: {after}"
    );

    // What *does* move it is the shape: a different key name is a different finding.
    std::fs::write(
        clone.project().join(".env"),
        concat!(
            "OTHER_KEY=",
            "totally-fake-value-0001
"
        ),
    )
    .unwrap();
    let renamed = json(&clone.run(&[
        "scan",
        &clone.project().display().to_string(),
        "--baseline",
        &baseline,
        "--json",
    ]));
    assert!(
        renamed["summary"]["total_findings"].as_u64().unwrap() > 0,
        "a different key name is a different finding: {renamed}"
    );
}

/// Recording a baseline for a clean project writes an empty one, and reading it back is
/// a no-op rather than an error — the state a team reaches once the list is worked down.
#[test]
fn an_empty_baseline_round_trips_and_suppresses_nothing() {
    let sandbox = Sandbox::new();
    let project = sandbox.project().display().to_string();
    let baseline = sandbox.out().join("baseline.json").display().to_string();

    assert_eq!(
        code(&sandbox.run(&["scan", &project, "--write-baseline", &baseline])),
        0
    );
    let output = sandbox.run(&["scan", &project, "--baseline", &baseline, "--json"]);
    assert_eq!(code(&output), 0);
    assert_eq!(json(&output)["summary"]["total_findings"], 0);
}

/// `--write-baseline` and `--baseline` naming the same file in one run: the baseline is
/// written from what survives the allowlist and then immediately filters the report, so
/// the run reports nothing new — which is the honest answer, and is what a team's first
/// adoption run looks like.
#[test]
fn recording_and_reading_the_same_file_in_one_run_is_coherent() {
    let sandbox = Sandbox::new().with_secret();
    let project = sandbox.project().display().to_string();
    let baseline = sandbox.out().join("baseline.json").display().to_string();

    let output = sandbox.run(&[
        "scan",
        &project,
        "--write-baseline",
        &baseline,
        "--baseline",
        &baseline,
        "--json",
    ]);
    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    assert_eq!(json(&output)["summary"]["total_findings"], 0);
}
