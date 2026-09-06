//! End-to-end coverage for [`codepack_engine::run_export`]: the full eight-step
//! pipeline, run once against a small fixture project with a real (tempdir-backed)
//! `codepack-storage` database. A dedicated, later verification pass adds the golden
//! per-stack fixtures, the full 8-scenario cancellation battery, and the
//! large-fixture performance test (`task-checklist.md`'s S9 Verification section);
//! this file only proves the wiring itself is correct end to end.

use std::collections::HashMap;
use std::fs;
use std::io::Read as _;
use std::path::Path;

use codepack_core::CancellationToken;
use codepack_core::config::Config;
use codepack_engine::run_export;

fn init_git_repo(root: &Path) {
    let repo = git2::Repository::init(root).unwrap();
    fs::write(root.join("tracked.txt"), "hello from git\n").unwrap();
    let mut index = repo.index().unwrap();
    index
        .add_all(["*"], git2::IndexAddOption::DEFAULT, None)
        .unwrap();
    index.write().unwrap();
    let tree_id = index.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let signature = git2::Signature::now("Test", "test@example.local").unwrap();
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        "initial commit",
        &tree,
        &[],
    )
    .unwrap();
}

fn read_zip_entry(zip_path: &Path, name: &str) -> String {
    let file = fs::File::open(zip_path).unwrap();
    let mut archive = zip::ZipArchive::new(file).unwrap();
    let mut entry = archive.by_name(name).unwrap();
    let mut contents = String::new();
    entry.read_to_string(&mut contents).unwrap();
    contents
}

fn zip_entry_names(zip_path: &Path) -> Vec<String> {
    let file = fs::File::open(zip_path).unwrap();
    let mut archive = zip::ZipArchive::new(file).unwrap();
    (0..archive.len())
        .map(|index| archive.by_index(index).unwrap().name().to_string())
        .collect()
}

fn build_fixture(source: &Path) {
    fs::write(source.join("main.py"), "print('hello')\n").unwrap();
    fs::write(source.join("README.md"), "# Fixture project\n").unwrap();
    fs::write(source.join(".env"), "API_KEY=super-secret-value\n").unwrap();
    init_git_repo(source);
}

#[test]
fn a_full_run_produces_an_archive_a_real_manifest_and_a_storage_row_then_cleans_staging() {
    let source = tempfile::tempdir().unwrap();
    build_fixture(source.path());
    let output = tempfile::tempdir().unwrap();
    let db_dir = tempfile::tempdir().unwrap();

    let mut conn = codepack_storage::open(&db_dir.path().join("codepack.db")).unwrap();
    let config = Config::default();
    let cancel = CancellationToken::new();
    let (tx, rx) = codepack_core::progress_channel();

    let outcome = run_export(
        &mut conn,
        source.path(),
        output.path(),
        &config,
        &HashMap::new(),
        &tx,
        &cancel,
    )
    .unwrap();
    drop(tx);

    assert!(!outcome.cancelled);
    assert!(outcome.successful, "copy_stats = {:?}", outcome.copy_stats);
    assert_eq!(outcome.copy_stats.errors, 0);

    // At least one progress event was actually sent (the channel is real, not a stub).
    assert!(rx.try_iter().count() > 0);

    let primary = outcome
        .archive_result
        .primary_result()
        .expect("a successful run always produces a primary archive result");
    assert!(primary.exists());
    if !outcome.archive_result.split {
        assert!(fs::metadata(primary).unwrap().len() > 0);
    }

    // The default safe export mode ("safe") excludes `.env`-shaped files: the secret
    // never reaches the copy, so it can never reach the final archive either.
    let final_zip = &outcome.paths.final_zip;
    assert!(final_zip.exists());
    let entry_names = zip_entry_names(final_zip);
    assert!(
        !entry_names.iter().any(|name| name.ends_with(".env")),
        "entries = {entry_names:?}"
    );

    let manifest_json = read_zip_entry(final_zip, "manifest.json");
    let manifest: serde_json::Value = serde_json::from_str(&manifest_json).unwrap();
    assert_ne!(manifest["archives"]["status"], "not_written_yet");

    let run_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM export_run", [], |row| row.get(0))
        .unwrap();
    assert_eq!(run_count, 1);

    let baseline = codepack_storage::latest_snapshot(&conn, outcome.project_id).unwrap();
    assert!(
        baseline.is_some(),
        "a successful run must advance the project's latest snapshot"
    );

    assert!(
        !outcome.paths.staging_dir.exists(),
        "staging must be removed by default (keep_staging_folder = false)"
    );
}

/// Finding 1, 2026-07-27 audit, reproduced end to end through the real pipeline: on
/// default settings (`redact_secrets: true`), a file carrying a connection-string
/// password, a bare AWS access key, a `Basic` auth header, and an `api_key` assignment
/// must not carry any of those four secrets into `03_text_dump.txt` — the artifact
/// built specifically to hand a project to an AI assistant. This test fails on the
/// code as it stood before the fix (only the last of the four was ever redacted).
#[test]
fn planted_secrets_never_reach_the_text_dump() {
    let source = tempfile::tempdir().unwrap();
    fs::write(
        source.path().join("app.py"),
        "db.connect('postgres://admin:hunter2fakepass@host/db?sslmode=require')\n\
         AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n\
         headers = {'Authorization': 'Basic ZmFrZXVzZXI6ZmFrZXBhc3N3b3Jk'}\n\
         api_key = \"sk-projFAKEfghijklmnopqrstuvwxyz1234567890ABCD\"\n",
    )
    .unwrap();
    init_git_repo(source.path());

    let output = tempfile::tempdir().unwrap();
    let db_dir = tempfile::tempdir().unwrap();
    let mut conn = codepack_storage::open(&db_dir.path().join("codepack.db")).unwrap();
    // Explicit rather than relying on Config::default() staying this way by accident:
    // this test's whole point is the default-settings reproduction from the audit.
    let config = Config {
        redact_secrets: true,
        ..Config::default()
    };
    let cancel = CancellationToken::new();
    let (tx, _rx) = codepack_core::progress_channel();

    let outcome = run_export(
        &mut conn,
        source.path(),
        output.path(),
        &config,
        &HashMap::new(),
        &tx,
        &cancel,
    )
    .unwrap();
    assert!(outcome.successful, "copy_stats = {:?}", outcome.copy_stats);

    // The scanner must still have flagged all four, confirming this is the "product
    // already knows" scenario the audit described, not a case where nothing was found.
    assert!(
        outcome.copy_stats.errors == 0,
        "export itself must succeed regardless of what the scanner finds"
    );

    let dump = read_zip_entry(&outcome.paths.final_zip, "reports/03_text_dump.txt");
    for secret in [
        "hunter2fakepass",
        "AKIAIOSFODNN7EXAMPLE",
        "ZmFrZXVzZXI6ZmFrZXBhc3N3b3Jk",
        "sk-projFAKEfghijklmnopqrstuvwxyz1234567890ABCD",
    ] {
        assert!(
            !dump.contains(secret),
            "{secret} leaked into 03_text_dump.txt, the file handed to an AI assistant"
        );
    }
}

/// `redaction_labels` end to end: the same credential used twice must come out of the
/// pipeline wearing the same label, a different one must not, and neither value may
/// appear anywhere in the bundle.
#[test]
fn stable_labels_survive_the_pipeline_without_the_secrets_doing_so() {
    let source = tempfile::tempdir().unwrap();
    fs::write(
        source.path().join("api.py"),
        "api_key = \"sharedFAKEsecretvalue1234\"\n",
    )
    .unwrap();
    fs::write(
        source.path().join("worker.py"),
        "token: \"sharedFAKEsecretvalue1234\"\npassword = \"aDifferentFAKEvalue5678\"\n",
    )
    .unwrap();
    init_git_repo(source.path());

    let output = tempfile::tempdir().unwrap();
    let db_dir = tempfile::tempdir().unwrap();
    let mut conn = codepack_storage::open(&db_dir.path().join("codepack.db")).unwrap();
    let config = Config {
        redact_secrets: true,
        redaction_labels: true,
        ..Config::default()
    };
    let cancel = CancellationToken::new();
    let (tx, _rx) = codepack_core::progress_channel();

    let outcome = run_export(
        &mut conn,
        source.path(),
        output.path(),
        &config,
        &HashMap::new(),
        &tx,
        &cancel,
    )
    .unwrap();
    assert!(outcome.successful, "copy_stats = {:?}", outcome.copy_stats);

    let dump = read_zip_entry(&outcome.paths.final_zip, "reports/03_text_dump.txt");

    for secret in ["sharedFAKEsecretvalue1234", "aDifferentFAKEvalue5678"] {
        assert!(!dump.contains(secret), "{secret} leaked into the text dump");
    }

    // Two occurrences of one secret, one of another: three labelled placeholders over
    // two distinct labels.
    assert_eq!(
        dump.matches("<REDACTED:s1>").count(),
        2,
        "the shared credential must carry one label in both files:\n{dump}"
    );
    assert_eq!(
        dump.matches("<REDACTED:s2>").count(),
        1,
        "the second, different credential must not share that label:\n{dump}"
    );
    assert!(
        dump.contains("stable label per distinct secret"),
        "the header must explain what <REDACTED:sN> means"
    );
}

/// The default must remain byte-identical to what the product produced before labels
/// existed. This is what lets the feature ship without moving a golden reference.
#[test]
fn labels_off_by_default_leaves_the_placeholder_exactly_as_it_was() {
    let source = tempfile::tempdir().unwrap();
    fs::write(
        source.path().join("api.py"),
        "api_key = \"sharedFAKEsecretvalue1234\"\n",
    )
    .unwrap();

    let output = tempfile::tempdir().unwrap();
    let db_dir = tempfile::tempdir().unwrap();
    let mut conn = codepack_storage::open(&db_dir.path().join("codepack.db")).unwrap();
    let cancel = CancellationToken::new();
    let (tx, _rx) = codepack_core::progress_channel();

    let outcome = run_export(
        &mut conn,
        source.path(),
        output.path(),
        &Config::default(),
        &HashMap::new(),
        &tx,
        &cancel,
    )
    .unwrap();

    let dump = read_zip_entry(&outcome.paths.final_zip, "reports/03_text_dump.txt");
    assert!(dump.contains("<REDACTED>"), "{dump}");
    assert!(
        !dump.contains("<REDACTED:"),
        "a default run must not label anything"
    );
    assert!(dump.contains("Secrets redaction: enabled\n"));
}

#[test]
fn keep_staging_folder_true_leaves_the_staging_tree_in_place() {
    let source = tempfile::tempdir().unwrap();
    fs::write(source.path().join("main.py"), "print(1)\n").unwrap();
    let output = tempfile::tempdir().unwrap();
    let db_dir = tempfile::tempdir().unwrap();

    let mut conn = codepack_storage::open(&db_dir.path().join("codepack.db")).unwrap();
    let config = Config {
        keep_staging_folder: true,
        ..Config::default()
    };
    let cancel = CancellationToken::new();
    let (tx, _rx) = codepack_core::progress_channel();

    let outcome = run_export(
        &mut conn,
        source.path(),
        output.path(),
        &config,
        &HashMap::new(),
        &tx,
        &cancel,
    )
    .unwrap();

    assert!(outcome.successful);
    assert!(outcome.paths.staging_dir.exists());
    assert!(outcome.paths.manifest_file.is_file());
}

#[test]
fn a_pre_cancelled_run_still_writes_the_manifest_and_archive_and_records_the_attempt() {
    let source = tempfile::tempdir().unwrap();
    build_fixture(source.path());
    let output = tempfile::tempdir().unwrap();
    let db_dir = tempfile::tempdir().unwrap();

    let mut conn = codepack_storage::open(&db_dir.path().join("codepack.db")).unwrap();
    // `keep_staging_folder: true` here is a test-observability choice, not a pipeline
    // requirement: staging cleanup always runs regardless of cancellation (see
    // `orchestrator.rs`'s own doc comment), and `manifest.json` lives inside the
    // staging tree, so keeping it lets this test inspect it directly on disk instead
    // of unzipping the final archive a second time.
    let config = Config {
        keep_staging_folder: true,
        ..Config::default()
    };
    let cancel = CancellationToken::new();
    cancel.cancel();
    let (tx, _rx) = codepack_core::progress_channel();

    let outcome = run_export(
        &mut conn,
        source.path(),
        output.path(),
        &config,
        &HashMap::new(),
        &tx,
        &cancel,
    )
    .unwrap();

    assert!(outcome.cancelled);
    assert!(!outcome.successful);
    assert!(outcome.analytics.is_none());

    // Steps 7-8 and history recording run unconditionally, cancelled or not.
    assert!(outcome.paths.manifest_file.is_file());
    let primary = outcome
        .archive_result
        .primary_result()
        .expect("archiving still runs, and still produces a result, on a cancelled run");
    assert!(primary.exists());

    let run_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM export_run", [], |row| row.get(0))
        .unwrap();
    assert_eq!(run_count, 1);

    let cancelled_flag: bool = conn
        .query_row(
            "SELECT cancelled FROM export_run WHERE id = ?1",
            [outcome.run_id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(cancelled_flag);

    let baseline = codepack_storage::latest_snapshot(&conn, outcome.project_id).unwrap();
    assert!(
        baseline.is_none(),
        "a cancelled run must never insert a snapshot row"
    );
}

// --- The allowlist and the scan cache in the pipeline (2026-09-05) ---------------------

/// A project whose secret is *inside* a file the export keeps, so the finding survives
/// into the bundle and the allowlist has something to act on. A bare `.env` would not
/// do: safe mode drops it before the scanner ever looks.
fn project_with_a_reported_secret(source: &Path) {
    fs::write(source.join("main.py"), "print('hello')\n").unwrap();
    fs::write(
        source.join("settings.py"),
        "DATABASE_URL = \"postgres://user:hunter2hunter2@db.internal/app\"\n",
    )
    .unwrap();
    init_git_repo(source);
}

fn run_once(
    source: &Path,
    output: &Path,
    conn: &mut codepack_storage::Connection,
) -> codepack_engine::ExportOutcome {
    let config = Config {
        // Keep the staging folder so a test can read the reports the run wrote.
        keep_staging_folder: true,
        ..Config::default()
    };
    let cancel = CancellationToken::new();
    let (tx, _rx) = codepack_core::progress_channel();
    let outcome = run_export(conn, source, output, &config, &HashMap::new(), &tx, &cancel).unwrap();
    drop(tx);
    outcome
}

fn fingerprint_of_first_finding(outcome: &codepack_engine::ExportOutcome) -> String {
    let analytics = outcome.analytics.as_ref().expect("step 6 ran");
    let finding = analytics
        .scan_result
        .findings
        .first()
        .expect("the fixture must produce a finding");
    codepack_security::allow::fingerprint_of(finding)
}

/// Q26: the file used to be honoured by `scan` and `verify` while the bundle went on
/// reporting what a team had already accepted.
#[test]
fn the_export_pipeline_honours_codepack_allow() {
    let source = tempfile::tempdir().unwrap();
    project_with_a_reported_secret(source.path());
    let output = tempfile::tempdir().unwrap();
    let db_dir = tempfile::tempdir().unwrap();
    let mut conn = codepack_storage::open(&db_dir.path().join("codepack.db")).unwrap();

    // First run: nothing is accepted yet, so the finding is reported.
    let before = run_once(source.path(), output.path(), &mut conn);
    let before_count = before
        .analytics
        .as_ref()
        .unwrap()
        .scan_result
        .findings
        .len();
    assert!(before_count > 0, "the fixture must produce a finding");
    let accepted = fingerprint_of_first_finding(&before);

    // Now the team accepts it, in the source project where the file belongs.
    fs::write(
        source.path().join(codepack_core::ALLOWLIST_FILE_NAME),
        format!("[[allow]]\nfingerprint = \"{accepted}\"\nreason = \"reviewed fixture\"\n"),
    )
    .unwrap();

    let output_after = tempfile::tempdir().unwrap();
    let after = run_once(source.path(), output_after.path(), &mut conn);
    let after_findings = &after.analytics.as_ref().unwrap().scan_result.findings;

    assert_eq!(
        after_findings.len(),
        before_count - 1,
        "the accepted finding should be gone and nothing else with it"
    );
    assert!(
        !after_findings
            .iter()
            .any(|finding| codepack_security::allow::fingerprint_of(finding) == accepted),
        "the accepted finding is still being reported"
    );
    // The summary has to agree with the list it sits above.
    assert_eq!(
        after
            .analytics
            .as_ref()
            .unwrap()
            .scan_result
            .summary
            .total_findings,
        after_findings.len()
    );
}

/// A malformed file must stop the run rather than be ignored: silently skipping it
/// would leave a reviewer believing findings are accepted when they are still reported.
#[test]
fn a_malformed_allowlist_fails_the_export_rather_than_being_ignored() {
    let source = tempfile::tempdir().unwrap();
    project_with_a_reported_secret(source.path());
    fs::write(
        source.path().join(codepack_core::ALLOWLIST_FILE_NAME),
        "[[allow]]\nfingerprint = \"not-a-fingerprint\"\nreason = \"r\"\n",
    )
    .unwrap();

    let output = tempfile::tempdir().unwrap();
    let db_dir = tempfile::tempdir().unwrap();
    let mut conn = codepack_storage::open(&db_dir.path().join("codepack.db")).unwrap();
    let config = Config::default();
    let cancel = CancellationToken::new();
    let (tx, _rx) = codepack_core::progress_channel();

    let result = run_export(
        &mut conn,
        source.path(),
        output.path(),
        &config,
        &HashMap::new(),
        &tx,
        &cancel,
    );
    assert!(
        result.is_err(),
        "a broken allowlist must not pass unnoticed"
    );
}

/// The cache exists to make the second run cheaper without making it different.
#[test]
fn a_second_export_fills_the_cache_and_answers_identically() {
    let source = tempfile::tempdir().unwrap();
    project_with_a_reported_secret(source.path());
    let db_dir = tempfile::tempdir().unwrap();
    let mut conn = codepack_storage::open(&db_dir.path().join("codepack.db")).unwrap();

    let first_out = tempfile::tempdir().unwrap();
    let first = run_once(source.path(), first_out.path(), &mut conn);

    let cached: i64 = conn
        .query_row("SELECT COUNT(*) FROM file_scan_cache", [], |row| row.get(0))
        .unwrap();
    assert!(cached > 0, "the first export must fill the cache");

    let second_out = tempfile::tempdir().unwrap();
    let second = run_once(source.path(), second_out.path(), &mut conn);

    assert_eq!(
        first.analytics.as_ref().unwrap().scan_result,
        second.analytics.as_ref().unwrap().scan_result,
        "a cached run must produce the same findings as the run that filled it"
    );

    // Nothing new to learn from unchanged bytes.
    let after: i64 = conn
        .query_row("SELECT COUNT(*) FROM file_scan_cache", [], |row| row.get(0))
        .unwrap();
    assert_eq!(after, cached);
}

/// Changing a file must not be answered from the cache — the whole risk of a
/// content-addressed store is a stale verdict presented as a current one.
#[test]
fn editing_a_file_produces_a_fresh_verdict() {
    let source = tempfile::tempdir().unwrap();
    fs::write(source.path().join("main.py"), "print('hello')\n").unwrap();
    init_git_repo(source.path());
    let db_dir = tempfile::tempdir().unwrap();
    let mut conn = codepack_storage::open(&db_dir.path().join("codepack.db")).unwrap();

    let clean_out = tempfile::tempdir().unwrap();
    let clean = run_once(source.path(), clean_out.path(), &mut conn);
    let clean_findings = clean.analytics.as_ref().unwrap().scan_result.findings.len();

    // The same file, now carrying a credential.
    fs::write(
        source.path().join("main.py"),
        "DATABASE_URL = \"postgres://user:hunter2hunter2@db.internal/app\"\n",
    )
    .unwrap();

    let dirty_out = tempfile::tempdir().unwrap();
    let dirty = run_once(source.path(), dirty_out.path(), &mut conn);
    let dirty_findings = dirty.analytics.as_ref().unwrap().scan_result.findings.len();

    assert!(
        dirty_findings > clean_findings,
        "the edit must be seen: {clean_findings} then {dirty_findings}"
    );
}

/// With `redaction_labels` on, the labels have to reach the scanner's own artifacts —
/// the gap Q34 named — and never the value itself.
#[test]
fn redaction_labels_reach_the_security_scan_report() {
    let source = tempfile::tempdir().unwrap();
    fs::write(
        source.path().join("settings.py"),
        "DATABASE_URL = \"postgres://user:hunter2hunter2@db.internal/app\"\n",
    )
    .unwrap();
    init_git_repo(source.path());

    let output = tempfile::tempdir().unwrap();
    let db_dir = tempfile::tempdir().unwrap();
    let mut conn = codepack_storage::open(&db_dir.path().join("codepack.db")).unwrap();
    let config = Config {
        redaction_labels: true,
        keep_staging_folder: true,
        ..Config::default()
    };
    let cancel = CancellationToken::new();
    let (tx, _rx) = codepack_core::progress_channel();

    let outcome = run_export(
        &mut conn,
        source.path(),
        output.path(),
        &config,
        &HashMap::new(),
        &tx,
        &cancel,
    )
    .unwrap();
    drop(tx);

    let report =
        fs::read_to_string(outcome.paths.insights_dir.join("06_security_scan.json")).unwrap();
    assert!(
        report.contains("<REDACTED:s") || report.contains("<REDACTED_SECRET:s"),
        "no label reached the scan report"
    );
    assert!(
        !report.contains("hunter2hunter2"),
        "invariant I3: the value must never reach an artifact"
    );
}

/// And with the flag off — the default — the report is byte for byte what it always was.
#[test]
fn labels_off_leaves_the_scan_report_unlabelled() {
    let source = tempfile::tempdir().unwrap();
    fs::write(
        source.path().join("settings.py"),
        "DATABASE_URL = \"postgres://user:hunter2hunter2@db.internal/app\"\n",
    )
    .unwrap();
    init_git_repo(source.path());

    let output = tempfile::tempdir().unwrap();
    let db_dir = tempfile::tempdir().unwrap();
    let mut conn = codepack_storage::open(&db_dir.path().join("codepack.db")).unwrap();
    let outcome = run_once(source.path(), output.path(), &mut conn);

    let report =
        fs::read_to_string(outcome.paths.insights_dir.join("06_security_scan.json")).unwrap();
    assert!(!report.contains("<REDACTED:s"));
    assert!(!report.contains("<REDACTED_SECRET:s"));
    assert!(!report.contains("hunter2hunter2"));
}

/// The promise labels exist to keep: one credential carries one label across every
/// artifact in the bundle.
///
/// This is the regression test for a defect the scanner's own tests exposed. Redaction
/// runs in more than one pass, and the later pass used to treat an existing
/// `<REDACTED:s1>` as a fresh secret and issue `s2` — so `03_text_dump.txt` and
/// `06_security_scan.json` disagreed about the same value, which is exactly the question
/// a reader uses the labels to answer.
#[test]
fn one_credential_carries_one_label_across_the_whole_bundle() {
    fn labels_in(text: &str) -> std::collections::BTreeSet<String> {
        let mut found = std::collections::BTreeSet::new();
        for prefix in ["<REDACTED:", "<REDACTED_SECRET:"] {
            let mut from = 0usize;
            while let Some(at) = text[from..].find(prefix) {
                let start = from + at;
                let Some(offset) = text[start..].find('>') else {
                    break;
                };
                let label = &text[start..start + offset + 1];
                // The dump's header explains the notation with a literal `<REDACTED:sN>`;
                // that is a legend, not a label, so only `s` followed by digits counts.
                let number = label.rsplit(':').next().unwrap_or("").trim_end_matches('>');
                if let Some(digits) = number.strip_prefix('s')
                    && !digits.is_empty()
                    && digits.bytes().all(|byte| byte.is_ascii_digit())
                {
                    found.insert(label.to_string());
                }
                from = start + offset + 1;
            }
        }
        found
    }

    let source = tempfile::tempdir().unwrap();
    // The same credential in two files: one leak, and the bundle has to say so.
    let secret = "postgres://user:hunter2hunter2@db.internal/app";
    fs::write(
        source.path().join("settings.py"),
        format!("DATABASE_URL = \"{secret}\"\n"),
    )
    .unwrap();
    fs::write(
        source.path().join("worker.py"),
        format!("DATABASE_URL = \"{secret}\"\n"),
    )
    .unwrap();
    init_git_repo(source.path());

    let output = tempfile::tempdir().unwrap();
    let db_dir = tempfile::tempdir().unwrap();
    let mut conn = codepack_storage::open(&db_dir.path().join("codepack.db")).unwrap();
    let config = Config {
        redaction_labels: true,
        keep_staging_folder: true,
        ..Config::default()
    };
    let cancel = CancellationToken::new();
    let (tx, _rx) = codepack_core::progress_channel();

    let outcome = run_export(
        &mut conn,
        source.path(),
        output.path(),
        &config,
        &HashMap::new(),
        &tx,
        &cancel,
    )
    .unwrap();
    drop(tx);

    let dump = fs::read_to_string(&outcome.paths.text_dump)
        .expect("the text dump is part of every bundle");
    let scan = fs::read_to_string(outcome.paths.insights_dir.join("06_security_scan.json"))
        .expect("the scan report is part of every bundle");

    // Neither artifact may carry the value itself (invariant I3).
    assert!(!dump.contains("hunter2hunter2"));
    assert!(!scan.contains("hunter2hunter2"));

    let in_dump = labels_in(&dump);
    let in_scan = labels_in(&scan);
    assert!(
        !in_dump.is_empty(),
        "the dump should carry labels: {dump:.400}"
    );
    assert!(!in_scan.is_empty(), "the report should carry labels");

    // One credential, so one number — and the same number on both sides.
    assert_eq!(
        in_dump.len(),
        1,
        "two files, one credential, so one label: {in_dump:?}"
    );
    let dump_number: Vec<&str> = in_dump.iter().map(|label| label.as_str()).collect();
    let scan_number: Vec<&str> = in_scan.iter().map(|label| label.as_str()).collect();
    let suffix = |label: &str| label.rsplit(':').next().unwrap_or(label).to_string();
    assert_eq!(
        suffix(dump_number[0]),
        suffix(scan_number[0]),
        "the same credential is labelled differently in two artifacts: {in_dump:?} vs {in_scan:?}"
    );
}

/// No artifact in the bundle may carry a credential embedded in a `package.json` script.
///
/// Written as a sweep over *every* file rather than as three assertions about three
/// reports, because the defect it guards was precisely that: four reports extracted the
/// same thing, one redacted it and three did not. A per-report test would have passed on
/// the one that was right and never been written for the fifth report nobody has added
/// yet. This one covers reports that do not exist.
#[test]
fn no_bundle_artifact_carries_a_credential_from_a_package_json_script() {
    fn walk(dir: &Path, found: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, found);
            } else {
                found.push(path);
            }
        }
    }

    const CREDENTIAL: &str = "npm_realvalue0123456789abcdef";

    let source = tempfile::tempdir().unwrap();
    fs::write(
        source.path().join("package.json"),
        format!(
            r#"{{"name":"demo","scripts":{{"deploy":"NPM_TOKEN={CREDENTIAL} npm publish","build":"vite build"}}}}"#
        ),
    )
    .unwrap();
    fs::write(source.path().join("main.js"), "console.log(1);\n").unwrap();
    init_git_repo(source.path());

    let output = tempfile::tempdir().unwrap();
    let db_dir = tempfile::tempdir().unwrap();
    let mut conn = codepack_storage::open(&db_dir.path().join("codepack.db")).unwrap();
    let config = Config {
        // Kept so the whole bundle can be swept before it is cleaned up.
        keep_staging_folder: true,
        ..Config::default()
    };
    let cancel = CancellationToken::new();
    let (tx, _rx) = codepack_core::progress_channel();

    let outcome = run_export(
        &mut conn,
        source.path(),
        output.path(),
        &config,
        &HashMap::new(),
        &tx,
        &cancel,
    )
    .unwrap();
    drop(tx);

    let mut files = Vec::new();
    walk(&outcome.paths.staging_dir, &mut files);
    assert!(files.len() > 10, "the sweep should see a real bundle");

    let mut leaked: Vec<String> = Vec::new();
    for file in &files {
        // The copied `package.json` itself is the source file, not an artifact: copied
        // sources are included verbatim and safe mode governs which ones (see the
        // README's own wording after this audit). Everything codepack *writes* is in
        // scope here.
        if file.file_name().is_some_and(|name| name == "package.json") {
            continue;
        }
        if let Ok(text) = fs::read_to_string(file)
            && text.contains(CREDENTIAL)
        {
            leaked.push(file.display().to_string());
        }
    }

    assert!(
        leaked.is_empty(),
        "a package.json script credential reached {} artifact(s): {leaked:#?}",
        leaked.len()
    );

    // And the sweep is only meaningful if the scripts actually made it into the reports.
    let runbook = fs::read_to_string(outcome.paths.insights_dir.join("13_runbook.md"))
        .expect("the runbook is part of the catalogue");
    assert!(
        runbook.contains("deploy"),
        "the script should still be listed"
    );
}

/// Invariant I2 at the layer that defines it, not at one of the two shells.
///
/// Before audit No. 3 this check lived only in `codepack-cli`, so the desktop — which
/// calls `run_export` directly — would happily stage a bundle inside the user's own
/// working tree, pick it up as a source on the next run, and, with
/// `keep_staging_folder = false`, recursively delete a directory inside their project.
#[test]
fn an_output_directory_inside_the_project_is_refused_and_nothing_is_written() {
    let source = tempfile::tempdir().unwrap();
    build_fixture(source.path());
    let db_dir = tempfile::tempdir().unwrap();
    let output = source.path().join("dist").join("bundles");

    let mut conn = codepack_storage::open(&db_dir.path().join("codepack.db")).unwrap();
    let (tx, _rx) = codepack_core::progress_channel();

    // `let ... else` rather than `expect_err`: `ExportOutcome` is deliberately not
    // `Debug`, and deriving it here would be a change to production code for a test.
    let Err(error) = run_export(
        &mut conn,
        source.path(),
        &output,
        &Config::default(),
        &HashMap::new(),
        &tx,
        &CancellationToken::new(),
    ) else {
        panic!("writing the bundle inside the source violates I2");
    };

    assert!(
        matches!(
            error,
            codepack_engine::EngineError::OutputInsideSource { .. }
        ),
        "{error:?}"
    );
    // The refusal must not be the thing that breaks the invariant: no directory is left
    // behind inside the project, and the fixture is untouched.
    assert!(!source.path().join("dist").exists());
    let mut entries: Vec<String> = fs::read_dir(source.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    entries.sort();
    assert_eq!(
        entries,
        vec![".env", ".git", "README.md", "main.py", "tracked.txt"]
    );
}

/// The source root itself is the same violation with a shorter path.
#[test]
fn the_project_root_itself_is_refused_as_an_output_directory() {
    let source = tempfile::tempdir().unwrap();
    build_fixture(source.path());
    let db_dir = tempfile::tempdir().unwrap();

    let mut conn = codepack_storage::open(&db_dir.path().join("codepack.db")).unwrap();
    let (tx, _rx) = codepack_core::progress_channel();

    let Err(error) = run_export(
        &mut conn,
        source.path(),
        source.path(),
        &Config::default(),
        &HashMap::new(),
        &tx,
        &CancellationToken::new(),
    ) else {
        panic!("a project cannot be exported into itself");
    };
    assert!(
        matches!(
            error,
            codepack_engine::EngineError::OutputInsideSource { .. }
        ),
        "{error:?}"
    );
}

/// Audit No. 21: `source_root` and `copied_root` carry the absolute paths of the machine
/// that produced the bundle — on Windows `C:\Users\<account name>\…`. With
/// `disclose_absolute_paths` off, no artifact may name the directory the export ran in.
#[test]
fn with_disclosure_off_no_artifact_names_the_machines_directories() {
    let source = tempfile::tempdir().unwrap();
    build_fixture(source.path());
    let output = tempfile::tempdir().unwrap();
    let db_dir = tempfile::tempdir().unwrap();

    let mut conn = codepack_storage::open(&db_dir.path().join("codepack.db")).unwrap();
    let config = Config {
        disclose_absolute_paths: false,
        keep_staging_folder: true,
        ..Config::default()
    };
    let (tx, _rx) = codepack_core::progress_channel();

    let outcome = run_export(
        &mut conn,
        source.path(),
        output.path(),
        &config,
        &HashMap::new(),
        &tx,
        &CancellationToken::new(),
    )
    .unwrap();

    // The tempdir's own path is the stand-in for the account name: it is the machine
    // detail that must not travel, and it appears in every one of the four fields the
    // audit named.
    let secret_path = source.path().display().to_string();
    let mut offenders = Vec::new();
    for entry in walkdir::WalkDir::new(&outcome.paths.staging_dir)
        .into_iter()
        .flatten()
    {
        if !entry.file_type().is_file() {
            continue;
        }
        // Only what codepack writes: a copied source file is the user's own content, and
        // this setting is not about rewriting that.
        let relative = entry
            .path()
            .strip_prefix(&outcome.paths.staging_dir)
            .unwrap();
        let is_copied_source = relative.starts_with(&outcome.paths.project_name);
        if is_copied_source {
            continue;
        }
        if let Ok(text) = fs::read_to_string(entry.path())
            && text.contains(&secret_path)
        {
            offenders.push(relative.display().to_string());
        }
    }

    assert!(
        offenders.is_empty(),
        "these artifacts still name the export machine's directories: {offenders:?}"
    );

    // And the fields are still there, with the project's name in them — the contract is
    // kept, only the value changed.
    let profile =
        fs::read_to_string(&outcome.paths.project_profile_file).expect("the profile is written");
    let parsed: serde_json::Value = serde_json::from_str(&profile).unwrap();
    assert!(
        parsed["source_root"].as_str().unwrap().starts_with('<'),
        "{}",
        parsed["source_root"]
    );
    assert!(parsed["copied_root"].as_str().unwrap().starts_with('<'));
}
