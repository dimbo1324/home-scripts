//! Tests for [`super`], the heuristic scanner.
//!
//! Split out of `mod.rs` on 2026-07-27: that file had grown to 890 lines, past the
//! project's own ~600-line limit (`.ai/project/12-domain-rules.md`), and the tests
//! were the larger half. Same remedy already applied to `commands/export.rs`.

use super::*;
use std::io::Write;

fn write_file(dir: &Path, relative: &str, content: &str) -> PathBuf {
    let full = dir.join(relative);
    if let Some(parent) = full.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let mut file = fs::File::create(&full).unwrap();
    file.write_all(content.as_bytes()).unwrap();
    PathBuf::from(relative)
}

fn no_cancel() -> CancellationToken {
    CancellationToken::new()
}

#[test]
fn sensitive_file_and_secret_line_and_risky_code_all_detected() {
    let dir = tempfile::tempdir().unwrap();
    let env = write_file(dir.path(), ".env", "API_KEY=abcdef0123456789\n");
    let script = write_file(
        dir.path(),
        "app.py",
        "eval(user_input)\nAKIAABCDEFGHIJKLMNOP\n",
    );

    let result = scan_project(dir.path(), &[env, script], None, &no_cancel()).unwrap();

    assert!(
        result
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::SensitiveFile && f.severity == "critical")
    );
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::PotentialSecret && f.rule == "secret_like_line")
    );
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::PotentialSecret && f.rule == "aws-access-key-id")
    );
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::RiskyCode && f.rule == "python-eval")
    );
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::RiskyCode && f.rule == "js-eval")
    );
    assert_eq!(result.summary.total_findings, result.findings.len());
}

#[test]
fn self_protection_suppresses_own_source_lines() {
    let dir = tempfile::tempdir().unwrap();
    let file = write_file(
        dir.path(),
        "notes.txt",
        "// see SECRET_PATTERNS and redact_secrets for details\n",
    );

    let result = scan_project(dir.path(), &[file], None, &no_cancel()).unwrap();
    assert!(
        result
            .findings
            .iter()
            .all(|f| f.kind != FindingKind::PotentialSecret)
    );
}

#[test]
fn binary_files_are_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let full = dir.path().join("data.bin");
    fs::write(&full, [0u8, 1, 2, 3, 0, 0, 0]).unwrap();

    let result =
        scan_project(dir.path(), &[PathBuf::from("data.bin")], None, &no_cancel()).unwrap();
    assert!(result.findings.is_empty());
}

#[test]
fn no_raw_secret_value_ever_reaches_a_finding_message() {
    let dir = tempfile::tempdir().unwrap();
    let file = write_file(
        dir.path(),
        "config.py",
        "API_KEY = \"super-secret-value-xyz\"\n",
    );

    let result = scan_project(dir.path(), &[file], None, &no_cancel()).unwrap();
    for finding in &result.findings {
        assert!(!finding.message.contains("super-secret-value-xyz"));
    }
}

#[test]
fn bare_provider_signature_with_no_adjacent_keyword_is_still_redacted() {
    // Regression test for a real I3 violation found during S3 integration:
    // `keyword::redacted_line` alone only redacts keyword-shaped `key=value`
    // spans. A bare AWS-shaped key with no keyword anywhere on the line has no
    // such span for it to act on, so without `mask_non_keyword_secret_spans` the
    // raw key text passed straight through into `Finding.message`.
    let dir = tempfile::tempdir().unwrap();
    let file = write_file(dir.path(), "notes.txt", "AKIAABCDEFGHIJKLMNOP\n");

    let result = scan_project(dir.path(), &[file], None, &no_cancel()).unwrap();
    let hit = result
        .findings
        .iter()
        .find(|f| f.rule == "aws-access-key-id")
        .expect("aws-access-key-id finding present");
    assert!(!hit.message.contains("AKIAABCDEFGHIJKLMNOP"));
}

#[test]
fn bare_high_entropy_token_with_no_adjacent_keyword_is_still_redacted() {
    let dir = tempfile::tempdir().unwrap();
    let token = "aZ9kQ2wLp7xR4tY8mN1cJ6hF3sD0eU";
    let file = write_file(dir.path(), "notes.txt", &format!("{token}\n"));

    let result = scan_project(dir.path(), &[file], None, &no_cancel()).unwrap();
    let hit = result
        .findings
        .iter()
        .find(|f| f.rule == "high-entropy-token")
        .expect("high-entropy-token finding present");
    assert!(!hit.message.contains(token));
}

#[test]
fn overlapping_provider_and_entropy_spans_mask_the_full_extent() {
    // Regression test for a real I3 violation found during S3 review:
    // `mask_non_keyword_secret_spans` sorted spans by start and, on finding an
    // overlap, dropped the later span entirely instead of extending the
    // redaction to cover it. A short fixed-length provider match (the AWS key,
    // 20 chars) glued directly (no separator) to more characters makes the
    // entropy tokenizer see one long token starting at the same offset but
    // extending well past the provider match's end — the tail used to leak
    // into every `Finding.message` on the line, including the entropy
    // detector's own finding about that exact span.
    let dir = tempfile::tempdir().unwrap();
    let secret = "AKIAABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789zzzzTAILSECRETPORTION";
    let file = write_file(dir.path(), "notes.txt", &format!("{secret}\n"));

    let result = scan_project(dir.path(), &[file], None, &no_cancel()).unwrap();
    assert!(
        !result.findings.is_empty(),
        "expected at least one secret finding on this line"
    );
    for finding in &result.findings {
        assert!(!finding.message.contains("TAILSECRETPORTION"));
        assert!(!finding.message.contains(secret));
    }
}

#[test]
fn keyword_hit_suppresses_a_duplicate_entropy_hit_on_the_same_line() {
    // Golden-parity regression (fixture `python_app`, `app/main.py:5`, and fixture
    // `mixed_stack`, `docker-compose.yml:10`): the line was reported twice, once as
    // `secret_like_line` and once as `high-entropy-token`, on the identical
    // file+line span. Legacy emits exactly one `SecretFinding` per line.
    let dir = tempfile::tempdir().unwrap();
    let file = write_file(
        dir.path(),
        "main.py",
        "SECRET_TOKEN = \"placeholder-token-for-fixture-only\"\n",
    );

    let result = scan_project(dir.path(), &[file], None, &no_cancel()).unwrap();
    let secrets: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.kind == FindingKind::PotentialSecret)
        .collect();
    assert_eq!(
        secrets.len(),
        1,
        "expected exactly one potential-secret finding, got {secrets:?}"
    );
    assert_eq!(secrets[0].rule, "secret_like_line");
}

#[test]
fn entropy_hit_survives_on_a_line_the_keyword_cascade_does_not_flag() {
    // The other half of the suppression rule: the recall gain must not be lost. This
    // line carries no keyword root anywhere, so the keyword cascade is silent and the
    // entropy detector is the only thing that can see it.
    let dir = tempfile::tempdir().unwrap();
    let file = write_file(dir.path(), "notes.txt", "aZ9kQ2wLp7xR4tY8mN1cJ6hF3sD0eU\n");

    let result = scan_project(dir.path(), &[file], None, &no_cancel()).unwrap();
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.rule == "high-entropy-token"),
        "entropy findings must survive on lines the keyword cascade misses"
    );
}

#[test]
fn provider_hit_survives_on_a_line_the_keyword_cascade_does_not_flag() {
    let dir = tempfile::tempdir().unwrap();
    let file = write_file(dir.path(), "notes.txt", "AKIAABCDEFGHIJKLMNOP\n");

    let result = scan_project(dir.path(), &[file], None, &no_cancel()).unwrap();
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.rule == "aws-access-key-id")
    );
}

#[test]
fn redaction_keeps_the_key_name_that_identifies_the_finding() {
    // Golden-parity regression (fixture `mixed_stack`, `docker-compose.yml:10`): the
    // entropy tokenizer's alphabet includes `=`, so `JWT_SECRET=<value>` is a single
    // token; masking that span before `keyword::redacted_line` wiped `JWT_SECRET=`
    // too and produced a message — `- <REDACTED>` — that no longer said which secret
    // was found. Legacy's message is `- JWT_SECRET=<REDACTED>`.
    let dir = tempfile::tempdir().unwrap();
    let file = write_file(
        dir.path(),
        "docker-compose.yml",
        "      - JWT_SECRET=fixture-placeholder-value\n",
    );

    let result = scan_project(dir.path(), &[file], None, &no_cancel()).unwrap();
    let secret = result
        .findings
        .iter()
        .find(|f| f.kind == FindingKind::PotentialSecret)
        .expect("a potential-secret finding on the JWT_SECRET line");
    assert_eq!(secret.message, "- JWT_SECRET=<REDACTED>");
    assert!(!secret.message.contains("fixture-placeholder-value"));
}

#[test]
fn redaction_matches_legacy_when_only_the_value_carries_the_keyword() {
    // Golden-parity regression (fixture `python_app`, `app/main.py:5`). Legacy's
    // `SECRET_KEY_PATTERN` matches `\btoken\b` inside the *value*
    // (`placeholder-token-for-fixture-only`), not inside `SECRET_TOKEN` (where `_`
    // blocks the word boundary on both roots) — which is why legacy reports this line
    // at `low` confidence and collapses it to `SECRET_TOKEN=<REDACTED>`. Masking the
    // value first deleted that `token` substring, the collapse never fired, and the
    // message came out as the uncollapsed `SECRET_TOKEN = "<REDACTED>"`.
    let dir = tempfile::tempdir().unwrap();
    let file = write_file(
        dir.path(),
        "main.py",
        "SECRET_TOKEN = \"placeholder-token-for-fixture-only\"\n",
    );

    let result = scan_project(dir.path(), &[file], None, &no_cancel()).unwrap();
    let secret = result
        .findings
        .iter()
        .find(|f| f.kind == FindingKind::PotentialSecret)
        .expect("a potential-secret finding on the SECRET_TOKEN line");
    assert_eq!(secret.confidence, "low");
    assert_eq!(secret.message, "SECRET_TOKEN=<REDACTED>");
}

#[test]
fn provider_token_in_the_surviving_key_prefix_is_still_masked() {
    // The residual pass in `redacted_message` is not decoration: `redacted_line`
    // keeps everything before the first `=`/`:`, so a provider token sitting in that
    // prefix reaches the message untouched in legacy. I3 forbids that here.
    let dir = tempfile::tempdir().unwrap();
    let file = write_file(
        dir.path(),
        "notes.txt",
        "AKIAABCDEFGHIJKLMNOP token: value\n",
    );

    let result = scan_project(dir.path(), &[file], None, &no_cancel()).unwrap();
    for finding in &result.findings {
        assert!(
            !finding.message.contains("AKIAABCDEFGHIJKLMNOP"),
            "provider token leaked through the surviving key prefix: {}",
            finding.message
        );
    }
}

// --- Finding 2 (2026-07-27 audit): the scanner now sees connection-string
// passwords and Basic/Digest auth, neither of which any prior detector caught. ---

#[test]
fn a_password_inside_a_connection_string_is_now_found() {
    let dir = tempfile::tempdir().unwrap();
    let file = write_file(
        dir.path(),
        "app.py",
        "db.connect('postgres://admin:hunter2fakepass@host/db?sslmode=require')\n",
    );

    let result = scan_project(dir.path(), &[file], None, &no_cancel()).unwrap();
    let hit = result
        .findings
        .iter()
        .find(|f| f.rule == "url-credentials")
        .expect("url-credentials finding present");
    assert!(!hit.message.contains("hunter2fakepass"));
}

#[test]
fn a_basic_auth_header_is_now_found() {
    let dir = tempfile::tempdir().unwrap();
    let file = write_file(
        dir.path(),
        "app.py",
        "headers = {'Authorization': 'Basic ZmFrZXVzZXI6ZmFrZXBhc3N3b3Jk'}\n",
    );

    let result = scan_project(dir.path(), &[file], None, &no_cancel()).unwrap();
    let hit = result
        .findings
        .iter()
        .find(|f| f.rule == "http-auth-credentials")
        .expect("http-auth-credentials finding present");
    assert!(!hit.message.contains("ZmFrZXVzZXI6ZmFrZXBhc3N3b3Jk"));
}

#[test]
fn a_url_with_no_credentials_is_not_flagged() {
    // The audit's own suggested negative: the '@' sits in the path, not the
    // authority, because a '/' appears first -- structurally not a credential.
    let dir = tempfile::tempdir().unwrap();
    let file = write_file(dir.path(), "notes.txt", "http://host/a:b@c\n");

    let result = scan_project(dir.path(), &[file], None, &no_cancel()).unwrap();
    assert!(
        result.findings.iter().all(|f| f.rule != "url-credentials"),
        "a path that only looks like userinfo must not be flagged"
    );
}

#[test]
fn the_audits_own_reproduction_is_now_fully_detected() {
    // AUDIT-2026-07-27.md, finding 2's table: of four planted secrets, only two were
    // found before this fix. All four must be found now.
    let dir = tempfile::tempdir().unwrap();
    let file = write_file(
        dir.path(),
        "app.py",
        "db.connect('postgres://admin:hunter2fakepass@host/db?sslmode=require')\n\
         AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n\
         headers = {'Authorization': 'Basic ZmFrZXVzZXI6ZmFrZXBhc3N3b3Jk'}\n\
         api_key = \"sk-projFAKEfghijklmnopqrstuvwxyz1234567890ABCD\"\n",
    );

    let result = scan_project(dir.path(), &[file], None, &no_cancel()).unwrap();
    let secrets: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.kind == FindingKind::PotentialSecret)
        .collect();
    assert_eq!(
        secrets.len(),
        4,
        "expected all four planted secrets to be found, got {secrets:?}"
    );
    for finding in &secrets {
        for raw in [
            "hunter2fakepass",
            "AKIAIOSFODNN7EXAMPLE",
            "ZmFrZXVzZXI6ZmFrZXBhc3N3b3Jk",
            "sk-projFAKEfghijklmnopqrstuvwxyz1234567890ABCD",
        ] {
            assert!(
                !finding.message.contains(raw),
                "{raw} leaked into a finding message: {finding:?}"
            );
        }
    }
}

#[test]
fn cancellation_is_checked_inside_the_file_loop() {
    let dir = tempfile::tempdir().unwrap();
    let files: Vec<PathBuf> = (0..3)
        .map(|i| write_file(dir.path(), &format!("file{i}.txt"), "nothing interesting\n"))
        .collect();

    let cancel = CancellationToken::new();
    cancel.cancel();
    let result = scan_project(dir.path(), &files, None, &cancel);
    assert!(matches!(result, Err(SecurityError::Cancelled)));
}

// --- Parallelism, options and the content cache ---------------------------------------
//
// Everything below covers behaviour added on 2026-09-05: the per-file pass became
// parallel, and gained a redactor, a strict-checksum switch and a cache.

/// A cache that lives in this test, so the scanner's side of the contract can be
/// exercised without a database.
#[derive(Default)]
struct MemoryCache {
    entries: std::sync::Mutex<std::collections::HashMap<String, Vec<crate::cache::CachedFinding>>>,
    lookups: std::sync::atomic::AtomicUsize,
    stores: std::sync::atomic::AtomicUsize,
}

impl MemoryCache {
    fn lookups(&self) -> usize {
        self.lookups.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn stores(&self) -> usize {
        self.stores.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl crate::cache::FileScanCache for MemoryCache {
    fn lookup(&self, key: &str) -> Option<Vec<crate::cache::CachedFinding>> {
        self.lookups
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.entries.lock().unwrap().get(key).cloned()
    }

    fn store(&self, key: &str, findings: &[crate::cache::CachedFinding]) {
        self.stores
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.entries
            .lock()
            .unwrap()
            .insert(key.to_string(), findings.to_vec());
    }
}

/// A project wide enough that rayon really splits it, with findings of several
/// severities spread across files whose names collide when lowercased.
fn many_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = vec![write_file(dir, ".env", "API_KEY=abcdef0123456789\n")];
    for index in 0..40 {
        files.push(write_file(
            dir,
            &format!("src/mod{index}.py"),
            "import os\npassword = \"hunter2hunter2hunter2\"\neval(user_input)\nprint(1)\n",
        ));
    }
    // Two paths differing only in case: their sort keys tie, so only insertion order
    // decides, which is exactly what the parallel collection must preserve.
    files.push(write_file(
        dir,
        "src/Alpha.txt",
        "token = \"abcdefghijklmnop\"\n",
    ));
    files.push(write_file(
        dir,
        "src/other.txt",
        "token = \"abcdefghijklmnop\"\n",
    ));
    files
}

/// The property the whole parallel rewrite rests on. A different order here would move
/// findings in `06_security_scan.json`, SARIF and the golden references, silently.
#[test]
fn the_finding_order_is_the_same_on_every_run() {
    let dir = tempfile::tempdir().unwrap();
    let files = many_files(dir.path());

    let first = scan_project(dir.path(), &files, None, &no_cancel()).unwrap();
    assert!(
        first.findings.len() > 40,
        "the fixture must be worth sorting"
    );

    for attempt in 0..15 {
        let again = scan_project(dir.path(), &files, None, &no_cancel()).unwrap();
        assert_eq!(again, first, "run {attempt} disagreed with the first");
    }
}

/// The same files in a different order are a different input, and the answer follows
/// the input rather than the thread schedule.
#[test]
fn the_order_follows_the_input_not_the_schedule() {
    let dir = tempfile::tempdir().unwrap();
    let files = many_files(dir.path());
    let mut reversed = files.clone();
    reversed.reverse();

    let forwards = scan_project(dir.path(), &files, None, &no_cancel()).unwrap();
    let backwards = scan_project(dir.path(), &reversed, None, &no_cancel()).unwrap();

    // Same findings either way — the sort is total enough for that…
    assert_eq!(forwards.summary, backwards.summary);
    // …and repeating the reversed input reproduces the reversed answer exactly.
    let backwards_again = scan_project(dir.path(), &reversed, None, &no_cancel()).unwrap();
    assert_eq!(backwards, backwards_again);
}

#[test]
fn cancellation_is_still_observed_per_file() {
    let dir = tempfile::tempdir().unwrap();
    let files = many_files(dir.path());
    let cancel = CancellationToken::new();
    cancel.cancel();

    let error = scan_project(dir.path(), &files, None, &cancel).unwrap_err();
    assert!(matches!(error, SecurityError::Cancelled));
}

#[test]
fn default_options_are_the_four_argument_call() {
    let dir = tempfile::tempdir().unwrap();
    let files = many_files(dir.path());

    let plain = scan_project(dir.path(), &files, None, &no_cancel()).unwrap();
    let explicit = scan_project_with_options(
        dir.path(),
        &files,
        None,
        &no_cancel(),
        &ScanOptions::default(),
    )
    .unwrap();
    assert_eq!(plain, explicit);
}

// --- Redaction labels reaching the scanner's own artifacts (Q34) ----------------------

fn scan_with(dir: &Path, files: &[PathBuf], options: &ScanOptions<'_>) -> ScanResult {
    scan_project_with_options(dir, files, None, &no_cancel(), options).unwrap()
}

#[test]
fn a_labelling_redactor_puts_labels_in_the_findings() {
    let dir = tempfile::tempdir().unwrap();
    let files = vec![write_file(
        dir.path(),
        "app.py",
        "API_KEY = \"one-secret-value-here\"\nOTHER_KEY = \"another-secret-value\"\n",
    )];

    let redactor = crate::Redactor::labelled();
    let result = scan_with(
        dir.path(),
        &files,
        &ScanOptions {
            redactor: Some(&redactor),
            ..ScanOptions::default()
        },
    );

    let messages: Vec<&str> = result
        .findings
        .iter()
        .map(|finding| finding.message.as_str())
        .collect();
    // The numbers themselves are a run's own bookkeeping — first-seen order, and the
    // line's own redaction may consume one before the finding does. What the feature
    // promises is that two different secrets are told apart, so that is what is asserted.
    let labels: std::collections::BTreeSet<String> = messages
        .iter()
        .flat_map(|message| {
            message.match_indices("<REDACTED:").filter_map(|(at, _)| {
                message[at..]
                    .split_once('>')
                    .map(|(label, _)| label.to_string())
            })
        })
        .collect();
    assert!(
        !labels.is_empty(),
        "no label reached a finding: {messages:?}"
    );
    assert_eq!(
        labels.len(),
        2,
        "two distinct secrets must carry two distinct labels: {messages:?}"
    );
    // And never the value itself (invariant I3).
    assert!(
        !messages
            .iter()
            .any(|message| message.contains("secret-value"))
    );
}

#[test]
fn a_plain_redactor_is_byte_for_byte_the_old_behaviour() {
    let dir = tempfile::tempdir().unwrap();
    let files = many_files(dir.path());

    let plain = crate::Redactor::plain();
    let with_redactor = scan_with(
        dir.path(),
        &files,
        &ScanOptions {
            redactor: Some(&plain),
            ..ScanOptions::default()
        },
    );
    let without = scan_project(dir.path(), &files, None, &no_cancel()).unwrap();
    assert_eq!(with_redactor, without);
}

// --- Strict token checksums ------------------------------------------------------------

/// A token shaped like GitHub's but with a checksum that cannot recompute — the shape a
/// documentation sample takes.
const PLACEHOLDER_TOKEN: &str = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

#[test]
fn a_failed_checksum_is_ignored_unless_strict_mode_is_asked_for() {
    let dir = tempfile::tempdir().unwrap();
    let files = vec![write_file(
        dir.path(),
        "docs.md",
        // A bare token, no keyword: `token = "..."` would be claimed by the keyword
        // cascade first (rule 1), and the provider rule would never be consulted.
        &format!("{PLACEHOLDER_TOKEN}\n"),
    )];

    let relaxed = scan_project(dir.path(), &files, None, &no_cancel()).unwrap();
    let token_finding = relaxed
        .findings
        .iter()
        .find(|finding| finding.rule == "github-token")
        .expect("the shape is still recognised");
    assert_eq!(
        token_finding.severity, "critical",
        "the default must not weaken a finding on an unverified recipe"
    );
}

#[test]
fn strict_mode_weakens_a_token_whose_checksum_fails_without_dropping_it() {
    let dir = tempfile::tempdir().unwrap();
    let files = vec![write_file(
        dir.path(),
        "docs.md",
        // A bare token, no keyword: `token = "..."` would be claimed by the keyword
        // cascade first (rule 1), and the provider rule would never be consulted.
        &format!("{PLACEHOLDER_TOKEN}\n"),
    )];

    let strict = scan_with(
        dir.path(),
        &files,
        &ScanOptions {
            strict_token_checksums: true,
            ..ScanOptions::default()
        },
    );
    let token_finding = strict
        .findings
        .iter()
        .find(|finding| finding.rule == "github-token")
        .expect("still reported, never dropped");
    assert_eq!(token_finding.severity, "medium");
}

/// A token built the way the recipe says one is built, so a *valid* checksum can be
/// tested rather than only an invalid one.
fn token_with_a_valid_checksum() -> String {
    use crate::patterns::checksum::{ENTROPY_LEN, base62_checksum, crc32};
    let entropy: String = "abcdefghij0123456789ABCDEFGHIJ".to_string();
    assert_eq!(entropy.len(), ENTROPY_LEN);
    format!(
        "ghp_{entropy}{}",
        base62_checksum(crc32(entropy.as_bytes()))
    )
}

/// The half that matters most: strict mode must weaken only what actually failed.
///
/// Note what this run shows about the layering. A realistic token — mixed alphanumerics
/// after `ghp_` — is claimed by the keyword cascade (rule 1) before the provider
/// signature is ever consulted, so it is reported as `secret_like_line`/`high` and the
/// checksum branch does not see it at all. That is a safety property worth stating: the
/// unverified recipe cannot reach a token the cascade already recognised, which is the
/// shape a real credential takes. Strict mode therefore changes nothing here.
#[test]
fn strict_mode_leaves_a_token_whose_checksum_holds_alone() {
    let dir = tempfile::tempdir().unwrap();
    let files = vec![write_file(
        dir.path(),
        "config.py",
        &format!(
            "{}
",
            token_with_a_valid_checksum()
        ),
    )];

    let relaxed = scan_project(dir.path(), &files, None, &no_cancel()).unwrap();
    let strict = scan_with(
        dir.path(),
        &files,
        &ScanOptions {
            strict_token_checksums: true,
            ..ScanOptions::default()
        },
    );

    assert_eq!(
        relaxed, strict,
        "a token whose checksum holds must be reported identically either way"
    );
    assert!(
        relaxed
            .findings
            .iter()
            .any(|finding| finding.severity == "critical" || finding.severity == "high"),
        "and it must still be reported strongly: {:?}",
        relaxed.findings
    );
}

/// A vendor with no recipe must never be weakened: "I cannot check this" is not
/// evidence about the token.
#[test]
fn strict_mode_leaves_an_uncheckable_vendor_alone() {
    let dir = tempfile::tempdir().unwrap();
    let files = vec![write_file(
        dir.path(),
        "aws.py",
        "aws_access_key_id = \"AKIAABCDEFGHIJKLMNOP\"
",
    )];

    let relaxed = scan_project(dir.path(), &files, None, &no_cancel()).unwrap();
    let strict = scan_with(
        dir.path(),
        &files,
        &ScanOptions {
            strict_token_checksums: true,
            ..ScanOptions::default()
        },
    );
    assert_eq!(relaxed, strict);
}

// --- The content cache ------------------------------------------------------------------

#[test]
fn a_second_scan_is_served_from_the_cache() {
    let dir = tempfile::tempdir().unwrap();
    let files = many_files(dir.path());
    let cache = MemoryCache::default();

    let first = scan_with(
        dir.path(),
        &files,
        &ScanOptions {
            cache: Some(&cache),
            ..ScanOptions::default()
        },
    );
    let stored_after_first = cache.stores();
    assert!(stored_after_first > 0, "the first pass must fill the cache");

    let second = scan_with(
        dir.path(),
        &files,
        &ScanOptions {
            cache: Some(&cache),
            ..ScanOptions::default()
        },
    );

    assert_eq!(first, second, "a cached answer must equal a computed one");
    assert_eq!(
        cache.stores(),
        stored_after_first,
        "nothing new should have been scanned the second time"
    );
    assert!(cache.lookups() >= files.len());
}

/// The mistake a content-keyed cache invites: `.env` and a copy of it under another
/// name have the same bytes and different verdicts.
#[test]
fn the_sensitive_filename_verdict_is_never_served_from_content() {
    let dir = tempfile::tempdir().unwrap();
    let secret_line = "API_KEY=abcdef0123456789\n";
    let env = write_file(dir.path(), ".env", secret_line);
    let notes = write_file(dir.path(), "notes.txt", secret_line);
    let cache = MemoryCache::default();

    let options = ScanOptions {
        cache: Some(&cache),
        ..ScanOptions::default()
    };
    // `.env` first, so its entry is in the cache before `notes.txt` is looked at.
    let result = scan_with(dir.path(), &[env, notes], &options);

    let sensitive: Vec<&str> = result
        .findings
        .iter()
        .filter(|finding| finding.kind == FindingKind::SensitiveFile)
        .map(|finding| finding.file.as_str())
        .collect();
    assert_eq!(
        sensitive.len(),
        1,
        "notes.txt must not inherit .env's verdict: {sensitive:?}"
    );
    assert!(
        sensitive[0].ends_with(".env"),
        "the surviving sensitive-file finding should be .env's: {sensitive:?}"
    );
}

#[test]
fn a_cached_run_and_an_uncached_run_agree() {
    let dir = tempfile::tempdir().unwrap();
    let files = many_files(dir.path());
    let cache = MemoryCache::default();

    let uncached = scan_project(dir.path(), &files, None, &no_cancel()).unwrap();
    let cold = scan_with(
        dir.path(),
        &files,
        &ScanOptions {
            cache: Some(&cache),
            ..ScanOptions::default()
        },
    );
    let warm = scan_with(
        dir.path(),
        &files,
        &ScanOptions {
            cache: Some(&cache),
            ..ScanOptions::default()
        },
    );

    assert_eq!(uncached, cold);
    assert_eq!(uncached, warm);
}

/// Labels are numbered per run, so a message stored by an earlier one would carry a
/// number standing for a different value. The cache is skipped rather than risked.
#[test]
fn a_labelling_run_does_not_touch_the_cache() {
    let dir = tempfile::tempdir().unwrap();
    let files = many_files(dir.path());
    let cache = MemoryCache::default();
    let redactor = crate::Redactor::labelled();

    scan_with(
        dir.path(),
        &files,
        &ScanOptions {
            redactor: Some(&redactor),
            cache: Some(&cache),
            ..ScanOptions::default()
        },
    );

    assert_eq!(cache.lookups(), 0);
    assert_eq!(cache.stores(), 0);
}

/// An entry recorded with one option set must not answer a run with another, or the
/// switch would appear to do nothing.
#[test]
fn strict_mode_does_not_read_the_relaxed_run_s_entries() {
    let dir = tempfile::tempdir().unwrap();
    let files = vec![write_file(
        dir.path(),
        "docs.md",
        // A bare token, no keyword: `token = "..."` would be claimed by the keyword
        // cascade first (rule 1), and the provider rule would never be consulted.
        &format!("{PLACEHOLDER_TOKEN}\n"),
    )];
    let cache = MemoryCache::default();

    let relaxed = scan_with(
        dir.path(),
        &files,
        &ScanOptions {
            cache: Some(&cache),
            ..ScanOptions::default()
        },
    );
    let strict = scan_with(
        dir.path(),
        &files,
        &ScanOptions {
            cache: Some(&cache),
            strict_token_checksums: true,
            ..ScanOptions::default()
        },
    );

    let severity_of = |result: &ScanResult| {
        result
            .findings
            .iter()
            .find(|finding| finding.rule == "github-token")
            .map(|finding| finding.severity.clone())
            .unwrap()
    };
    assert_eq!(severity_of(&relaxed), "critical");
    assert_eq!(severity_of(&strict), "medium");
}

#[test]
fn result_from_findings_recounts_by_kind() {
    let dir = tempfile::tempdir().unwrap();
    let files = many_files(dir.path());
    let result = scan_project(dir.path(), &files, None, &no_cancel()).unwrap();

    let rebuilt = result_from_findings(result.findings.clone());
    assert_eq!(rebuilt.summary, result.summary);
    assert_eq!(rebuilt.findings, result.findings);

    let empty = result_from_findings(Vec::new());
    assert_eq!(empty.summary, ScanSummary::default());
}
