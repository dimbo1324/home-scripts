//! `codepack verify <bundle>` — re-scanning a bundle that has already been produced.
//!
//! ## Why the command exists
//!
//! Everything else in this product asks the pipeline to be trustworthy. This asks the
//! *artifact* to prove it, which is a different and weaker assumption: it opens the file
//! that actually exists and reports what is inside it, whatever produced it and whatever
//! options were used.
//!
//! That makes it useful to two people rather than one. The person who built the bundle
//! gets a check that is independent of the run that built it. The person **receiving**
//! one gets the only check they can perform at all — they were not there when it was
//! made, and until now had nothing to do but trust the sender.
//!
//! ## What it accepts
//!
//! A single `.zip`, a split archive-set directory (recognised by
//! `ARCHIVE_SET_MANIFEST.json`), or an already-extracted bundle folder. Which one it is
//! gets decided by looking, not by a flag: a person holding a file they were sent should
//! not have to know the vocabulary of the tool that made it.
//!
//! ## Extraction safety
//!
//! Archives are unpacked through `codepack_archive::extract_zip_safely`, the same
//! traversal-checked path S8 built and tested, into a temporary directory that is
//! removed on every exit path. A bundle is by definition a file from somewhere else, so
//! this is the one command in the binary whose input is genuinely untrusted; it does not
//! get its own second implementation of that defence (invariant I7).
//!
//! ## Why findings are split into two groups
//!
//! A codepack bundle carries the exported project *and* codepack's own reports about it.
//! Scanning both together and presenting one list makes every clean bundle look dirty:
//! `06_security_scan.txt` contains the literal placeholder `<REDACTED_SECRET_LINE>`,
//! which re-trips the keyword cascade, and `manifest.json` embeds absolute paths, which
//! trip the entropy detector. Measured on a two-file toy project, that is two dozen
//! findings for a bundle that is provably clean — and a verdict nobody can act on is
//! worse than no verdict, because the reader learns to skim it.
//!
//! So a finding is kept out of the verdict when **either** of two things is true:
//!
//! * it sits in a file codepack generated from already-redacted data
//!   ([`is_generated_artifact`]: `reports/insights/`, `manifest.json`,
//!   `PROJECT_PROFILE.json`, `INDEX.md`, `reports/01_structure.txt`); or
//! * the line it points at, *as it exists in the bundle*, holds nothing
//!   credential-shaped ([`is_not_credential_shaped`]).
//!
//! The second test is what makes `reports/03_text_dump.txt` and `reports/02_git.txt`
//! safe to leave in the verdict even though codepack writes them too. Those two carry
//! the project's own bytes, so a redaction failure must be caught there — and it is,
//! because a leaked value is credential-shaped, while a `<REDACTED_SECRET_LINE>` marker
//! or a header sentence containing the word *Secret* is not.
//!
//! Nothing is hidden. Both groups are counted and both are printed; the split says
//! *where* a finding is, and only the verdict is narrowed. A bundle that is not a
//! codepack bundle has no recognisable generated paths, so all of it is content — the
//! safe direction.

use std::path::{Path, PathBuf};

use codepack_core::CancellationToken;
use codepack_security::{FindingKind, scan_project};
use serde::Serialize;

use crate::cli::VerifyArgs;
use crate::error::{CliError, Result};
use crate::exit::Outcome;
use crate::output::{self, Format};

#[derive(Debug, Serialize)]
pub(crate) struct VerifyReport {
    /// The path as the user gave it, so the output names the thing they asked about.
    pub bundle: String,
    /// `zip`, `archive_set` or `directory` — what the path turned out to be.
    pub bundle_kind: &'static str,
    pub scanned_files: usize,
    /// Counted over the exported content only — the numbers the verdict is based on.
    pub summary: Summary,
    /// Findings in the exported project's own content. These drive the exit code.
    pub findings: Vec<ReportedFinding>,
    /// Findings inside codepack's own generated reports and metadata. Reported in full,
    /// but kept out of the verdict — see the module docs for why.
    pub generated_findings: Vec<ReportedFinding>,
    pub suppressed: Vec<crate::allow::SuppressedFinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowlist: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct Summary {
    pub sensitive_files: usize,
    pub potential_secrets: usize,
    pub risky_code: usize,
    pub total_findings: usize,
    pub critical: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct ReportedFinding {
    pub kind: &'static str,
    pub severity: String,
    pub confidence: String,
    /// Relative to the bundle root, so it reads as a location *inside the bundle*
    /// rather than as a path on whoever's machine ran the check.
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    pub rule: String,
    pub message: String,
    pub fingerprint: String,
}

/// Where the bundle's content was found, and what kind of thing it was.
enum Opened {
    /// Already on disk; nothing to clean up.
    Directory(PathBuf),
    /// Unpacked into a temporary directory that disappears when this is dropped.
    Extracted {
        directory: tempfile::TempDir,
        kind: &'static str,
    },
}

impl Opened {
    fn root(&self) -> &Path {
        match self {
            Self::Directory(path) => path,
            Self::Extracted { directory, .. } => directory.path(),
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::Directory(_) => "directory",
            Self::Extracted { kind, .. } => kind,
        }
    }
}

pub(crate) fn run(args: &VerifyArgs, format: Format) -> Result<Outcome> {
    let report = build(&args.bundle, args.allowlist_root.as_deref())?;

    if format.is_json() {
        output::emit_json("verify", &report)?;
    } else {
        print_human(&report);
    }

    Ok(if report.summary.critical > 0 {
        Outcome::CriticalSecretsFound
    } else {
        Outcome::Success
    })
}

fn build(bundle: &Path, allowlist_root: Option<&Path>) -> Result<VerifyReport> {
    let cancel = CancellationToken::new();
    let opened = open(bundle)?;
    let root = opened.root();

    let relative_files = collect_files(root)?;
    // No size limit: a limit is a statement about what is worth *shipping*, and this
    // command is looking at something already shipped. The same reasoning `scan` records
    // for `text_file_size_limit_enabled`.
    let result = scan_project(root, &relative_files, None, &cancel)?;

    let screened = match allowlist_root {
        Some(project_root) => match crate::allow::load(project_root)? {
            Some((path, index)) => crate::allow::screen(&result, &path, &index),
            None => crate::allow::Screened::unfiltered(&result),
        },
        None => crate::allow::Screened::unfiltered(&result),
    };

    Ok(assemble(
        bundle,
        opened.kind(),
        root,
        relative_files.len(),
        &screened,
    ))
}

/// Decides what `bundle` is and makes its content available as a directory.
fn open(bundle: &Path) -> Result<Opened> {
    if bundle.is_dir() {
        // An archive set is a directory too, so the manifest is what tells them apart.
        if bundle.join("ARCHIVE_SET_MANIFEST.json").is_file() {
            let directory = temp_dir()?;
            codepack_archive::restore_archive_set(bundle, directory.path())
                .map_err(|error| CliError::message(error.to_string()))?;
            return Ok(Opened::Extracted {
                directory,
                kind: "archive_set",
            });
        }
        return Ok(Opened::Directory(bundle.to_path_buf()));
    }

    if bundle.is_file() {
        let directory = temp_dir()?;
        codepack_archive::extract_zip_safely(bundle, directory.path())
            .map_err(|error| CliError::message(error.to_string()))?;
        return Ok(Opened::Extracted {
            directory,
            kind: "zip",
        });
    }

    Err(CliError::message(format!(
        "{} is not a file or a directory",
        bundle.display()
    )))
}

fn temp_dir() -> Result<tempfile::TempDir> {
    tempfile::tempdir().map_err(|source| CliError::Read {
        path: PathBuf::from("(temporary directory)"),
        source,
    })
}

/// Every file under `root`, as paths relative to it.
///
/// Symlinks are not followed: a bundle is untrusted input, and a link pointing out of
/// the extracted tree would otherwise be read from wherever it aimed (invariant I7).
fn collect_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    walk(root, root, &mut files)?;
    files.sort();
    Ok(files)
}

fn walk(root: &Path, directory: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    let entries = std::fs::read_dir(directory).map_err(|source| CliError::Read {
        path: directory.to_path_buf(),
        source,
    })?;

    for entry in entries {
        let entry = entry.map_err(|source| CliError::Read {
            path: directory.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path).map_err(|source| CliError::Read {
            path: path.clone(),
            source,
        })?;

        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            walk(root, &path, files)?;
        } else if metadata.is_file()
            && let Ok(relative) = path.strip_prefix(root)
        {
            files.push(relative.to_path_buf());
        }
    }
    Ok(())
}

fn assemble(
    bundle: &Path,
    bundle_kind: &'static str,
    root: &Path,
    scanned_files: usize,
    screened: &crate::allow::Screened,
) -> VerifyReport {
    let (generated, content): (Vec<_>, Vec<_>) = screened.findings.iter().partition(|finding| {
        is_generated_artifact(&finding.file)
            || bundle_line(root, &finding.file, finding.line)
                .is_some_and(|line| is_not_credential_shaped(&line))
    });

    let critical = content
        .iter()
        .filter(|finding| finding.severity == "critical")
        .count();
    let count_of = |kind: FindingKind| content.iter().filter(|f| f.kind == kind).count();

    let report = |finding: &codepack_security::Finding| ReportedFinding {
        kind: kind_label(finding.kind),
        severity: finding.severity.clone(),
        confidence: finding.confidence.clone(),
        file: finding.file.clone(),
        line: finding.line,
        rule: finding.rule.clone(),
        message: finding.message.clone(),
        fingerprint: crate::allow::fingerprint_of(finding),
    };

    VerifyReport {
        bundle: bundle.display().to_string(),
        bundle_kind,
        scanned_files,
        summary: Summary {
            sensitive_files: count_of(FindingKind::SensitiveFile),
            potential_secrets: count_of(FindingKind::PotentialSecret),
            risky_code: count_of(FindingKind::RiskyCode),
            total_findings: content.len(),
            critical,
        },
        findings: content.iter().map(|finding| report(finding)).collect(),
        generated_findings: generated.iter().map(|finding| report(finding)).collect(),
        suppressed: screened.suppressed.clone(),
        allowlist: screened
            .allowlist_path
            .as_ref()
            .map(|path| path.display().to_string()),
    }
}

fn kind_label(kind: FindingKind) -> &'static str {
    match kind {
        FindingKind::SensitiveFile => "sensitive_file",
        FindingKind::PotentialSecret => "potential_secret",
        FindingKind::RiskyCode => "risky_code",
    }
}

/// Removes codepack's own redaction placeholders from `line`, leaving what redaction
/// did not put there.
///
/// The spans come from `codepack-security`, which writes them, rather than from a list
/// restated here: a labelled bundle spells them `<REDACTED:s1>`, and a copy that knew
/// only the plain shapes would read every label as a leftover credential and call a
/// clean bundle dirty. Since audit No. 7 the match is exact, so a crafted
/// `<REDACTED>real-secret-value>` no longer disappears wholesale from the residue — the
/// value stays, and `verify` gets to judge it.
fn without_placeholders(line: &str) -> String {
    let mut residue = String::with_capacity(line.len());
    let mut cursor = 0usize;
    for (start, end) in codepack_security::placeholder_spans(line) {
        residue.push_str(&line[cursor..start]);
        residue.push(' ');
        cursor = end;
    }
    residue.push_str(&line[cursor..]);
    residue
}

/// The shortest run of alphanumerics `verify` still treats as possibly-a-secret once
/// placeholders are removed. Below this a leftover is a label or a word, not a
/// credential; `codepack-security`'s own entropy detector uses a comparable floor.
const RESIDUAL_SECRET_MIN_RUN: usize = 12;

/// True when the **raw bundle line** a finding points at cannot be carrying a
/// credential, so the scanner fired on something other than a secret.
///
/// The line as it sits in the bundle is the signal, not the finding's message:
/// `Finding::message` is redacted on the way out for *every* finding, real or not, so it
/// cannot tell the two apart. What the bundle actually contains can.
///
/// After codepack's own redaction markers are stripped, a line with no alphanumeric run
/// at least [`RESIDUAL_SECRET_MIN_RUN`] long has nothing credential-shaped left in it.
/// That single rule covers both ways a clean bundle used to look dirty:
///
/// * `<REDACTED_SECRET_LINE>` — redaction did its job, and the marker exists precisely
///   because the secret is gone.
/// * `Secret redaction is applied to command output.` — codepack's own report header,
///   which trips the keyword cascade on the word *Secret* while holding no value at all.
///
/// A line where redaction genuinely failed still carries the raw value, that value has a
/// long run, and the finding is reported — which is the case `verify` exists for.
///
/// Known limit, consistent with Q18: a short, word-shaped credential (`hunter2`) has no
/// long run either and is dismissed here. Telling that apart from an ordinary word by
/// shape alone is not possible, and the project already records that trade-off.
fn is_not_credential_shaped(raw_line: &str) -> bool {
    // Whole placeholders come out, labels and all, so nothing redaction introduced can
    // be mistaken for a leftover. `>` is not alphanumeric, so whatever is left of an
    // unrecognised bracket breaks a run rather than extending one.
    let residue = without_placeholders(raw_line);

    let mut run = 0usize;
    for character in residue.chars() {
        if character.is_ascii_alphanumeric() {
            run += 1;
            if run >= RESIDUAL_SECRET_MIN_RUN {
                return false;
            }
        } else {
            run = 0;
        }
    }
    true
}

/// Reads the 1-based `line` of `root/file`, when it can be read at all.
///
/// A file that cannot be read yields `None`, which classifies the finding as content —
/// the safe direction, since an unreadable line is not evidence that redaction worked.
fn bundle_line(root: &Path, file: &str, line: Option<usize>) -> Option<String> {
    let line = line?;
    let relative: PathBuf = file
        .replace('\\', "/")
        .trim_start_matches("./")
        .split('/')
        .collect();
    let text = std::fs::read_to_string(root.join(relative)).ok()?;
    text.lines().nth(line.checked_sub(1)?).map(str::to_string)
}

/// True when a bundle-relative path is a file codepack itself generated from
/// already-redacted data, rather than a place the source project's bytes land.
///
/// `03_text_dump.txt` and `02_git.txt` are deliberately **not** in this set even though
/// codepack writes them: the first concatenates the project's own file contents and the
/// second carries git output, so a redaction failure would surface in exactly those two.
/// Treating them as generated would blind the check where it matters most.
fn is_generated_artifact(file: &str) -> bool {
    // Findings report paths with backslashes and often a leading `.\`; normalise both
    // before matching so the classification does not depend on that spelling.
    let normalised = file.replace('\\', "/");
    let path = normalised
        .trim_start_matches("./")
        .trim_start_matches('/')
        .to_ascii_lowercase();

    path.starts_with("reports/insights/")
        || path == "manifest.json"
        || path == "project_profile.json"
        || path == "index.md"
        || path == "reports/01_structure.txt"
        || path == "report_plugins.json"
}

fn print_human(report: &VerifyReport) {
    output::line(format!("Bundle:    {}", report.bundle));
    output::line(format!(
        "Contents:  {} file(s) ({})",
        report.scanned_files, report.bundle_kind
    ));

    if let Some(path) = &report.allowlist {
        if report.suppressed.is_empty() {
            output::line(format!("Allowlist: {path} (nothing suppressed)"));
        } else {
            output::line(format!(
                "Allowlist: {path} — {} finding(s) accepted and not shown below",
                report.suppressed.len()
            ));
        }
    }
    output::line("");

    if report.findings.is_empty() {
        output::line("Clean: nothing found in this bundle's exported content.");
    } else {
        output::line(format!(
            "{} finding(s) in exported content: {} sensitive file(s), {} potential secret(s), {} risky code",
            report.summary.total_findings,
            report.summary.sensitive_files,
            report.summary.potential_secrets,
            report.summary.risky_code
        ));
        if report.summary.critical > 0 {
            output::line(format!("{} of them are critical.", report.summary.critical));
        }
        output::line("");
        print_findings(&report.findings);
    }

    // Always mentioned, never silently dropped: a reader must be able to see that a
    // second group exists and decide for themselves whether to look at it.
    if !report.generated_findings.is_empty() {
        output::line("");
        output::line(format!(
            "{} further finding(s) sit in codepack's own generated reports rather than in \
             the exported content. These are usually redaction placeholders and embedded \
             paths, and do not affect the verdict above.",
            report.generated_findings.len()
        ));
        print_findings(&report.generated_findings);
    }
}

fn print_findings(findings: &[ReportedFinding]) {
    for finding in findings {
        let location = match finding.line {
            Some(line) => format!("{}:{}", finding.file, line),
            None => finding.file.clone(),
        };
        output::line(format!(
            "  [{}] {} ({}) — {}",
            finding.severity, location, finding.rule, finding.message
        ));
        output::line(format!("           fingerprint: {}", finding.fingerprint));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    #[test]
    fn a_clean_directory_bundle_reports_nothing() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "src/main.rs", "fn main() {}\n");
        write(dir.path(), "README.md", "# Demo\n");

        let report = build(dir.path(), None).unwrap();
        assert_eq!(report.bundle_kind, "directory");
        assert_eq!(report.scanned_files, 2);
        assert!(report.findings.is_empty());
        assert_eq!(report.summary.critical, 0);
    }

    #[test]
    fn a_planted_secret_inside_a_directory_bundle_is_found() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "config.env",
            "API_KEY=zZ9xQ7vLwPmR3sT8uAbCdEfGhIj\n",
        );

        let report = build(dir.path(), None).unwrap();
        assert!(
            !report.findings.is_empty(),
            "a secret in the bundle must be reported"
        );
        assert!(report.findings.iter().all(|f| !f.fingerprint.is_empty()));
    }

    #[test]
    fn a_missing_path_is_an_error_rather_than_an_empty_clean_result() {
        let dir = tempfile::tempdir().unwrap();
        let error = build(&dir.path().join("nope.zip"), None).unwrap_err();
        assert!(
            error.to_string().contains("not a file or a directory"),
            "unhelpful message: {error}"
        );
    }

    #[test]
    fn a_file_that_is_not_a_zip_is_an_error_not_a_clean_result() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bundle.zip");
        std::fs::write(&path, b"this is not a zip archive").unwrap();

        // A corrupt archive must never read as "clean": that is the one wrong answer
        // this command can give, because it is the answer a user acts on.
        assert!(build(&path, None).is_err());
    }

    #[test]
    fn nested_files_are_reported_relative_to_the_bundle_root() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "reports/deep/thing.env",
            "SECRET=aB3xY7qL9mN2pR5tV8wZ\n",
        );

        let report = build(dir.path(), None).unwrap();
        let files: Vec<&str> = report.findings.iter().map(|f| f.file.as_str()).collect();
        assert!(
            files.iter().any(|file| file.contains("thing.env")),
            "expected a bundle-relative path, got {files:?}"
        );
        assert!(
            files
                .iter()
                .all(|file| !file.contains(dir.path().to_str().unwrap())),
            "paths must not leak the checking machine's layout: {files:?}"
        );
    }

    #[test]
    fn an_already_redacted_bundle_line_is_not_reported_as_a_secret() {
        // The marker exists because the secret was removed; reporting it says the
        // opposite of the truth about the one place there provably is no secret.
        // A labelled bundle spells them with a suffix; `verify` must read those as
        // redaction having worked, not as a leftover value.
        assert!(is_not_credential_shaped("API_KEY=<REDACTED:s1>"));
        assert!(is_not_credential_shaped("  token: <REDACTED_SECRET:s12>,"));
        assert!(is_not_credential_shaped("<REDACTED_SECRET_LINE>"));
        assert!(is_not_credential_shaped("- Secret redaction: <REDACTED>"));
        assert!(is_not_credential_shaped("API_KEY=<REDACTED>"));
        assert!(is_not_credential_shaped("  token: <REDACTED_SECRET>,"));
    }

    #[test]
    fn codepack_s_own_report_header_prose_is_not_reported_as_a_secret() {
        // Verbatim from `reports/02_git.txt`: codepack's own boilerplate trips its own
        // keyword cascade on the word `Secret` while holding no value whatsoever.
        assert!(is_not_credential_shaped(
            "Secret redaction is applied to command output."
        ));
    }

    #[test]
    fn a_bundle_line_where_redaction_failed_is_still_reported() {
        // The property that keeps the dismissal narrow: a raw value next to a marker
        // survives stripping, so the finding stands.
        assert!(!is_not_credential_shaped(
            "API_KEY=<REDACTED> BACKUP_KEY=zZ9xQ7vLwPmR3sT8uAbCdEfGhIj"
        ));
        assert!(!is_not_credential_shaped(
            "<REDACTED_SECRET_LINE> AKIAIOSFODNN7EXAMPLE"
        ));
    }

    #[test]
    fn a_bundle_line_carrying_a_raw_credential_is_never_dismissed() {
        assert!(!is_not_credential_shaped(
            "API_KEY=zZ9xQ7vLwPmR3sT8uAbCdEfGhIj"
        ));
        assert!(is_not_credential_shaped("nothing interesting here"));
    }

    #[test]
    fn a_leaked_secret_in_the_text_dump_still_counts_towards_the_verdict() {
        // The case the raw-line check must never dismiss: `03_text_dump.txt` is written
        // by codepack, but it carries the project's own bytes, so a redaction failure
        // there is a genuine leak and has to reach the verdict.
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "reports/03_text_dump.txt",
            "API_KEY=zZ9xQ7vLwPmR3sT8uAbCdEfGhIj\n",
        );

        let report = build(dir.path(), None).unwrap();
        assert!(
            !report.findings.is_empty(),
            "an unredacted secret in the text dump is a real leak"
        );
    }

    #[test]
    fn an_already_redacted_text_dump_does_not_count_towards_the_verdict() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "reports/03_text_dump.txt",
            "API_KEY=<REDACTED_SECRET_LINE>\n",
        );

        let report = build(dir.path(), None).unwrap();
        assert!(
            report.findings.is_empty(),
            "redaction having worked is not a finding, got {:?}",
            report.findings
        );
    }

    #[test]
    fn codepack_s_own_reports_are_classified_as_generated() {
        for path in [
            r".\reports\insights\06_security_scan.txt",
            "reports/insights/16_key_files_report.md",
            r".\manifest.json",
            "PROJECT_PROFILE.json",
            r".\INDEX.md",
            "reports/01_structure.txt",
        ] {
            assert!(
                is_generated_artifact(path),
                "{path} should not count towards the verdict"
            );
        }
    }

    #[test]
    fn the_text_dump_and_git_report_stay_content_because_project_bytes_land_there() {
        // The two files codepack writes that carry the source project's own content. A
        // redaction failure surfaces here, so classifying them as generated would blind
        // the check exactly where it matters.
        assert!(!is_generated_artifact(r".\reports\03_text_dump.txt"));
        assert!(!is_generated_artifact("reports/02_git.txt"));
    }

    #[test]
    fn exported_project_files_are_content_even_under_a_reports_like_name() {
        assert!(!is_generated_artifact(r".\demo\src\main.rs"));
        assert!(!is_generated_artifact(r".\demo\reports\insights\thing.rs"));
        assert!(!is_generated_artifact("some-project/manifest.json"));
    }

    #[test]
    fn a_finding_in_a_generated_report_does_not_drive_the_verdict() {
        let dir = tempfile::tempdir().unwrap();
        // Exactly the shape that made every clean bundle read as dirty: the scanner's
        // own placeholder text, sitting inside the scanner's own report.
        write(
            dir.path(),
            "reports/insights/06_security_scan.txt",
            "  [high] a.rs:1 (secret_like_line) — API_KEY=<REDACTED_SECRET_LINE>\n",
        );
        write(dir.path(), "demo/src/main.rs", "fn main() {}\n");

        let report = build(dir.path(), None).unwrap();

        assert!(
            report.findings.is_empty(),
            "verdict must come from exported content only, got {:?}",
            report.findings
        );
        assert_eq!(report.summary.total_findings, 0);
        assert!(
            !report.generated_findings.is_empty(),
            "but the finding must still be reported, not dropped"
        );
    }

    #[test]
    fn the_allowlist_suppresses_a_reviewed_finding_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "config.env",
            "API_KEY=zZ9xQ7vLwPmR3sT8uAbCdEfGhIj\n",
        );

        let before = build(dir.path(), None).unwrap();
        assert!(!before.findings.is_empty());
        let print = before.findings[0].fingerprint.clone();

        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join(codepack_core::ALLOWLIST_FILE_NAME),
            format!("[[allow]]\nfingerprint = \"{print}\"\nreason = \"sample bundle\"\n"),
        )
        .unwrap();

        let after = build(dir.path(), Some(project.path())).unwrap();
        assert_eq!(after.suppressed.len(), 1);
        assert_eq!(after.suppressed[0].reason, "sample bundle");
        assert!(after.findings.iter().all(|f| f.fingerprint != print));
        assert!(after.allowlist.is_some());
    }
}
