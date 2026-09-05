//! Pipeline step 5 ("text dump"): concatenates every text-like, size-eligible file
//! under the **copy** (`paths.project_dir`, never the source) into one file, ported
//! from legacy `reports/text_dump_report.py::write_text_dump`. Walks the
//! already-filtered copy with no further ignore-directory pruning of its own — the copy
//! step (pipeline step 2) already decided what survives into `project_dir`.
//!
//! ## The 6-encoding fallback chain — an honest, documented approximation
//!
//! Legacy tries `("utf-8", "utf-8-sig", "cp1251", "cp866", "utf-16", "latin-1")` in
//! order via Python's `bytes.decode(encoding)`, which can raise `UnicodeDecodeError` on
//! genuinely malformed input for `cp1251`/`cp866`/`utf-16`, falling through to the next
//! encoding. [`encoding_rs`]'s single-byte codecs (`WINDOWS_1251`, `IBM866`) and its
//! `UTF_16LE`/`UTF_16BE` are **total** functions per the WHATWG Encoding Standard — they
//! never fail, substituting `U+FFFD` for anything unmappable instead of raising. There
//! is therefore no way to get byte-for-byte identical fallback-chain behavior with
//! `encoding_rs` alone.
//!
//! The documented approximation implemented in [`decode_best_effort`]: use each
//! codec's `decode()` method, which returns `(Cow<str>, &Encoding, had_errors: bool)`,
//! and treat `had_errors == true` as "this encoding would have raised in Python",
//! falling through to the next one anyway even though `encoding_rs` already produced
//! *some* string for it. The final `latin-1` branch is total (matching legacy's own
//! final `errors="replace"` fallback, which also never fails) and always returns
//! `Some` in practice — so [`TextDumpStats::skipped_decode`] here can only increment on
//! a real `fs::metadata`/`fs::read`/sample-peek I/O error, never on a decoding failure,
//! matching legacy's own split between `"StatError"`/`"IOError"` (→ `skipped_decode`)
//! and an actual decode failure (which legacy's own final fallback also never truly
//! hits). This is a structurally unreachable-via-decoding counter by design, not an
//! oversight.
//!
//! ## Redaction: the plain function, deliberately not strengthened
//!
//! [`codepack_security::redact_secrets`] is used here on purpose — this **is** legacy
//! parity (legacy's own `text_dump_report.py` already calls the plain function),
//! unlike [`crate::git_report::write_git_report`]'s deliberate strengthening to the
//! keyword cascade (see that module's doc comment for the S7-derived reasoning). The
//! `DATABASE_URL` leak S7 review found and fixed was specific to `docker_report.py`'s
//! particular call site reusing the wrong function; text-dump content that is not
//! secret-shaped by the plain patterns still gets the sensitive-file/safety-mode
//! exclusion from pipeline step 2 as its primary defense — a structurally different
//! safety net than a report that quotes an entire repository's Git history. This
//! asymmetry between the two report steps is a deliberate, considered choice, not an
//! inconsistency.

use std::fs;
use std::io::{BufWriter, Read};
use std::path::{Path, PathBuf};

use codepack_core::{CancellationToken, TextDumpStats};
use codepack_scanner::{BINARY_SAMPLE_BYTES, looks_binary, should_consider_text_file};

use crate::error::{EngineError, Result};
use crate::layout::{file_banner_rule, section_rule};
use crate::timestamp::{human_from_system_time, human_now_utc};

/// Legacy `f"{size:,}"`: groups digits into runs of three, separated by `,`.
fn format_thousands(value: u64) -> String {
    let raw = value.to_string();
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len() + raw.len() / 3);
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 && (bytes.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(*byte as char);
    }
    out
}

/// See the module doc comment's "honest approximation" section.
fn decode_best_effort(raw: &[u8]) -> (String, &'static str) {
    if let Ok(text) = std::str::from_utf8(raw) {
        return (text.to_string(), "utf-8");
    }
    if let Some(stripped) = raw.strip_prefix(&[0xEF, 0xBB, 0xBF])
        && let Ok(text) = std::str::from_utf8(stripped)
    {
        return (text.to_string(), "utf-8-sig");
    }

    let (text, _, had_errors) = encoding_rs::WINDOWS_1251.decode(raw);
    if !had_errors {
        return (text.into_owned(), "cp1251");
    }
    let (text, _, had_errors) = encoding_rs::IBM866.decode(raw);
    if !had_errors {
        return (text.into_owned(), "cp866");
    }
    if raw.len().is_multiple_of(2) {
        let decoder = if raw.starts_with(&[0xFF, 0xFE]) {
            encoding_rs::UTF_16LE
        } else if raw.starts_with(&[0xFE, 0xFF]) {
            encoding_rs::UTF_16BE
        } else {
            encoding_rs::UTF_16LE
        };
        let (text, _, had_errors) = decoder.decode(raw);
        if !had_errors {
            return (text.into_owned(), "utf-16");
        }
    }

    let text: String = raw.iter().map(|&byte| byte as char).collect();
    (text, "latin-1(replace)")
}

/// Same backslash-joined display convention as [`crate::structure`]'s `rel_display`
/// (duplicated rather than shared: both are tiny, module-local formatting helpers over
/// different walk contexts — the same duplication-over-coupling tradeoff already
/// documented in `crate::timestamp`'s own module doc comment).
fn rel_display(path: &Path, root: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    let joined = rel
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("\\");
    format!(".\\{joined}")
}

/// Legacy `root.rglob("*")` filtered to files, sorted by lowercased relative path. No
/// ignore-directory pruning here on purpose — see the module doc comment.
fn collect_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(read_dir) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in read_dir.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                files.push(path);
            }
        }
    }
    files.sort_by_key(|path| {
        path.strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .to_lowercase()
    });
    files
}

/// Reads only the first [`BINARY_SAMPLE_BYTES`] bytes — the same bound
/// `codepack_security::scan_project` reads a size cap against, avoiding a full read of
/// a large binary file just to classify it.
fn peek_sample(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut file = fs::File::open(path)?;
    let mut buffer = vec![0u8; BINARY_SAMPLE_BYTES];
    let read = file.read(&mut buffer)?;
    buffer.truncate(read);
    Ok(buffer)
}

fn prepend_developer_context(output_file: &Path, context: &str, log: &dyn Fn(&str)) {
    let rule = "═".repeat(54);
    let header = format!(
        "# {rule}\n# ЗАДАЧА / КОНТЕКСТ РАЗРАБОТЧИКА\n# {rule}\n\n{context}\n\n# {rule}\n\n"
    );
    match fs::read(output_file) {
        Ok(existing) => {
            let mut combined = header.into_bytes();
            combined.extend_from_slice(&existing);
            if let Err(err) = fs::write(output_file, combined) {
                log(&format!(
                    "text dump: could not prepend developer context: {err}"
                ));
            }
        }
        Err(err) => log(&format!(
            "text dump: could not prepend developer context: {err}"
        )),
    }
}

/// What the text-dump step produced. `stats` is the legacy-shaped structure that goes
/// into `manifest.json`; `redacted_substitutions` is deliberately kept *outside* it so the
/// artifact's own shape is unchanged (invariant I5) while the export-history row can
/// still record a real number instead of `NULL`.
pub struct TextDumpOutcome {
    pub stats: TextDumpStats,
    /// How many lines this step rewrote because they matched a redaction keyword.
    /// Counted from the `<REDACTED>` markers the redaction actually produced, so it
    /// reflects work done rather than secrets detected — a line with two redacted
    /// values counts twice, which is the honest reading of "how much was redacted".
    pub redacted_substitutions: u32,
}

/// Counts redaction markers, which is how many substitutions the redaction made.
///
/// Both spellings, because a labelled run writes `<REDACTED:s1>` where a plain one
/// writes `<REDACTED>` — counting only the plain marker would report zero
/// substitutions for a bundle full of them. `<REDACTED_SECRET>` stays uncounted, as it
/// always has been: this figure is the one the history has recorded since S5 and
/// widening it would silently change what a stored number means.
fn count_redaction_markers(text: &str) -> u32 {
    let plain = text.matches("<REDACTED>").count();
    let labelled = text.matches("<REDACTED:").count();
    u32::try_from(plain + labelled).unwrap_or(u32::MAX)
}

/// The largest file this step will read whole, whatever the configuration says.
///
/// `Config::text_file_size_limit_enabled` is `false` by default, so the user-facing limit
/// is usually absent altogether. This one is not a preference: past this size a single
/// file costs more memory than any dump entry is worth, and the file is far more likely
/// to be a database or a build artifact that slipped past the text filters than something
/// a reader wants quoted.
const ABSOLUTE_MAX_TEXT_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Appends to the dump, naming the file in any error.
///
/// Every write goes through here so the `EngineError::Io` path is written once rather
/// than at each of the dozen call sites.
fn write_text(out: &mut BufWriter<fs::File>, output_file: &Path, text: &str) -> Result<()> {
    std::io::Write::write_all(out, text.as_bytes()).map_err(|source| EngineError::Io {
        path: output_file.to_path_buf(),
        source,
    })
}

/// Runs pipeline step 5. `max_bytes_per_file` mirrors
/// `config.effective_max_text_file_bytes()`; `redactor` is `Some` exactly when
/// `config.redact_secrets` is set, and carries the run's placeholder policy;
/// `developer_context` mirrors `config.developer_context.trim()` — pass an empty string
/// to skip the header-prepend step entirely.
pub fn write_text_dump(
    root: &Path,
    output_file: &Path,
    max_bytes_per_file: Option<u64>,
    redactor: Option<&codepack_security::Redactor>,
    developer_context: &str,
    log: &dyn Fn(&str),
    cancel: &CancellationToken,
) -> Result<TextDumpOutcome> {
    let mut stats = TextDumpStats::default();
    let mut redacted_substitutions = 0u32;

    // The walk happens before the output file exists. Streaming the dump means the file
    // is created up front, and `output_file` normally sits inside the tree being walked —
    // so listing afterwards would have the dump include itself. Collecting first keeps
    // exactly the set of files the accumulating version saw.
    let files = collect_files(root);

    // Written as the walk goes rather than accumulated. The dump used to be built in one
    // `String` and written once at the end, so peak memory was "every text file in the
    // project, decoded, plus the largest file three times over" — against the project's
    // own rule that memory must not grow with file size, and on the desktop a crash in
    // the middle of a long operation (audit No. 15).
    //
    // Nothing in the header depends on the body, so the order the file is written in is
    // the order it is produced. `prepend_developer_context` still rewrites the file
    // afterwards, unchanged.
    let handle = fs::File::create(output_file).map_err(|source| EngineError::Io {
        path: output_file.to_path_buf(),
        source,
    })?;
    let mut out = BufWriter::new(handle);

    let root_name = root
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();

    write_text(&mut out, output_file, "=== Text Files Dump ===\n")?;
    write_text(
        &mut out,
        output_file,
        &format!("Project copy root name: {root_name}\n"),
    )?;
    write_text(
        &mut out,
        output_file,
        &format!("Generated: {}\n", human_now_utc()),
    )?;
    write_text(
        &mut out,
        output_file,
        &format!(
            "Max bytes per file: {}\n",
            max_bytes_per_file
                .map(format_thousands)
                .unwrap_or_else(|| "unlimited".to_string())
        ),
    )?;
    write_text(
        &mut out,
        output_file,
        &format!(
            "Secrets redaction: {}\n",
            match redactor {
                // Said out loud so a reader meeting `<REDACTED:s1>` for the first time
                // knows it is a label for one particular secret, not part of the value.
                Some(redactor) if redactor.is_labelled() =>
                    "enabled, with a stable label per distinct secret (<REDACTED:sN>)",
                Some(_) => "enabled",
                None => "disabled",
            }
        ),
    )?;
    write_text(
        &mut out,
        output_file,
        "Only readable text-like files are included.\n",
    )?;
    write_text(&mut out, output_file, &section_rule('='))?;
    write_text(&mut out, output_file, "\n\n")?;

    for path in files {
        if cancel.is_cancelled() {
            break;
        }
        stats.scanned += 1;

        if !should_consider_text_file(&path) {
            stats.skipped_not_text += 1;
            continue;
        }

        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => {
                stats.skipped_decode += 1;
                continue;
            }
        };

        // The user's own ceiling, which is off by default.
        if let Some(max) = max_bytes_per_file
            && metadata.len() > max
        {
            stats.skipped_large += 1;
            continue;
        }
        // And a ceiling no configuration can switch off. `text_file_size_limit_enabled`
        // defaults to `false`, so without this a single enormous file is read whole,
        // decoded, redacted and held in memory several times over. Counted as
        // `skipped_large` — which is what it is — rather than as a new statistic, because
        // `TextDumpStats` is part of `manifest.json` and I5 makes that a contract.
        if metadata.len() > ABSOLUTE_MAX_TEXT_FILE_BYTES {
            stats.skipped_large += 1;
            log(&format!(
                "text dump: {} skipped — {} bytes is past the {} byte ceiling that applies \
                 regardless of settings",
                rel_display(&path, root),
                format_thousands(metadata.len()),
                format_thousands(ABSOLUTE_MAX_TEXT_FILE_BYTES)
            ));
            continue;
        }

        let sample = match peek_sample(&path) {
            Ok(sample) => sample,
            Err(_) => {
                stats.skipped_decode += 1;
                continue;
            }
        };
        if looks_binary(&sample) {
            stats.skipped_binary += 1;
            continue;
        }

        let raw = match fs::read(&path) {
            Ok(raw) => raw,
            Err(_) => {
                stats.skipped_decode += 1;
                continue;
            }
        };

        let (text, encoding) = decode_best_effort(&raw);
        let text = match redactor {
            Some(redactor) => {
                let redacted = redactor.redact_secrets(&text);
                redacted_substitutions += count_redaction_markers(&redacted);
                redacted
            }
            None => text,
        };
        let modified = metadata
            .modified()
            .map(human_from_system_time)
            .unwrap_or_default();
        let display = rel_display(&path, root);

        let banner = file_banner_rule();
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        write_text(
            &mut out,
            output_file,
            &format!(
                "\n{banner}\nFile: {display}\nName: {name}\nSize: {} bytes\nModified: \
                 {modified}\nEncoding: {encoding}\n{banner}\n\n",
                format_thousands(metadata.len())
            ),
        )?;
        write_text(&mut out, output_file, &text)?;
        if !text.ends_with('\n') {
            write_text(&mut out, output_file, "\n")?;
        }

        stats.written += 1;
        log(&format!("text dump: {display}"));
    }

    // Explicitly, rather than on drop: a `BufWriter` that fails to flush while being
    // dropped has nowhere to report it, and a silently truncated dump would look like a
    // complete one.
    std::io::Write::flush(&mut out).map_err(|source| EngineError::Io {
        path: output_file.to_path_buf(),
        source,
    })?;
    drop(out);

    let trimmed_context = developer_context.trim();
    if !trimmed_context.is_empty() {
        prepend_developer_context(output_file, trimmed_context, log);
    }

    Ok(TextDumpOutcome {
        stats,
        redacted_substitutions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_log(_: &str) {}

    /// The dump is written as the walk goes, so a file created while walking must not
    /// end up quoting itself. The output normally sits inside the tree being dumped.
    #[test]
    fn the_dump_does_not_include_itself() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("a.py"),
            "print('hello')
",
        )
        .unwrap();
        let output = dir.path().join("dump.txt");

        let outcome = write_text_dump(
            dir.path(),
            &output,
            None,
            Some(&codepack_security::Redactor::plain()),
            "",
            &no_log,
            &CancellationToken::new(),
        )
        .unwrap();

        assert_eq!(outcome.stats.written, 1);
        let body = fs::read_to_string(&output).unwrap();
        assert!(!body.contains("File: dump.txt"), "{body}");
    }

    /// The dump is streamed, so what lands on disk has to be flushed rather than left in
    /// a buffer — a truncated dump would look like a complete one.
    #[test]
    fn a_dump_larger_than_one_buffer_is_written_whole() {
        let dir = tempfile::tempdir().unwrap();
        // Comfortably past BufWriter's default 8 KiB.
        let body = "x = 1  # padding
"
        .repeat(4000);
        fs::write(dir.path().join("big.py"), &body).unwrap();
        let output = dir.path().join("dump.txt");

        write_text_dump(
            dir.path(),
            &output,
            None,
            None,
            "",
            &no_log,
            &CancellationToken::new(),
        )
        .unwrap();

        let written = fs::read_to_string(&output).unwrap();
        assert!(written.len() > body.len(), "{}", written.len());
        assert!(
            written.ends_with(
                "x = 1  # padding
"
            ),
            "the tail must be there"
        );
    }

    #[test]
    fn a_binary_file_is_skipped_and_counted() {
        // A `.txt` extension is text-eligible per `should_consider_text_file`, so this
        // exercises the content-sniffing `looks_binary` branch specifically, not the
        // (separate) extension-based `skipped_not_text` branch a `.bin` file would hit.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("data.txt"), [0u8, 1, 2, 3, 0, 0]).unwrap();
        let output = dir.path().join("dump.txt");

        let stats = write_text_dump(
            dir.path(),
            &output,
            None,
            Some(&codepack_security::Redactor::plain()),
            "",
            &no_log,
            &CancellationToken::new(),
        )
        .unwrap()
        .stats;

        assert_eq!(stats.skipped_binary, 1);
        assert_eq!(stats.written, 0);
    }

    #[test]
    fn an_oversized_file_is_skipped_and_counted() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("big.py"), "x".repeat(100)).unwrap();
        let output = dir.path().join("dump.txt");

        let stats = write_text_dump(
            dir.path(),
            &output,
            Some(10),
            Some(&codepack_security::Redactor::plain()),
            "",
            &no_log,
            &CancellationToken::new(),
        )
        .unwrap()
        .stats;

        assert_eq!(stats.skipped_large, 1);
        assert_eq!(stats.written, 0);
    }

    #[test]
    fn a_plain_utf8_file_round_trips_with_utf8_encoding_label() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("main.py"), "print('hello')\n").unwrap();
        let output = dir.path().join("dump.txt");

        let stats = write_text_dump(
            dir.path(),
            &output,
            None,
            Some(&codepack_security::Redactor::plain()),
            "",
            &no_log,
            &CancellationToken::new(),
        )
        .unwrap()
        .stats;

        assert_eq!(stats.written, 1);
        let content = fs::read_to_string(&output).unwrap();
        assert!(content.contains("Encoding: utf-8\n"));
        assert!(content.contains("print('hello')"));
    }

    #[test]
    fn a_windows_1251_file_decodes_with_cp1251_encoding_label() {
        let dir = tempfile::tempdir().unwrap();
        let (encoded, _, had_errors) = encoding_rs::WINDOWS_1251.encode("привет мир");
        assert!(!had_errors);
        fs::write(dir.path().join("ru.txt"), &encoded).unwrap();
        let output = dir.path().join("dump.txt");

        let stats = write_text_dump(
            dir.path(),
            &output,
            None,
            Some(&codepack_security::Redactor::plain()),
            "",
            &no_log,
            &CancellationToken::new(),
        )
        .unwrap()
        .stats;

        assert_eq!(stats.written, 1);
        let content = fs::read_to_string(&output).unwrap();
        assert!(content.contains("Encoding: cp1251\n"));
        assert!(content.contains("привет мир"));
    }

    #[test]
    fn redaction_removes_a_secret_value_from_the_dump_body() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("config.py"),
            "API_KEY=super-secret-value-123\n",
        )
        .unwrap();
        let output = dir.path().join("dump.txt");

        let _ = write_text_dump(
            dir.path(),
            &output,
            None,
            Some(&codepack_security::Redactor::plain()),
            "",
            &no_log,
            &CancellationToken::new(),
        )
        .unwrap()
        .stats;

        let content = fs::read_to_string(&output).unwrap();
        assert!(!content.contains("super-secret-value-123"));
    }

    #[test]
    fn developer_context_header_is_prepended_when_set() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("main.py"), "x = 1\n").unwrap();
        let output = dir.path().join("dump.txt");

        let _ = write_text_dump(
            dir.path(),
            &output,
            None,
            Some(&codepack_security::Redactor::plain()),
            "  fix the login bug  ",
            &no_log,
            &CancellationToken::new(),
        )
        .unwrap()
        .stats;

        let content = fs::read_to_string(&output).unwrap();
        assert!(content.starts_with("# ═"));
        assert!(content.contains("fix the login bug"));
    }

    #[test]
    fn developer_context_header_is_absent_when_empty() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("main.py"), "x = 1\n").unwrap();
        let output = dir.path().join("dump.txt");

        let _ = write_text_dump(
            dir.path(),
            &output,
            None,
            Some(&codepack_security::Redactor::plain()),
            "   ",
            &no_log,
            &CancellationToken::new(),
        )
        .unwrap()
        .stats;

        let content = fs::read_to_string(&output).unwrap();
        assert!(content.starts_with("=== Text Files Dump ==="));
    }

    #[test]
    fn cancellation_mid_loop_yields_an_honestly_partial_result() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..10 {
            fs::write(dir.path().join(format!("file{i:02}.py")), "x").unwrap();
        }
        let output = dir.path().join("dump.txt");
        let cancel = CancellationToken::new();
        cancel.cancel();

        let stats = write_text_dump(
            dir.path(),
            &output,
            None,
            Some(&codepack_security::Redactor::plain()),
            "",
            &no_log,
            &cancel,
        )
        .unwrap()
        .stats;

        assert_eq!(stats.scanned, 0);
        assert_eq!(stats.written, 0);
    }

    #[test]
    fn format_thousands_groups_digits() {
        assert_eq!(format_thousands(0), "0");
        assert_eq!(format_thousands(1234), "1,234");
        assert_eq!(format_thousands(1_234_567), "1,234,567");
    }
}
