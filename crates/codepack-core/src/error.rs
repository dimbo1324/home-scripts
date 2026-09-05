//! Crate-wide error type and `Result` alias.

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("cannot write {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("cannot determine an application directory for the current platform")]
    NoAppDirectories,

    /// Built by [`CoreError::invalid_json`], which is the only way to make one.
    ///
    /// The position and the class of the problem, never `serde_json::Error`'s own
    /// `Display` — that text embeds the offending value: `invalid type: string
    /// "sk-live-…", expected a boolean at line 3 column 20`. These errors come from
    /// parsing the user's own settings and profile files, and the message reaches stderr
    /// and, in CI, a build log. The same conclusion `CliError::ProjectConfigSyntax`
    /// already reached for TOML; it had not been drawn for JSON (audit No. 11).
    ///
    /// Redacting the text instead would be the weaker fix: the redactor keys on its own
    /// keyword list, and an arbitrary field name in an arbitrary file need not be on it.
    /// A position says everything the user needs to find the line themselves.
    #[error("{field} must be valid JSON: {kind} at line {line} column {column}")]
    InvalidJson {
        field: &'static str,
        kind: &'static str,
        line: usize,
        column: usize,
    },
}

impl CoreError {
    /// The only constructor for [`CoreError::InvalidJson`]: takes the parse error apart
    /// here so no call site is in a position to keep its text.
    pub fn invalid_json(field: &'static str, source: &serde_json::Error) -> Self {
        let kind = match source.classify() {
            serde_json::error::Category::Io => "an I/O failure",
            serde_json::error::Category::Syntax => "a syntax error",
            serde_json::error::Category::Data => "a value of the wrong type",
            serde_json::error::Category::Eof => "an unexpected end of input",
        };
        Self::InvalidJson {
            field,
            kind,
            line: source.line(),
            column: source.column(),
        }
    }
}

pub type Result<T> = std::result::Result<T, CoreError>;
