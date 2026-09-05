//! Crate-wide error type and `Result` alias.

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
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

    #[error("cannot walk {path}: {source}")]
    Walk {
        path: PathBuf,
        #[source]
        source: walkdir::Error,
    },

    #[error("zip error for {path}: {source}")]
    Zip {
        path: PathBuf,
        #[source]
        source: zip::result::ZipError,
    },

    #[error("cannot serialize archive report: {0}")]
    Serialize(#[from] serde_json::Error),

    #[error("7z error for {path}: {source}")]
    SevenZip {
        path: PathBuf,
        #[source]
        source: sevenz_rust2::Error,
    },

    /// A format that is listed as a choice but has no implementation — today only
    /// `rar`. Refused before anything is written, and the message names what the user
    /// *can* pick, because "unsupported" without an alternative is a dead end.
    #[error(
        "the {format} format is not implemented yet — it is reserved for a future release. Choose zip (the default) or 7z."
    )]
    FormatNotImplemented { format: &'static str },

    #[error("unsafe archive member path: {member}")]
    UnsafeMemberPath { member: String },

    /// The archive expands past what a caller allowed. A distinct variant, and one that
    /// names the ceiling: a refusal a user cannot act on is barely better than the
    /// failure it prevented.
    #[error(
        "{archive} expands past the {limit} limit of {allowed}; extraction stopped. \
         A bundle this large is either not a codepack bundle or is deliberately \
         oversized."
    )]
    ExtractionTooLarge {
        archive: PathBuf,
        limit: &'static str,
        allowed: String,
    },

    /// The caller cancelled mid-archive. A distinct variant rather than a generic
    /// failure because the caller must be able to tell "you stopped this" from
    /// "something broke", and report it as neither an error nor a success.
    #[error("archiving was cancelled")]
    Cancelled,
}

pub type Result<T> = std::result::Result<T, ArchiveError>;
