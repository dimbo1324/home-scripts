//! Crate-wide error type and `Result` alias.

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error(transparent)]
    Scanner(#[from] codepack_scanner::ScannerError),

    #[error(transparent)]
    Diff(#[from] codepack_diff::DiffError),

    #[error(transparent)]
    Security(#[from] codepack_security::SecurityError),

    #[error(transparent)]
    Report(#[from] codepack_reports::ReportError),

    #[error(transparent)]
    Storage(#[from] codepack_storage::StorageError),

    #[error(transparent)]
    Archive(#[from] codepack_archive::ArchiveError),

    #[error(transparent)]
    Allowlist(#[from] codepack_core::AllowlistError),

    /// A question about one file that cannot be answered as asked — a path outside the
    /// project, or one that cannot be resolved.
    #[error("{0}")]
    Explain(String),

    /// Invariant I2, refused at the layer both shells go through.
    ///
    /// The CLI checks this too, earlier and with a friendlier message, but that check is
    /// no longer the only one: the desktop shell called `run_export` without it, so the
    /// invariant was held by one of the two front ends rather than by the engine that
    /// defines it.
    #[error(
        "refusing to write the bundle into {output_root}: it is inside {source_root}, the \
         project being exported, and an export never writes into the source folder"
    )]
    OutputInsideSource {
        source_root: PathBuf,
        output_root: PathBuf,
    },

    #[error("cannot create directory {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

pub type Result<T> = std::result::Result<T, EngineError>;

/// `true` when `err` is one of the lower-layer crates' own "the token was already
/// cancelled when I was called" hard error (`ScannerError::Cancelled`/
/// `DiffError::Cancelled`/`SecurityError::Cancelled` — S2/S4/S3, already shipped and
/// reviewed with a fail-fast, not cooperative-partial, cancellation contract).
///
/// [`crate::orchestrator::run_export`] calls into these crates from inside its own
/// steps 1 and 6; a cancellation that arrives in the narrow window between an outer
/// `cancel.is_cancelled()` gate check and one of these calls' own internal recheck
/// would otherwise surface as a hard `Err`, breaking this pipeline's own "steps 7-8
/// (and history recording) always run" guarantee. `run_export` matches on this
/// predicate at both call sites to fall back to an honestly-empty step result instead
/// — found and fixed during this pass's own cancellation-battery testing (a real,
/// reachable race, not a purely theoretical one: it failed two of that suite's own
/// scenarios on an ordinary run before this fix).
pub(crate) fn is_cancellation_error(err: &EngineError) -> bool {
    matches!(
        err,
        EngineError::Scanner(codepack_scanner::ScannerError::Cancelled)
            | EngineError::Diff(codepack_diff::DiffError::Cancelled)
            | EngineError::Security(codepack_security::SecurityError::Cancelled)
    )
}
