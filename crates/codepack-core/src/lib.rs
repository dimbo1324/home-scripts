pub mod allowlist;
mod cancellation;
pub mod classify;
mod error;
pub mod file_groups;
mod paths;
mod progress;
pub mod time;
mod types;

pub mod config;
pub mod profiles;

pub use allowlist::{ALLOWLIST_FILE_NAME, AllowEntry, Allowlist, AllowlistError};
pub use cancellation::CancellationToken;
pub use classify::{
    BINARY_EXTENSIONS, BINARY_SAMPLE_BYTES, TEXT_EXTENSIONS, TEXT_FILENAMES_WITHOUT_EXTENSION,
    looks_binary, should_consider_text_file,
};
pub use error::{CoreError, Result};
pub use paths::{
    AppPaths, DestinationError, UnsafeRelativePath, canonicalize_existing, resolve_prospective,
    safe_join, validate_destination_outside,
};
pub use progress::{
    LogEvent, LogLevel, ProgressEvent, ProgressReceiver, ProgressSender, progress_channel,
};
pub use types::{
    ArchiveBuildResult, CopyStats, ExportPaths, RiskPreviewItem, RiskPreviewReport, TextDumpStats,
};
