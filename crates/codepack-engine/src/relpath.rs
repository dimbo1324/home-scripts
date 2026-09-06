//! Shared helper: turns a backslash-joined `PlannedFile.relative_path` (this project's
//! join convention, the same on every OS — see `codepack_scanner::plan`) into real path
//! components. Never `Path::new(rel_str)` directly: on Linux/macOS a backslash is an
//! ordinary filename character, not a separator, which would silently corrupt every
//! nested path.
//!
//! Shared by [`crate::copy`] (pipeline step 2, copying planned files onto disk) and
//! [`crate::analytics`] (pipeline step 6, turning the re-plan's planned files back into
//! a `Vec<PathBuf>` for `codepack_security::scan_project`) — both call sites must never
//! silently diverge on this conversion.

use std::path::PathBuf;

/// The rule itself is [`codepack_core::relative_from_stored`], which validates as well as
/// rebuilds. This wrapper keeps the infallible signature the pipeline's call sites are
/// written against.
///
/// A path that fails validation resolves to the empty path, which every caller then joins
/// onto a root — so a hostile `..\..\x` names the root itself rather than escaping it,
/// and the file is skipped as unreadable a moment later. Refusing the whole export for one
/// malformed entry would be a worse answer for a plan this crate produced itself; the
/// check is here because a plan can also arrive from a stored snapshot.
pub(crate) fn to_relative_path(relative_path: &str) -> PathBuf {
    codepack_core::relative_from_stored(relative_path).unwrap_or_default()
}
