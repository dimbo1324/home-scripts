//! What a scan leaves out, and on whose authority.
//!
//! Two files answer two different questions and are deliberately kept apart:
//! `.codepack-allow` means "we read this and accepted it, here is why"; a baseline means
//! "this was already here when we started counting". Both narrow what gets reported, so
//! the order they run in is a decision rather than an accident — see [`screen_all`].

use codepack_security::ScanResult;

use crate::cli::ScanArgs;
use crate::error::Result;
use crate::output;

/// The two baseline paths a caller may supply. Threaded as one value so every entry
/// point takes the same shape, and so a caller that has no baseline says so once.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct BaselineOptions<'a> {
    /// Findings listed here are not reported: they were already present.
    pub read: Option<&'a std::path::Path>,
    /// Where to record the findings that survived the allowlist.
    pub write: Option<&'a std::path::Path>,
}

impl<'a> BaselineOptions<'a> {
    pub(crate) fn from_args(args: &'a ScanArgs) -> Self {
        Self {
            read: args.baseline.as_deref(),
            write: args.write_baseline.as_deref(),
        }
    }
}

/// What a baseline held back on this run.
pub(super) struct BaselineScreen {
    pub(super) path: std::path::PathBuf,
    pub(super) suppressed: Vec<crate::allow::SuppressedFinding>,
}

pub(super) fn screen_with_allowlist(
    project_root: &std::path::Path,
    result: &ScanResult,
) -> Result<crate::allow::Screened> {
    Ok(match crate::allow::load(project_root)? {
        Some((path, index)) => crate::allow::screen(result, &path, &index),
        None => crate::allow::Screened::unfiltered(result),
    })
}

/// The allowlist first, then `--write-baseline`, then `--baseline`, in that order.
///
/// Order matters and is not arbitrary. The allowlist runs first because an accepted
/// finding is accepted, full stop — recording it in a baseline as well would be noise.
/// A baseline is then *written* from what survives, which is exactly the set a team
/// wants frozen. And `--baseline` filters last, so what is reported is what is genuinely
/// new.
pub(super) fn screen_all(
    project_root: &std::path::Path,
    baseline_options: BaselineOptions<'_>,
    result: &ScanResult,
) -> Result<(crate::allow::Screened, Option<BaselineScreen>)> {
    let screened = screen_with_allowlist(project_root, result)?;

    if let Some(path) = baseline_options.write {
        let written = crate::baseline::write(path, project_root, &screened.to_result())?;
        output::note(format!(
            "baseline written to {} ({written} finding(s))",
            path.display()
        ));
    }

    let Some(path) = baseline_options.read else {
        return Ok((screened, None));
    };
    let index = crate::baseline::load(path)?;
    let after = crate::allow::screen(&screened.to_result(), path, &index);
    Ok((
        crate::allow::Screened {
            findings: after.findings,
            suppressed: screened.suppressed,
            allowlist_path: screened.allowlist_path,
        },
        Some(BaselineScreen {
            path: path.to_path_buf(),
            suppressed: after.suppressed,
        }),
    ))
}
