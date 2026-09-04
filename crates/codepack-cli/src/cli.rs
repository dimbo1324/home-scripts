//! The command surface, exactly as `docs/__arch__/ROADMAP.md` §3 specifies it for stage S10:
//! `export`, `preview`, `scan`, `history`, `doctor`, with `--preset`, `--profile`,
//! `--safe-mode`, `--diff`, `--budget`, `--out` and `--json`.
//!
//! `--json` is declared once, globally, rather than repeated per command: it changes
//! how output is rendered, not what a command does, and a user should not have to
//! remember which subcommands support it.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "codepack",
    version,
    about = "Turn a source folder into a clean, safe snapshot.",
    long_about = "Turn a source folder into a clean, safe snapshot: an archive plus \
                  reports fit to hand to an AI assistant and to a human.\n\n\
                  Analysis is entirely local; nothing is ever sent anywhere.\n\n\
                  Exit codes: 0 success, 1 error, 2 bad arguments, 3 critical secrets found."
)]
pub(crate) struct Cli {
    /// Emit machine-readable JSON on stdout instead of a human report.
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Run the full export pipeline and write a bundle.
    Export(ExportArgs),
    /// Report what an export would include, without writing anything.
    Preview(PreviewArgs),
    /// Scan a project for secrets and risky code.
    Scan(ScanArgs),
    /// List previous export runs.
    History(HistoryArgs),
    /// Check the environment and report what is available.
    Doctor,
    /// Strip comments (tree-sitter) and reformat with a `PATH` tool into a separate
    /// destination folder. A standalone action, not part of `export`'s pipeline.
    Sanitize(SanitizeArgs),
    /// Print a shell completion script to stdout.
    Completions(CompletionsArgs),
    /// Re-scan an already-produced bundle and report what is actually inside it.
    Verify(VerifyArgs),
    /// Explain why one file would, or would not, end up in the export.
    Explain(ExplainArgs),
    /// Prepare an already-exported bundle for a coding agent running on this machine.
    Handoff(HandoffArgs),
    /// Set this project up to use codepack: install the pre-commit hook.
    Init(InitArgs),
    /// Serve the Model Context Protocol over stdin/stdout, so a coding agent can ask
    /// these questions itself. Speaks JSON-RPC on stdout; nothing else may go there.
    Mcp,
}

#[derive(Debug, Args)]
pub(crate) struct HandoffArgs {
    /// The bundle to hand over: a `.zip`, an archive-set directory, or an extracted
    /// folder. Which one it is gets decided by looking at it, not by a flag.
    pub bundle: PathBuf,

    /// Which agent the handoff file is addressed to.
    #[arg(long, value_name = "ID")]
    pub agent: Option<String>,

    /// What the agent should do with the project. Falls back to the stored question,
    /// then to a general-purpose one.
    #[arg(long, value_name = "TEXT")]
    pub question: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct InitArgs {
    /// Install the pre-commit hook that runs `codepack scan --staged`.
    ///
    /// Required rather than implied: `init` will grow other setup steps, and a command
    /// that silently writes into `.git/` because it was run bare is a command people
    /// stop trusting.
    #[arg(long)]
    pub hook: bool,

    /// Refuse a commit the hook cannot check, instead of warning and allowing it.
    ///
    /// Without this, a colleague who has never installed codepack still commits; the
    /// hook says loudly that nothing was checked. With it, that commit is refused. Which
    /// is right depends on whether everyone who commits here is expected to have the
    /// tool, and only the person installing the hook can say.
    #[arg(long)]
    pub strict: bool,

    /// Replace an existing hook that codepack did not write.
    #[arg(long)]
    pub force: bool,

    #[command(flatten)]
    pub project: ProjectArgs,
}

#[derive(Debug, Args)]
pub(crate) struct ExplainArgs {
    /// The file to explain. Absolute, relative to the project, or spelled the way the
    /// export plan stores it — all three name the same file.
    pub file: PathBuf,

    #[command(flatten)]
    pub project: ProjectArgs,
}

#[derive(Debug, Args)]
pub(crate) struct VerifyArgs {
    /// The bundle to check: a `.zip`, an archive-set directory, or an extracted folder.
    /// Which one it is gets decided by looking at it, not by a flag.
    pub bundle: PathBuf,

    /// Project whose `.codepack-allow` should be honoured while checking.
    ///
    /// Not inferred from the bundle: the bundle came from somewhere else, and letting a
    /// received archive carry its own suppression list would let a sender decide what
    /// the recipient is allowed to be told.
    #[arg(long, value_name = "DIR")]
    pub allowlist_root: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct CompletionsArgs {
    /// Which shell to generate a completion script for.
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

/// Settings shared by the commands that read a project.
#[derive(Debug, Args)]
pub(crate) struct ProjectArgs {
    /// Project directory. Defaults to the current directory.
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// AI preset to apply (see `codepack doctor` for the list).
    #[arg(long)]
    pub preset: Option<String>,

    /// Export profile: one of the five built in, or one of your own from
    /// `~/.project_exporter_profiles.json`.
    #[arg(long)]
    pub profile: Option<String>,

    /// How aggressively to exclude sensitive files.
    #[arg(long, value_enum)]
    pub safe_mode: Option<SafeMode>,

    /// Which files to consider: everything, or only what changed.
    #[arg(long, value_enum)]
    pub diff: Option<DiffMode>,

    /// Token budget; drops the least valuable files to fit. Accepts `200000`, `200k`,
    /// `1M`, or a model name such as `Claude`. An unknown name lists the models that
    /// are available, so there is nothing to look up first.
    #[arg(long, value_parser = crate::settings::parse_budget)]
    pub budget: Option<crate::settings::BudgetSpec>,

    /// Container the bundle is written as. `zip` is the default and what every earlier
    /// release produced; `rar` is reserved and not implemented yet.
    ///
    /// Shared with the other project commands rather than being `export`-only so
    /// `preview` can report which container an export would produce — the same
    /// reasoning that puts `--budget` here.
    #[arg(long, value_enum)]
    pub archive_format: Option<ArchiveFormat>,
}

#[derive(Debug, Args)]
pub(crate) struct ExportArgs {
    #[command(flatten)]
    pub project: ProjectArgs,

    /// Directory to write the bundle into. Defaults to the current directory.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct PreviewArgs {
    #[command(flatten)]
    pub project: ProjectArgs,

    /// Also list the files that would be included.
    #[arg(long)]
    pub list_files: bool,
}

#[derive(Debug, Args)]
pub(crate) struct ScanArgs {
    #[command(flatten)]
    pub project: ProjectArgs,

    /// Scan only what is staged in git, reading the staged content itself.
    ///
    /// This is the pre-commit-hook mode: it answers "what is about to be committed",
    /// which is not the same question as "what is in my working tree" once a staged
    /// file has been edited again.
    #[arg(long)]
    pub staged: bool,

    /// Scan the project's git history instead of its working tree.
    ///
    /// Deleting a credential from a file does not remove it from the commits that
    /// carried it, and those travel with every clone. This is the mode that answers
    /// "was a secret ever committed", which is the question rotation depends on.
    #[arg(long, conflicts_with = "staged")]
    pub history: bool,

    /// With `--history`: exclude everything reachable from this ref, leaving "what has
    /// been added since". Typically a base branch, in CI.
    #[arg(long, value_name = "REF", requires = "history")]
    pub since: Option<String>,

    /// With `--history`: how many commits to walk, newest first. `0` walks all of them.
    #[arg(long, value_name = "N", requires = "history")]
    pub max_commits: Option<usize>,

    /// Also write the findings as SARIF 2.1.0 to this file.
    ///
    /// The same writer the export pipeline uses, so a scan and an export describe a
    /// finding identically. This is what makes `scan` usable in a code-scanning
    /// pipeline that consumes SARIF.
    #[arg(long, value_name = "FILE")]
    pub sarif: Option<PathBuf>,

    /// Lowest severity that should make this command exit with code 3.
    ///
    /// Defaults to `critical`, which is exactly the published contract; raising it is
    /// opt-in. A staged `.env` is `critical` and always gated, while
    /// `export API_KEY=…` in a shell script is `high` and is not — same secret,
    /// different rule, and only the person running the gate can say whether that should
    /// stop a commit.
    #[arg(long, value_name = "SEVERITY", default_value = "critical")]
    pub fail_on: SeverityArg,
}

/// Severity levels the scanner assigns, ordered from most to least severe.
///
/// An enum rather than a string so a typo is a usage error listing the valid values,
/// not a threshold that silently means something else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lower")]
pub(crate) enum SeverityArg {
    Critical,
    High,
    Medium,
    Low,
}

impl SeverityArg {
    /// Rank, lower being more severe — the same ordering `codepack-security` sorts by.
    pub(crate) fn rank(self) -> u8 {
        match self {
            Self::Critical => 0,
            Self::High => 1,
            Self::Medium => 2,
            Self::Low => 3,
        }
    }

    /// Whether a finding of `severity` reaches this threshold. An unrecognised severity
    /// never gates: inventing a rank for a value this build does not know would be a
    /// guess, and a guess that fails a pipeline is worse than one that does not.
    pub(crate) fn is_reached_by(self, severity: &str) -> bool {
        let rank = match severity {
            "critical" => 0,
            "high" => 1,
            "medium" => 2,
            "low" => 3,
            _ => return false,
        };
        rank <= self.rank()
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct SanitizeArgs {
    /// Source project directory to read from. Never written to.
    #[arg(long)]
    pub source: PathBuf,

    /// Destination directory the sterile copy is written into. Must not be the same as,
    /// or nested inside, `--source`.
    ///
    /// Optional only when `--archive` is given: then the copy goes to a temporary
    /// folder that is removed afterwards, and the `.7z` is the whole result. Wanting
    /// only an archive should not require inventing a folder to throw away.
    #[arg(long, required_unless_present = "archive")]
    pub out: Option<PathBuf>,

    /// Also pack the finished sterile copy into a single archive at this path.
    ///
    /// The archive contains the copied files and `STERILE_COPY_REPORT.*`, so a
    /// recipient holding only the archive still has the account of what was stripped,
    /// skipped and redacted. The container follows the file extension unless
    /// `--archive-format` says otherwise.
    #[arg(long, value_name = "FILE")]
    pub archive: Option<PathBuf>,

    /// Container for `--archive`. Defaults to whatever the file extension says, and to
    /// `zip` when it says nothing.
    #[arg(long, value_enum)]
    pub archive_format: Option<ArchiveFormat>,

    /// How aggressively to exclude sensitive files. Defaults to `safe`, matching every
    /// other command that reads a project.
    #[arg(long, value_enum)]
    pub safe_mode: Option<SafeMode>,
}

#[derive(Debug, Args)]
pub(crate) struct HistoryArgs {
    /// Show only runs for this project directory. Defaults to every project.
    #[arg(long)]
    pub path: Option<PathBuf>,

    /// How many runs to show.
    #[arg(long, default_value_t = 20)]
    pub limit: usize,
}

/// Mirrors `codepack_core::config::valid_sets::SAFE_EXPORT_MODES`. Spelled out as an
/// enum so `clap` rejects a bad value with a usage error (exit code 2) and lists the
/// valid ones, rather than letting it reach `Config` normalization, which would quietly
/// fall back to a default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum SafeMode {
    /// Exclude the most; safest to share.
    Safe,
    /// The default balance.
    Balanced,
    /// Exclude nothing on safety grounds.
    Full,
}

impl SafeMode {
    pub(crate) fn as_config_value(self) -> &'static str {
        match self {
            Self::Safe => "safe",
            Self::Balanced => "balanced",
            Self::Full => "full",
        }
    }
}

/// Mirrors `codepack_core::config::valid_sets::ARCHIVE_FORMATS`. `Rar` is offered
/// deliberately: the choice exists, it is reserved, and asking for it gets a message
/// saying so rather than "unexpected value", which would read like a typo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum ArchiveFormat {
    /// The default. What every earlier release produced.
    Zip,
    /// Smaller archives, at some cost in time.
    #[value(name = "7z")]
    SevenZip,
    /// Reserved — not implemented yet.
    Rar,
}

impl ArchiveFormat {
    pub(crate) fn as_config_value(self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::SevenZip => "7z",
            Self::Rar => "rar",
        }
    }
}

/// Mirrors `codepack_core::config::valid_sets::DIFF_EXPORT_MODES`, for the same reason
/// as [`SafeMode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum DiffMode {
    /// Every file the rules include.
    All,
    /// Only what changed since the last successful export.
    LastExport,
    /// Only what changed against a git ref.
    GitRef,
    /// Only what is uncommitted.
    Uncommitted,
}

impl DiffMode {
    pub(crate) fn as_config_value(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::LastExport => "last_export",
            Self::GitRef => "git_ref",
            Self::Uncommitted => "uncommitted",
        }
    }
}

impl ProjectArgs {
    /// Collects the flags into the shape [`crate::settings::resolve`] consumes.
    pub(crate) fn overrides(&self) -> crate::settings::Overrides {
        crate::settings::Overrides {
            preset: self.preset.clone(),
            profile: self.profile.clone(),
            safe_mode: self
                .safe_mode
                .map(|mode| mode.as_config_value().to_string()),
            diff: self.diff.map(|mode| mode.as_config_value().to_string()),
            budget: self.budget.clone(),
            archive_format: self
                .archive_format
                .map(|format| format.as_config_value().to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_definition_is_internally_consistent() {
        // clap's own audit: catches duplicate flags, bad defaults and broken value
        // parsers at test time rather than at a user's first invocation.
        Cli::command().debug_assert();
    }

    #[test]
    fn every_command_roadmap_names_exists() {
        for argv in [
            vec!["codepack", "export", "."],
            vec!["codepack", "preview", "."],
            vec!["codepack", "scan", "."],
            vec!["codepack", "history"],
            vec!["codepack", "doctor"],
            vec!["codepack", "sanitize", "--source", ".", "--out", "../out"],
        ] {
            assert!(
                Cli::try_parse_from(&argv).is_ok(),
                "failed to parse {argv:?}"
            );
        }
    }

    #[test]
    fn json_is_accepted_on_every_command_not_just_some() {
        for argv in [
            vec!["codepack", "--json", "export", "."],
            vec!["codepack", "export", ".", "--json"],
            vec!["codepack", "doctor", "--json"],
            vec!["codepack", "history", "--json"],
            vec![
                "codepack", "sanitize", "--source", ".", "--out", "../out", "--json",
            ],
        ] {
            assert!(
                Cli::try_parse_from(&argv).is_ok(),
                "failed to parse {argv:?}"
            );
        }
    }

    #[test]
    fn the_project_path_defaults_to_the_current_directory() {
        let cli = Cli::try_parse_from(["codepack", "preview"]).unwrap();
        match cli.command {
            Command::Preview(args) => assert_eq!(args.project.path, PathBuf::from(".")),
            other => panic!("expected preview, got {other:?}"),
        }
    }

    #[test]
    fn budget_units_are_parsed_by_the_argument_parser_itself() {
        let cli = Cli::try_parse_from(["codepack", "export", ".", "--budget", "200k"]).unwrap();
        match cli.command {
            Command::Export(args) => assert_eq!(
                args.project.budget,
                Some(crate::settings::BudgetSpec::Tokens(200_000))
            ),
            other => panic!("expected export, got {other:?}"),
        }
    }

    #[test]
    fn an_invalid_enum_value_is_a_usage_error_not_a_silent_default() {
        let error = Cli::try_parse_from(["codepack", "export", ".", "--safe-mode", "paranoid"])
            .unwrap_err();
        assert_eq!(error.exit_code(), crate::exit::BAD_ARGUMENTS);
    }

    /// A value that *looks* like a number but is not one stays a usage error. A value
    /// that looks like nothing in particular is a model name now, so it is no longer
    /// decidable at parse time — an unknown model is a resolution failure (exit 1),
    /// reported by `settings`, not a usage error.
    #[test]
    fn a_malformed_numeric_budget_is_a_usage_error_too() {
        let error =
            Cli::try_parse_from(["codepack", "export", ".", "--budget", "12kb"]).unwrap_err();
        assert_eq!(error.exit_code(), crate::exit::BAD_ARGUMENTS);
    }

    #[test]
    fn a_model_name_budget_parses_and_is_resolved_later() {
        let cli = Cli::try_parse_from(["codepack", "export", ".", "--budget", "Claude"]).unwrap();
        match cli.command {
            Command::Export(args) => assert_eq!(
                args.project.budget,
                Some(crate::settings::BudgetSpec::Model("Claude".to_string()))
            ),
            other => panic!("expected export, got {other:?}"),
        }
    }

    #[test]
    fn enum_values_map_to_exactly_what_config_expects() {
        use codepack_core::config::{DIFF_EXPORT_MODES, SAFE_EXPORT_MODES};

        for mode in [SafeMode::Safe, SafeMode::Balanced, SafeMode::Full] {
            assert!(
                SAFE_EXPORT_MODES.contains(&mode.as_config_value()),
                "{mode:?} maps to a value Config does not accept"
            );
        }
        for mode in [
            DiffMode::All,
            DiffMode::LastExport,
            DiffMode::GitRef,
            DiffMode::Uncommitted,
        ] {
            assert!(
                DIFF_EXPORT_MODES.contains(&mode.as_config_value()),
                "{mode:?} maps to a value Config does not accept"
            );
        }
    }
}
