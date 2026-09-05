//! The one way a report may read `package.json`'s `scripts`.
//!
//! ## Why this exists rather than four call sites
//!
//! The extraction was written out four times. One copy redacted the command and said in
//! its own module documentation why — "a script command in particular can embed an
//! inline credential (e.g. `SOME_TOKEN=abc node build.js`)" — and three did not. So the
//! risk was understood, documented, and closed in exactly one of four places; the other
//! three wrote a live credential into `13_runbook.md`, `AI_CONTEXT/10_SCRIPTS.md` and
//! `12_ai_context_pack.md`, the last of which exists to be pasted into a language model.
//!
//! Adding the missing call in three places would fix today and lose again the day a
//! fifth report is written. So the raw command is not obtainable from here at all:
//! [`PackageScript::command`] is a [`RedactedCommand`], which can only be built by this
//! module, from text that has been through [`crate::context::redact_line`]. A caller that
//! cannot hold a raw command cannot forget to redact one.
//!
//! `package.json` is never excluded by safe mode — its name is not sensitive and `.json`
//! is not an excluded suffix — so this is not a hypothetical path.

use crate::context::ReportContext;
use crate::text::safe_read_json;

/// A script command that has already been through redaction.
///
/// There is deliberately no constructor from `String` and no accessor returning the
/// original text: the type exists to make "I forgot to redact this" unrepresentable
/// rather than merely discouraged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedCommand(String);

impl RedactedCommand {
    fn redact(raw: &str) -> Self {
        // `redact_shell_command`, not the general line redaction: a command may be
        // prefixed by environment assignments whose names are compounded
        // (`NPM_TOKEN=…`), and the general rule requires a keyword to stand as a whole
        // word. See that function for why the boundary is not simply widened.
        Self(codepack_security::redact_shell_command(raw))
    }

    /// The redacted text, safe to write into any artifact.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RedactedCommand {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// One entry of `package.json`'s `scripts` object.
pub struct PackageScript {
    /// The script's key. A name is a name — it is not redacted, and a credential has
    /// never been observed in one.
    pub name: String,
    pub command: RedactedCommand,
}

/// Every `scripts` entry in the project's `package.json`, sorted by name
/// case-insensitively, with commands already redacted.
///
/// An absent or malformed `package.json` yields an empty list rather than an error: a
/// report describes what is there, and "no scripts" is a description.
pub fn package_scripts(ctx: &ReportContext<'_>) -> Vec<PackageScript> {
    let package_json = safe_read_json(&ctx.staging_root.join("package.json"));
    let Some(scripts) = package_json
        .get("scripts")
        .and_then(|value| value.as_object())
    else {
        return Vec::new();
    };

    let mut names: Vec<&String> = scripts.keys().collect();
    names.sort_by_key(|name| name.to_lowercase());
    names
        .into_iter()
        .map(|name| PackageScript {
            name: name.clone(),
            command: RedactedCommand::redact(scripts[name].as_str().unwrap_or_default()),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::Fixture;

    fn scripts_of(json: &str) -> Vec<PackageScript> {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("package.json"), json).unwrap();
        });
        package_scripts(&fixture.context("full"))
    }

    #[test]
    fn an_inline_credential_never_leaves_this_module() {
        let scripts = scripts_of(
            r#"{"scripts": {"deploy": "NPM_TOKEN=npm_realvalue0123456789 npm publish"}}"#,
        );

        assert_eq!(scripts.len(), 1);
        assert_eq!(scripts[0].name, "deploy");
        assert!(
            !scripts[0]
                .command
                .as_str()
                .contains("npm_realvalue0123456789"),
            "the credential survived: {}",
            scripts[0].command
        );
    }

    #[test]
    fn an_ordinary_command_is_passed_through_readably() {
        let scripts = scripts_of(r#"{"scripts": {"build": "vite build"}}"#);
        assert!(scripts[0].command.as_str().contains("vite build"));
    }

    #[test]
    fn entries_come_back_sorted_case_insensitively() {
        let scripts = scripts_of(r#"{"scripts": {"Zebra": "z", "alpha": "a", "Beta": "b"}}"#);
        let names: Vec<&str> = scripts.iter().map(|script| script.name.as_str()).collect();
        assert_eq!(names, ["alpha", "Beta", "Zebra"]);
    }

    #[test]
    fn an_absent_or_malformed_package_json_yields_nothing() {
        assert!(scripts_of("{}").is_empty());
        assert!(scripts_of(r#"{"scripts": []}"#).is_empty());
        assert!(scripts_of("not json at all").is_empty());
    }
}
