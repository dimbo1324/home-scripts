//! Assembles `AGENTS.md` from the shared rule modules in `.ai/`.
//!
//! `CLAUDE.md` imports those modules natively, so only the Codex entry point needs to be
//! generated. Codex reads at most 32 KiB of project instructions, so the assembled file
//! is held below a hard budget: a module marked `<!-- tier: extended -->` contributes only
//! its title, path, and `> **Essence.**` line instead of its full text.

use std::fs;
use std::path::{Path, PathBuf};

/// Budget in KiB for the assembled file, below the 32 KiB Codex instruction limit.
const SIZE_LIMIT_KIB: f64 = 30.0;
const TIER_MARKER: &str = "tier: extended";
const ESSENCE_PREFIX: &str = "> **Essence.**";

const BANNER: &str = "\
<!--
GENERATED FILE - DO NOT EDIT.
Source of truth: .ai/universal/*.md and .ai/project/*.md.
Edit a module, then run: cargo xtask sync-agents
-->

# codepack - working notes for Codex

This file is the Codex entry point. It is assembled from the shared rule modules in
`.ai/` so Codex and Claude Code always follow identical rules. Later sections override
earlier ones; an explicit owner instruction in the current conversation overrides
everything.
";

struct Module {
    relative_path: String,
    body: String,
}

impl Module {
    fn is_extended(&self) -> bool {
        self.body
            .lines()
            .take(5)
            .any(|line| line.contains(TIER_MARKER))
    }

    fn title(&self) -> &str {
        self.body
            .lines()
            .find_map(|line| line.strip_prefix("# "))
            .unwrap_or("(untitled module)")
            .trim()
    }

    fn essence(&self) -> Option<&str> {
        self.body
            .lines()
            .find_map(|line| line.trim().strip_prefix(ESSENCE_PREFIX))
            .map(str::trim)
    }
}

fn collect_modules(root: &Path) -> Result<Vec<Module>, String> {
    let mut modules = Vec::new();
    for group in ["universal", "project"] {
        let dir = root.join(".ai").join(group);
        if !dir.is_dir() {
            return Err(format!("missing module directory: {}", dir.display()));
        }
        // `(name, path)` rather than the path alone: the directory entry already knows
        // the file name, so carrying it forward means the name is never an `Option` that
        // has to be unwrapped further down.
        let mut entries: Vec<(String, PathBuf)> = fs::read_dir(&dir)
            .map_err(|error| format!("cannot read {}: {error}", dir.display()))?
            .filter_map(Result::ok)
            .map(|entry| {
                (
                    entry.file_name().to_string_lossy().into_owned(),
                    entry.path(),
                )
            })
            .filter(|(_, path)| path.extension().is_some_and(|extension| extension == "md"))
            .collect();
        // Sorted by name, which is what the assembled file's order actually depends on.
        entries.sort();
        for (name, path) in entries {
            let body = fs::read_to_string(&path)
                .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
            modules.push(Module {
                relative_path: format!(".ai/{group}/{name}"),
                body: body.trim().to_string(),
            });
        }
    }
    if modules.is_empty() {
        return Err("no rule modules found under .ai/".to_string());
    }
    Ok(modules)
}

fn render(modules: &[Module]) -> String {
    let mut sections = vec![BANNER.trim_end().to_string()];
    let mut extended = Vec::new();

    for module in modules {
        if module.is_extended() {
            extended.push(module);
            continue;
        }
        sections.push(format!(
            "<!-- module: {} -->\n\n{}",
            module.relative_path, module.body
        ));
    }

    if !extended.is_empty() {
        let mut index = String::from(
            "<!-- module index: extended -->\n\n\
             # Modules loaded on demand\n\n\
             These rules bind exactly like the inlined ones; only their full text lives\n\
             outside this file, to stay within the instruction budget. Read the file itself\n\
             when a task touches it — that is an obligation, not a suggestion.\n",
        );
        for module in extended {
            index.push_str(&format!(
                "\n## {}\n\nFile: `{}`\n",
                module.title(),
                module.relative_path
            ));
            if let Some(essence) = module.essence() {
                index.push_str(&format!("\n{essence}\n"));
            }
        }
        sections.push(index.trim_end().to_string());
    }

    format!("{}\n", sections.join("\n\n---\n\n"))
}

/// Regenerates `AGENTS.md`, or verifies it is current when `check_only` is set.
pub(crate) fn run(root: &Path, check_only: bool) -> Result<(), String> {
    let modules = collect_modules(root)?;
    let content = render(&modules);
    let size_kib = content.len() as f64 / 1024.0;

    if size_kib > SIZE_LIMIT_KIB {
        return Err(format!(
            "assembled AGENTS.md is {size_kib:.1} KiB; the budget is {SIZE_LIMIT_KIB:.0} KiB. \
             Tighten a module, or mark a situational one with `<!-- tier: extended -->` and \
             give it a `> **Essence.**` line."
        ));
    }

    let target = root.join("AGENTS.md");
    let current = fs::read_to_string(&target).unwrap_or_default();

    if check_only {
        if current == content {
            println!("AGENTS.md is in sync with .ai/ modules ({size_kib:.1} KiB).");
            return Ok(());
        }
        return Err(
            "AGENTS.md is out of sync with .ai/ modules. Run: cargo xtask sync-agents".to_string(),
        );
    }

    if current == content {
        println!("AGENTS.md already up to date ({size_kib:.1} KiB).");
        return Ok(());
    }
    fs::write(&target, &content)
        .map_err(|error| format!("cannot write {}: {error}", target.display()))?;
    println!(
        "AGENTS.md regenerated from {} modules ({size_kib:.1} KiB of {SIZE_LIMIT_KIB:.0} KiB budget).",
        modules.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(path: &str, body: &str) -> Module {
        Module {
            relative_path: path.to_string(),
            body: body.trim().to_string(),
        }
    }

    #[test]
    fn inline_module_is_embedded_in_full() {
        let modules = vec![module(".ai/universal/01-a.md", "# Alpha\n\nBody text.")];
        let rendered = render(&modules);
        assert!(rendered.contains("Body text."));
        assert!(rendered.contains("<!-- module: .ai/universal/01-a.md -->"));
    }

    #[test]
    fn extended_module_contributes_only_its_essence() {
        let modules = vec![module(
            ".ai/universal/02-b.md",
            "<!-- tier: extended -->\n\n# Beta\n\n> **Essence.** Short summary.\n\nLong body.",
        )];
        let rendered = render(&modules);
        assert!(rendered.contains("Short summary."));
        assert!(rendered.contains("File: `.ai/universal/02-b.md`"));
        assert!(!rendered.contains("Long body."));
    }

    #[test]
    fn title_and_essence_are_extracted() {
        let parsed = module(
            ".ai/universal/03-c.md",
            "<!-- tier: extended -->\n\n# Gamma\n\n> **Essence.** Keep it tight.",
        );
        assert_eq!(parsed.title(), "Gamma");
        assert_eq!(parsed.essence(), Some("Keep it tight."));
        assert!(parsed.is_extended());
    }
}
