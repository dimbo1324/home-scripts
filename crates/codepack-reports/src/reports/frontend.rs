//! `19_frontend_report.md`, ported from legacy
//! `reports/insights/frontend_backend.py::write_frontend_report`.

use std::collections::BTreeSet;
use std::path::Path;

use regex::Regex;

use crate::context::ReportContext;
use crate::error::ReportError;
use crate::paths::to_native_path;
use crate::plugin::ReportJob;
use crate::profile;
use crate::reports::layout::all_directories;
use crate::text::{read_text_unredacted, safe_read_json};

pub const JOB: ReportJob = ReportJob {
    filename: "19_frontend_report.md",
    profiles: profile::FRONTEND_REPORT_MD,
    description: "Frontend libraries, directory roles, route/store/form files, component/hook candidates.",
    run: write_frontend_report,
};

const DIR_LIMIT: usize = 60;
const FILE_LIMIT: usize = 120;
const SYMBOL_LIMIT: usize = 200;
const DIR_ROLE_KEYS: &[&str] = &["pages", "routes", "components", "hooks", "stores", "styles"];
const INTERESTING_DEPS: &[&str] = &[
    "react",
    "vue",
    "svelte",
    "@tanstack/react-router",
    "@tanstack/react-query",
    "react-hook-form",
    "zod",
    "zustand",
    "redux",
    "tailwindcss",
    "framer-motion",
    "recharts",
    "echarts",
];

fn component_pattern() -> Regex {
    Regex::new(r"\b(?:export\s+default\s+)?function\s+([A-Z][A-Za-z0-9_]*)|\bconst\s+([A-Z][A-Za-z0-9_]*)\s*=\s*(?:\(|React\.)")
        .expect("fixed literal")
}
fn hook_pattern() -> Regex {
    Regex::new(r"\bfunction\s+(use[A-Z][A-Za-z0-9_]*)|\bconst\s+(use[A-Z][A-Za-z0-9_]*)\s*=")
        .expect("fixed literal")
}

fn dir_role(directory: &str, key: &str) -> bool {
    let lower_parts: Vec<String> = directory
        .split('\\')
        .map(|part| part.to_lowercase())
        .collect();
    if key == "styles" {
        return lower_parts
            .iter()
            .any(|part| matches!(part.as_str(), "css" | "styles" | "style"));
    }
    lower_parts.iter().any(|part| part == key)
}

fn write_frontend_report(ctx: &ReportContext<'_>, output_file: &Path) -> Result<(), ReportError> {
    let max_bytes = ctx.config.effective_max_text_file_bytes();
    let package_json = safe_read_json(&ctx.staging_root.join("package.json"));
    let mut deps: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for section in ["dependencies", "devDependencies"] {
        if let Some(object) = package_json.get(section).and_then(|v| v.as_object()) {
            for (name, value) in object {
                if let Some(version) = value.as_str() {
                    deps.insert(name.clone(), version.to_string());
                }
            }
        }
    }

    let directories = all_directories(ctx.inventory);
    let mut dirs_by_role: std::collections::BTreeMap<&str, Vec<String>> =
        DIR_ROLE_KEYS.iter().map(|key| (*key, Vec::new())).collect();
    for directory in &directories {
        for key in DIR_ROLE_KEYS {
            if dir_role(directory, key) {
                // `dirs_by_role` was just pre-populated with every `DIR_ROLE_KEYS`
                // entry above, and `key` is itself drawn from that same slice.
                dirs_by_role
                    .get_mut(key)
                    .expect("dirs_by_role was pre-populated with every DIR_ROLE_KEYS entry")
                    .push(directory.clone());
            }
        }
    }
    for dirs in dirs_by_role.values_mut() {
        dirs.sort_by_key(|value| value.to_lowercase());
        dirs.dedup();
    }

    let mut components: BTreeSet<(String, String)> = BTreeSet::new();
    let mut hooks: BTreeSet<(String, String)> = BTreeSet::new();
    let mut state_files: BTreeSet<String> = BTreeSet::new();
    let mut form_files: BTreeSet<String> = BTreeSet::new();
    let mut route_files: BTreeSet<String> = BTreeSet::new();

    for file in &ctx.inventory.files {
        if !matches!(
            file.extension.as_str(),
            "js" | "jsx" | "ts" | "tsx" | "vue" | "svelte" | "astro"
        ) {
            continue;
        }
        let rel_lower = file.relative_path.to_lowercase();
        let name_lower = crate::paths::file_name_of(&file.relative_path).to_lowercase();

        if rel_lower.contains("route") || name_lower.starts_with("page.") {
            route_files.insert(file.relative_path.clone());
        }
        if ["store", "zustand", "redux", "state"]
            .iter()
            .any(|token| rel_lower.contains(token))
        {
            state_files.insert(file.relative_path.clone());
        }
        if ["form", "schema", "zod"]
            .iter()
            .any(|token| rel_lower.contains(token))
        {
            form_files.insert(file.relative_path.clone());
        }

        let native = to_native_path(&file.relative_path);
        if !codepack_scanner::should_consider_text_file(&native) {
            continue;
        }
        let Some(text) = read_text_unredacted(&ctx.staging_root.join(&native), max_bytes) else {
            continue;
        };
        for captures in component_pattern().captures_iter(&text) {
            if let Some(name) = captures.get(1).or_else(|| captures.get(2)) {
                components.insert((file.relative_path.clone(), name.as_str().to_string()));
            }
        }
        for captures in hook_pattern().captures_iter(&text) {
            if let Some(name) = captures.get(1).or_else(|| captures.get(2)) {
                hooks.insert((file.relative_path.clone(), name.as_str().to_string()));
            }
        }
    }

    let mut out = String::new();
    out.push_str("# Frontend Report\n\n");
    out.push_str(&format!("Generated: {}\n\n", ctx.plan.generated_at));

    out.push_str("## Frontend libraries detected from package.json\n\n");
    let detected: Vec<&&str> = INTERESTING_DEPS
        .iter()
        .filter(|name| deps.contains_key(**name))
        .collect();
    if detected.is_empty() {
        out.push_str("- No common frontend libraries detected.\n");
    } else {
        for name in detected {
            out.push_str(&format!("- `{name}` — `{}`\n", deps[*name]));
        }
    }

    out.push_str("\n## Important frontend directories\n\n");
    for key in DIR_ROLE_KEYS {
        out.push_str(&format!("### {key}\n"));
        let dirs = &dirs_by_role[key];
        if dirs.is_empty() {
            out.push_str("- not detected\n");
        } else {
            for directory in dirs.iter().take(DIR_LIMIT) {
                out.push_str(&format!("- `{directory}`\n"));
            }
        }
        out.push('\n');
    }

    for (title, paths) in [
        ("Route/page files", &route_files),
        ("State/store files", &state_files),
        ("Form/schema files", &form_files),
    ] {
        out.push_str(&format!("## {title}\n\n"));
        if paths.is_empty() {
            out.push_str("- none detected\n");
        } else {
            for path in paths.iter().take(FILE_LIMIT) {
                out.push_str(&format!("- `{path}`\n"));
            }
        }
        out.push('\n');
    }

    out.push_str("## Component candidates\n\n");
    if components.is_empty() {
        out.push_str("- none detected\n");
    } else {
        let mut sorted: Vec<&(String, String)> = components.iter().collect();
        sorted.sort_by(|a, b| {
            a.1.to_lowercase()
                .cmp(&b.1.to_lowercase())
                .then_with(|| a.0.to_lowercase().cmp(&b.0.to_lowercase()))
        });
        for (path, name) in sorted.iter().take(SYMBOL_LIMIT) {
            out.push_str(&format!("- `{name}` — `{path}`\n"));
        }
    }

    out.push_str("\n## Hook candidates\n\n");
    if hooks.is_empty() {
        out.push_str("- none detected\n");
    } else {
        let mut sorted: Vec<&(String, String)> = hooks.iter().collect();
        sorted.sort_by(|a, b| {
            a.1.to_lowercase()
                .cmp(&b.1.to_lowercase())
                .then_with(|| a.0.to_lowercase().cmp(&b.0.to_lowercase()))
        });
        for (path, name) in sorted.iter().take(SYMBOL_LIMIT) {
            out.push_str(&format!("- `{name}` — `{path}`\n"));
        }
    }

    std::fs::write(output_file, out).map_err(|source| ReportError::Write {
        path: output_file.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::Fixture;

    #[test]
    fn detects_react_dependency_component_and_hook() {
        let fixture = Fixture::new(|root| {
            std::fs::write(
                root.join("package.json"),
                r#"{"dependencies": {"react": "18.0.0"}}"#,
            )
            .unwrap();
            std::fs::create_dir_all(root.join("src").join("components")).unwrap();
            std::fs::write(
                root.join("src").join("components").join("Button.tsx"),
                "export default function Button() { return null; }\nfunction useToggle() { return false; }\n",
            )
            .unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_frontend_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.starts_with("# Frontend Report"));
        assert!(content.contains("`react` — `18.0.0`"));
        assert!(content.contains("### components\n- `src\\components`"));
        assert!(content.contains("`Button` — `src\\components\\Button.tsx`"));
        assert!(content.contains("`useToggle` — `src\\components\\Button.tsx`"));
    }

    #[test]
    fn reports_none_detected_for_a_non_frontend_project() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("main.py"), "x = 1\n").unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_frontend_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("No common frontend libraries detected."));
        assert!(content.contains("- none detected"));
    }
}
