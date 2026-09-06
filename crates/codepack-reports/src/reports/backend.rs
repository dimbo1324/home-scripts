//! `20_backend_report.md`, ported from legacy
//! `reports/insights/frontend_backend.py::write_backend_report`.

use std::collections::BTreeSet;
use std::path::Path;

use regex::Regex;

use crate::context::ReportContext;
use crate::error::ReportError;
use crate::paths::to_native_path;
use crate::plugin::ReportJob;
use crate::profile;
use crate::reports::layout::all_directories;
use crate::text::read_text_unredacted;

pub const JOB: ReportJob = ReportJob {
    filename: "20_backend_report.md",
    profiles: profile::BACKEND_REPORT_MD,
    description: "Backend directory roles, Go/DB/config files, Python class/function candidates.",
    run: write_backend_report,
};

const DIR_LIMIT: usize = 80;
const FILE_LIMIT: usize = 120;
const SYMBOL_LIMIT: usize = 250;
const DIR_ROLE_KEYS: &[&str] = &[
    "api",
    "services",
    "models",
    "repositories",
    "migrations",
    "workers",
    "config",
];

fn py_class_pattern() -> Regex {
    Regex::new(r"(?m)^class\s+([A-Za-z_][A-Za-z0-9_]*)").expect("fixed literal")
}
fn py_func_pattern() -> Regex {
    Regex::new(r"(?m)^def\s+([A-Za-z_][A-Za-z0-9_]*)").expect("fixed literal")
}

fn dir_role(directory: &str, key: &str) -> bool {
    let lower_parts: Vec<String> = directory
        .split('\\')
        .map(|part| part.to_lowercase())
        .collect();
    if key == "workers" {
        return lower_parts
            .iter()
            .any(|part| matches!(part.as_str(), "tasks" | "jobs" | "worker"));
    }
    lower_parts.iter().any(|part| part == key)
}

fn write_backend_report(ctx: &ReportContext<'_>, output_file: &Path) -> Result<(), ReportError> {
    let max_bytes = ctx.config.effective_max_text_file_bytes();
    let directories = all_directories(ctx.inventory);

    let mut backend_dirs: std::collections::BTreeMap<&str, Vec<String>> =
        DIR_ROLE_KEYS.iter().map(|key| (*key, Vec::new())).collect();
    for directory in &directories {
        for key in DIR_ROLE_KEYS {
            if dir_role(directory, key) {
                // `backend_dirs` was just pre-populated with every `DIR_ROLE_KEYS`
                // entry above, and `key` is itself drawn from that same slice.
                backend_dirs
                    .get_mut(key)
                    .expect("backend_dirs was pre-populated with every DIR_ROLE_KEYS entry")
                    .push(directory.clone());
            }
        }
    }
    for dirs in backend_dirs.values_mut() {
        dirs.sort_by_key(|value| value.to_lowercase());
        dirs.dedup();
    }

    let mut py_symbols: BTreeSet<(String, &'static str, String)> = BTreeSet::new();
    let mut go_files: BTreeSet<String> = BTreeSet::new();
    let mut db_files: BTreeSet<String> = BTreeSet::new();
    let mut config_files: BTreeSet<String> = BTreeSet::new();

    for file in &ctx.inventory.files {
        let rel_lower = file.relative_path.to_lowercase();
        let name_lower = crate::paths::file_name_of(&file.relative_path).to_lowercase();
        if file.extension == "go" {
            go_files.insert(file.relative_path.clone());
        }
        if matches!(file.extension.as_str(), "sql" | "prisma") || rel_lower.contains("migration") {
            db_files.insert(file.relative_path.clone());
        }
        if name_lower.contains("config") || name_lower.contains("settings") {
            config_files.insert(file.relative_path.clone());
        }

        if file.extension != "py" {
            continue;
        }
        let native = to_native_path(&file.relative_path);
        if !codepack_scanner::should_consider_text_file(&native) {
            continue;
        }
        let Some(text) = read_text_unredacted(&ctx.staging_root.join(&native), max_bytes) else {
            continue;
        };
        for captures in py_class_pattern().captures_iter(&text) {
            if let Some(name) = captures.get(1) {
                py_symbols.insert((
                    file.relative_path.clone(),
                    "class",
                    name.as_str().to_string(),
                ));
            }
        }
        for captures in py_func_pattern().captures_iter(&text) {
            if let Some(name) = captures.get(1) {
                py_symbols.insert((file.relative_path.clone(), "def", name.as_str().to_string()));
            }
        }
    }

    let mut out = String::new();
    out.push_str("# Backend Report\n\n");
    out.push_str(&format!("Generated: {}\n\n", ctx.plan.generated_at));

    out.push_str("## Backend directories\n\n");
    for key in DIR_ROLE_KEYS {
        out.push_str(&format!("### {key}\n"));
        let dirs = &backend_dirs[key];
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
        ("Go files", &go_files),
        ("Database/migration files", &db_files),
        ("Config/settings files", &config_files),
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

    out.push_str("## Python class/function candidates\n\n");
    if py_symbols.is_empty() {
        out.push_str("- none detected\n");
    } else {
        let mut sorted: Vec<&(String, &str, String)> = py_symbols.iter().collect();
        sorted.sort_by(|a, b| {
            a.0.to_lowercase()
                .cmp(&b.0.to_lowercase())
                .then_with(|| a.2.to_lowercase().cmp(&b.2.to_lowercase()))
        });
        for (path, kind, name) in sorted.iter().take(SYMBOL_LIMIT) {
            out.push_str(&format!("- `{kind} {name}` — `{path}`\n"));
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
    fn detects_backend_directories_go_files_and_python_symbols() {
        let fixture = Fixture::new(|root| {
            std::fs::create_dir_all(root.join("services")).unwrap();
            std::fs::write(root.join("services").join("user_service.py"), "x = 1\n").unwrap();
            std::fs::write(
                root.join("app.py"),
                "class UserService:\n    pass\n\ndef create_user():\n    pass\n",
            )
            .unwrap();
            std::fs::write(root.join("server.go"), "package main\n").unwrap();
            std::fs::write(root.join("001_init.sql"), "CREATE TABLE x();\n").unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_backend_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.starts_with("# Backend Report"));
        assert!(content.contains("### services\n- `services`"));
        assert!(content.contains("server.go"));
        assert!(content.contains("001_init.sql"));
        assert!(content.contains("`class UserService` — `app.py`"));
        assert!(content.contains("`def create_user` — `app.py`"));
    }

    #[test]
    fn reports_none_detected_for_a_frontend_only_project() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("index.ts"), "export {}\n").unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_backend_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("- none detected"));
        assert!(content.contains("- not detected"));
    }
}
