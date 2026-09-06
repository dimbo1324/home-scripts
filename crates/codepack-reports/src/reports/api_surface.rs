//! `18_api_surface_report.md`, ported from legacy
//! `reports/insights/api_surface.py::write_api_surface_report`: FastAPI/Flask route
//! decorators, Express route handlers, Go `net/http` handlers, and frontend
//! `fetch`/`axios`/`client` call sites, all via the exact legacy regex patterns.
//!
//! Every captured route/call-site string is routed through
//! [`crate::context::redact_line`] before being written — invariant I3: unlike a file
//! path (a structural identifier), a route or call-site string is a raw substring
//! captured straight out of source content and can carry an inline credential (e.g.
//! a hardcoded `https://user:token@host/path` call site).

use std::collections::BTreeSet;
use std::path::Path;

use regex::Regex;

use crate::context::{ReportContext, redact_line};
use crate::error::ReportError;
use crate::paths::to_native_path;
use crate::plugin::ReportJob;
use crate::profile;
use crate::text::read_text_unredacted;

pub const JOB: ReportJob = ReportJob {
    filename: "18_api_surface_report.md",
    profiles: profile::API_SURFACE_REPORT_MD,
    description: "Backend route candidates and frontend HTTP call sites (regex heuristics).",
    run: write_api_surface_report,
};

const ROUTE_LIMIT: usize = 500;
const CALL_LIMIT: usize = 500;
const OPENAPI_NAMES: &[&str] = &[
    "openapi.yaml",
    "openapi.yml",
    "openapi.json",
    "swagger.yaml",
    "swagger.yml",
    "swagger.json",
];

fn fastapi_pattern() -> Regex {
    Regex::new(r#"(?i)@(?:app|router)\.(get|post|put|patch|delete|options|head)\(\s*['"]([^'"]+)"#)
        .expect("fixed literal")
}
fn flask_pattern() -> Regex {
    Regex::new(
        r#"(?i)@(?:app|blueprint|bp)\.route\(\s*['"]([^'"]+).*?(?:methods\s*=\s*\[([^\]]+)\])?"#,
    )
    .expect("fixed literal")
}
fn express_pattern() -> Regex {
    Regex::new(r#"(?i)(?:app|router)\.(get|post|put|patch|delete|use)\(\s*['"]([^'"]+)"#)
        .expect("fixed literal")
}
fn go_pattern() -> Regex {
    Regex::new(r#"(?:http\.)?HandleFunc\(\s*['"]([^'"]+)"#).expect("fixed literal")
}
fn fetch_pattern() -> Regex {
    Regex::new(r#"(?:fetch|axios\.(?:get|post|put|patch|delete)|client\.(?:get|post|put|patch|delete))\(\s*`?['"]?([^'"`)]+)"#)
        .expect("fixed literal")
}

fn write_api_surface_report(
    ctx: &ReportContext<'_>,
    output_file: &Path,
) -> Result<(), ReportError> {
    let max_bytes = ctx.config.effective_max_text_file_bytes();

    let mut backend_routes: BTreeSet<(String, String, String)> = BTreeSet::new();
    let mut frontend_calls: BTreeSet<(String, String)> = BTreeSet::new();
    let mut specs: Vec<String> = Vec::new();

    for file in &ctx.inventory.files {
        let name_lower = crate::paths::file_name_of(&file.relative_path).to_lowercase();
        if OPENAPI_NAMES.contains(&name_lower.as_str()) {
            specs.push(file.relative_path.clone());
        }
        let extension = file.extension.as_str();
        if !matches!(
            extension,
            "py" | "js" | "jsx" | "ts" | "tsx" | "go" | "vue" | "svelte" | "astro"
        ) {
            continue;
        }
        let native = to_native_path(&file.relative_path);
        if !codepack_scanner::should_consider_text_file(&native) {
            continue;
        }
        let Some(text) = read_text_unredacted(&ctx.staging_root.join(&native), max_bytes) else {
            continue;
        };

        if extension == "py" {
            for captures in fastapi_pattern().captures_iter(&text) {
                let method = captures
                    .get(1)
                    .map(|m| m.as_str())
                    .unwrap_or_default()
                    .to_uppercase();
                let route = captures
                    .get(2)
                    .map(|m| m.as_str())
                    .unwrap_or_default()
                    .to_string();
                backend_routes.insert((file.relative_path.clone(), method, route));
            }
            for captures in flask_pattern().captures_iter(&text) {
                let route = captures
                    .get(1)
                    .map(|m| m.as_str())
                    .unwrap_or_default()
                    .to_string();
                let methods = captures
                    .get(2)
                    .map(|m| m.as_str().replace(['\'', '"'], ""))
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| "GET(default)".to_string());
                backend_routes.insert((file.relative_path.clone(), methods, route));
            }
        } else if matches!(
            extension,
            "js" | "jsx" | "ts" | "tsx" | "vue" | "svelte" | "astro"
        ) {
            for captures in express_pattern().captures_iter(&text) {
                let method = captures
                    .get(1)
                    .map(|m| m.as_str())
                    .unwrap_or_default()
                    .to_uppercase();
                let route = captures
                    .get(2)
                    .map(|m| m.as_str())
                    .unwrap_or_default()
                    .to_string();
                backend_routes.insert((file.relative_path.clone(), method, route));
            }
            for captures in fetch_pattern().captures_iter(&text) {
                let Some(call) = captures.get(1).map(|m| m.as_str()) else {
                    continue;
                };
                if call.starts_with("http")
                    || call.starts_with('/')
                    || call.starts_with("api")
                    || call.starts_with("${")
                    || call.contains("/api")
                {
                    frontend_calls.insert((file.relative_path.clone(), call.to_string()));
                }
            }
        } else if extension == "go" {
            for captures in go_pattern().captures_iter(&text) {
                let route = captures
                    .get(1)
                    .map(|m| m.as_str())
                    .unwrap_or_default()
                    .to_string();
                backend_routes.insert((
                    file.relative_path.clone(),
                    "GO_HANDLEFUNC".to_string(),
                    route,
                ));
            }
        }
    }
    specs.sort_by_key(|value| value.to_lowercase());

    let mut sorted_routes: Vec<(String, String, String)> = backend_routes.into_iter().collect();
    sorted_routes.sort_by(|a, b| {
        a.2.cmp(&b.2)
            .then_with(|| a.0.to_lowercase().cmp(&b.0.to_lowercase()))
    });

    let mut sorted_calls: Vec<(String, String)> = frontend_calls.into_iter().collect();
    sorted_calls.sort_by(|a, b| {
        a.1.cmp(&b.1)
            .then_with(|| a.0.to_lowercase().cmp(&b.0.to_lowercase()))
    });

    let mut out = String::new();
    out.push_str("# API Surface Report\n\n");
    out.push_str(&format!("Generated: {}\n\n", ctx.plan.generated_at));
    out.push_str(
        "This report detects backend routes and frontend HTTP calls using conservative regex heuristics.\n\n",
    );

    out.push_str("## API specifications\n\n");
    if specs.is_empty() {
        out.push_str("- No OpenAPI/Swagger files detected.\n");
    } else {
        for path in &specs {
            out.push_str(&format!("- `{path}`\n"));
        }
    }

    out.push_str("\n## Backend route candidates\n\n");
    if sorted_routes.is_empty() {
        out.push_str("- No backend route candidates detected.\n");
    } else {
        for (path, method, route) in sorted_routes.iter().take(ROUTE_LIMIT) {
            // `route` is a raw substring captured straight out of source content
            // (unlike `path`, a structural filename) — invariant I3.
            out.push_str(&redact_line(&format!(
                "- `{method}` `{route}` — `{path}`\n"
            )));
        }
    }

    out.push_str("\n## Frontend HTTP call candidates\n\n");
    if sorted_calls.is_empty() {
        out.push_str("- No frontend HTTP call candidates detected.\n");
    } else {
        for (path, call) in sorted_calls.iter().take(CALL_LIMIT) {
            // `call` is a raw substring captured straight out of source content —
            // invariant I3.
            out.push_str(&redact_line(&format!("- `{call}` — `{path}`\n")));
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
    fn detects_fastapi_route_and_frontend_fetch_call() {
        let fixture = Fixture::new(|root| {
            std::fs::write(
                root.join("app.py"),
                "@app.get(\"/users\")\ndef list_users():\n    pass\n",
            )
            .unwrap();
            std::fs::write(
                root.join("client.ts"),
                "fetch('/api/users').then(r => r.json());\n",
            )
            .unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_api_surface_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.starts_with("# API Surface Report"));
        assert!(content.contains("`GET` `/users` — `app.py`"));
        assert!(content.contains("`/api/users` — `client.ts`"));
    }

    /// Invariant I3: a secret embedded in a captured route/call-site string must
    /// never reach the report in clear text.
    #[test]
    fn redacts_a_secret_embedded_in_a_captured_route_string() {
        let fixture = Fixture::new(|root| {
            std::fs::write(
                root.join("app.py"),
                "@app.get(\"/users?API_KEY=sk-super-secret-value\")\ndef list_users():\n    pass\n",
            )
            .unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_api_surface_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("`GET`"));
        assert!(!content.contains("sk-super-secret-value"));
        assert!(content.contains("<REDACTED>"));
    }

    #[test]
    fn reports_no_candidates_and_no_specs_when_none_detected() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("plain.py"), "x = 1\n").unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_api_surface_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("No OpenAPI/Swagger files detected."));
        assert!(content.contains("No backend route candidates detected."));
        assert!(content.contains("No frontend HTTP call candidates detected."));
    }
}
