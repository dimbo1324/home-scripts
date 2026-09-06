//! `10_docker.txt`, ported from legacy
//! `reports/insights/docker_report.py::write_docker_report`/`parse_compose_services`.
//!
//! [`parse_compose_services`] is a hand-written, indent-sensitive parser for the small
//! subset of Compose YAML this report needs (service names, plus `image`/`build`/
//! `ports`/`volumes`/`environment`/`env_file`/`depends_on` keys) — legacy's own comment
//! reads "Uses a hand-written indent-sensitive parser so no PyYAML dependency is
//! required"; pulling in a full YAML crate for this one report would be exactly the
//! kind of unjustified new dependency `.ai/universal/05-security-and-secrets.md`
//! forbids for a small, bounded need, so this ports the same heuristic rather than
//! reaching for `serde_yaml`/`yaml-rust`.

use std::path::Path;

use crate::context::{ReportContext, redact_line};
use crate::error::ReportError;
use crate::paths::file_name_of;
use crate::plugin::ReportJob;
use crate::profile;
use crate::reports::layout::section_rule;
use crate::text::read_text_unredacted;

pub const JOB: ReportJob = ReportJob {
    filename: "10_docker.txt",
    profiles: profile::DOCKER_TXT,
    description: "Dockerfile / Docker Compose service map.",
    run: write_docker_report,
};

const SERVICE_VALUE_LIMIT: usize = 80;
const COMPOSE_KEYS: &[&str] = &[
    "image",
    "build",
    "ports",
    "volumes",
    "environment",
    "env_file",
    "depends_on",
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ComposeService {
    pub name: String,
    pub values: Vec<(String, Vec<String>)>,
}

impl ComposeService {
    fn entry(&mut self, key: &str) -> &mut Vec<String> {
        if let Some(index) = self.values.iter().position(|(k, _)| k == key) {
            &mut self.values[index].1
        } else {
            self.values.push((key.to_string(), Vec::new()));
            let last = self.values.len() - 1;
            &mut self.values[last].1
        }
    }

    fn get(&self, key: &str) -> Option<&[String]> {
        self.values
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_slice())
    }
}

/// Legacy `parse_compose_services`: indent-based, `services:` block only, order of
/// discovery preserved (legacy's own dict insertion order).
pub fn parse_compose_services(text: &str) -> Vec<ComposeService> {
    let mut services: Vec<ComposeService> = Vec::new();
    let mut in_services = false;
    let mut current_service: Option<usize> = None;
    let mut current_key = String::new();

    for raw_line in text.lines() {
        if raw_line.trim().is_empty() || raw_line.trim_start().starts_with('#') {
            continue;
        }
        let indent = raw_line.len() - raw_line.trim_start_matches(' ').len();
        let stripped = raw_line.trim();

        if indent == 0 && stripped.starts_with("services:") {
            in_services = true;
            current_service = None;
            continue;
        }
        if indent == 0 && in_services && !stripped.starts_with("services:") {
            break;
        }
        if !in_services {
            continue;
        }
        if indent == 2 && stripped.ends_with(':') {
            let name = stripped
                .trim_end_matches(':')
                .trim()
                .trim_matches(|c| c == '"' || c == '\'')
                .to_string();
            let index = match services.iter().position(|s| s.name == name) {
                Some(index) => index,
                None => {
                    services.push(ComposeService {
                        name,
                        values: Vec::new(),
                    });
                    services.len() - 1
                }
            };
            current_service = Some(index);
            current_key.clear();
            continue;
        }
        let Some(service_index) = current_service else {
            continue;
        };
        if indent == 4 && stripped.contains(':') {
            let (key, value) = stripped.split_once(':').expect("checked contains(':')");
            current_key = key.trim().to_string();
            let value = value.trim();
            if !value.is_empty() {
                services[service_index]
                    .entry(&current_key)
                    .push(value.to_string());
            }
            continue;
        }
        if indent >= 6 && stripped.starts_with('-') && !current_key.is_empty() {
            let value = stripped[1..].trim().to_string();
            services[service_index].entry(&current_key).push(value);
        }
    }

    services
}

fn dockerfiles(ctx: &ReportContext<'_>) -> Vec<String> {
    let mut found: Vec<String> = ctx
        .inventory
        .files
        .iter()
        .filter(|file| {
            file_name_of(&file.relative_path)
                .to_lowercase()
                .starts_with("dockerfile")
        })
        .map(|file| file.relative_path.clone())
        .collect();
    found.sort_by_key(|path| path.to_lowercase());
    found
}

fn compose_files(ctx: &ReportContext<'_>) -> Vec<String> {
    let mut found: Vec<String> = ctx
        .inventory
        .files
        .iter()
        .filter(|file| {
            matches!(
                file_name_of(&file.relative_path).to_lowercase().as_str(),
                "docker-compose.yml" | "docker-compose.yaml" | "compose.yml" | "compose.yaml"
            )
        })
        .map(|file| file.relative_path.clone())
        .collect();
    found.sort_by_key(|path| path.to_lowercase());
    found
}

fn write_docker_report(ctx: &ReportContext<'_>, output_file: &Path) -> Result<(), ReportError> {
    let dockerfiles = dockerfiles(ctx);
    let compose_files = compose_files(ctx);

    let mut out = String::new();
    out.push_str("=== Docker / Infrastructure Report ===\n");
    out.push_str(&format!("Generated: {}\n", ctx.plan.generated_at));
    out.push_str("Compose parsing is heuristic and works best with simple YAML files.\n");
    out.push_str(&section_rule('='));
    out.push_str("\n\n");

    out.push_str("--- Dockerfiles ---\n");
    if dockerfiles.is_empty() {
        out.push_str("None detected.\n");
    } else {
        for path in &dockerfiles {
            out.push_str(path);
            out.push('\n');
        }
    }

    out.push_str("\n--- Compose files ---\n");
    if compose_files.is_empty() {
        out.push_str("None detected.\n");
    } else {
        for path in &compose_files {
            out.push_str(path);
            out.push('\n');
        }
    }

    for compose in &compose_files {
        out.push_str(&format!("\n--- Parsed services from {compose} ---\n"));
        let path = ctx.resolve(compose);
        let Some(text) = read_text_unredacted(&path, None) else {
            out.push_str("Could not read compose file.\n");
            continue;
        };
        let services = parse_compose_services(&text);
        if services.is_empty() {
            out.push_str("No services parsed.\n");
            continue;
        }
        for service in &services {
            out.push_str(&format!("\nService: {}\n", redact_line(&service.name)));
            for key in COMPOSE_KEYS {
                let Some(values) = service.get(key) else {
                    continue;
                };
                if values.is_empty() {
                    continue;
                }
                out.push_str(&format!("  {key}:\n"));
                for value in values.iter().take(SERVICE_VALUE_LIMIT) {
                    out.push_str(&format!("    - {}\n", redact_line(value)));
                }
            }
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

    const COMPOSE_FIXTURE: &str = "services:\n  web:\n    image: nginx:latest\n    ports:\n      - \"8080:80\"\n    environment:\n      - API_KEY=abcdef0123456789\n    env_file:\n      - .env\n  db:\n    image: postgres:16\n    volumes:\n      - dbdata:/var/lib/postgresql/data\nvolumes:\n  dbdata:\n";

    #[test]
    fn parses_two_services_with_environment_and_env_file() {
        let services = parse_compose_services(COMPOSE_FIXTURE);
        assert_eq!(services.len(), 2);
        assert_eq!(services[0].name, "web");
        assert_eq!(
            services[0].get("image"),
            Some(&["nginx:latest".to_string()][..])
        );
        assert_eq!(
            services[0].get("environment"),
            Some(&["API_KEY=abcdef0123456789".to_string()][..])
        );
        assert_eq!(services[0].get("env_file"), Some(&[".env".to_string()][..]));
        assert_eq!(services[1].name, "db");
        assert_eq!(
            services[1].get("volumes"),
            Some(&["dbdata:/var/lib/postgresql/data".to_string()][..])
        );
    }

    #[test]
    fn stops_parsing_once_a_top_level_key_follows_services() {
        let text = "services:\n  web:\n    image: nginx\nvolumes:\n  dbdata:\n    driver: local\n";
        let services = parse_compose_services(text);
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].name, "web");
    }

    #[test]
    fn malformed_compose_text_yields_no_services_without_panicking() {
        let garbage = "not: yaml: at: all\n\t\tbroken indentation\n===";
        let services = parse_compose_services(garbage);
        assert!(services.is_empty());
    }

    #[test]
    fn report_lists_dockerfiles_compose_files_and_redacts_environment_values() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("Dockerfile"), "FROM scratch\n").unwrap();
            std::fs::write(root.join("docker-compose.yml"), COMPOSE_FIXTURE).unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_docker_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("Dockerfile"));
        assert!(content.contains("docker-compose.yml"));
        assert!(content.contains("Service: web"));
        assert!(content.contains("Service: db"));
        assert!(!content.contains("abcdef0123456789"));
        assert!(content.contains("<REDACTED>"));
    }

    #[test]
    fn reports_none_detected_when_no_docker_files_exist() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("main.py"), "x = 1\n").unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_docker_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("--- Dockerfiles ---\nNone detected."));
        assert!(content.contains("--- Compose files ---\nNone detected."));
    }
}
