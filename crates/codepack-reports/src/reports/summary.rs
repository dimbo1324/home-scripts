//! `01_summary.txt`, ported from legacy
//! `reports/insights/summary.py::write_project_summary_report`.
//!
//! This is the crate's RU/EN localization pilot report (`crate::i18n`): the job entry
//! point still always renders English (unchanged from earlier passes — no existing
//! behavior or test changes), but the rendering logic is now factored through
//! [`Language`] and directly testable in both languages from the same
//! [`ReportContext`] data.

use std::path::Path;

use codepack_tokens::format_bytes;

use crate::context::{ReportContext, detect_stack};
use crate::error::ReportError;
use crate::i18n::Language;
use crate::paths::{file_name_of, looks_like_test_path};
use crate::plugin::ReportJob;
use crate::profile;
use crate::reports::layout::section_rule;

pub const JOB: ReportJob = ReportJob {
    filename: "01_summary.txt",
    profiles: profile::SUMMARY_TXT,
    description: "High-level overview: stack detection, language counts, biggest files.",
    run: write_summary_report,
};

fn write_summary_report(ctx: &ReportContext<'_>, output_file: &Path) -> Result<(), ReportError> {
    let rendered = render_summary_report(ctx, ctx.artifact_language());
    std::fs::write(output_file, rendered).map_err(|source| ReportError::Write {
        path: output_file.to_path_buf(),
        source,
    })
}

fn render_summary_report(ctx: &ReportContext<'_>, language: Language) -> String {
    let inventory = ctx.inventory;
    let stack = detect_stack(&ctx.staging_root, inventory);

    let readmes = inventory
        .files
        .iter()
        .filter(|file| {
            file_name_of(&file.relative_path)
                .to_lowercase()
                .starts_with("readme")
        })
        .count();
    let licenses = inventory
        .files
        .iter()
        .filter(|file| {
            file_name_of(&file.relative_path)
                .to_lowercase()
                .starts_with("license")
        })
        .count();
    let env_files = inventory
        .files
        .iter()
        .filter(|file| {
            file_name_of(&file.relative_path)
                .to_lowercase()
                .starts_with(".env")
        })
        .count();
    let test_files = inventory
        .files
        .iter()
        .filter(|file| looks_like_test_path(&file.relative_path))
        .count();
    let docker_files = inventory
        .files
        .iter()
        .filter(|file| {
            file_name_of(&file.relative_path)
                .to_lowercase()
                .starts_with("dockerfile")
        })
        .count();
    let compose_files = inventory
        .files
        .iter()
        .filter(|file| {
            matches!(
                file_name_of(&file.relative_path).to_lowercase().as_str(),
                "docker-compose.yml" | "docker-compose.yaml" | "compose.yml" | "compose.yaml"
            )
        })
        .count();
    let ci_files = inventory
        .files
        .iter()
        .filter(|file| {
            let forward = file.relative_path.replace('\\', "/");
            forward.starts_with(".github/workflows/")
                && (forward.ends_with(".yml") || forward.ends_with(".yaml"))
        })
        .count();

    let mut sorted_by_size: Vec<&crate::context::InventoryFile> = inventory.files.iter().collect();
    sorted_by_size.sort_by_key(|file| std::cmp::Reverse(file.size));

    let yes = language.pick("yes", "да");
    let no = language.pick("no", "нет");
    let not_detected = language.pick("not detected", "не обнаружено");

    let mut out = String::new();
    out.push_str(language.pick("=== Project Summary ===\n", "=== Сводка проекта ===\n"));
    out.push_str(&format!(
        "{}: {}\n",
        language.pick("Generated", "Сформировано"),
        ctx.plan.generated_at
    ));
    out.push_str(&section_rule('='));
    out.push_str("\n\n");

    out.push_str(&format!(
        "{:<32}: {}\n",
        language.pick("Source root", "Исходный корень"),
        ctx.disclosed_source_root()
    ));
    out.push_str(&format!(
        "{:<32}: {}\n",
        language.pick("Copied project root", "Скопированный корень"),
        ctx.disclosed_staging_root()
    ));
    out.push_str(&format!(
        "{:<32}: {}\n",
        language.pick("Project name", "Имя проекта"),
        ctx.staging_root
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    ));
    out.push_str(&format!(
        "{:<32}: {}\n",
        language.pick("Total files", "Всего файлов"),
        inventory.files.len()
    ));
    out.push_str(&format!(
        "{:<32}: {}\n",
        language.pick("Total folders", "Всего папок"),
        inventory.total_dirs
    ));
    out.push_str(&format!(
        "{:<32}: {}\n",
        language.pick("Total copied size", "Общий скопированный размер"),
        format_bytes(inventory.total_size)
    ));
    out.push_str(&format!(
        "{:<32}: {}\n",
        language.pick("README present", "Файл README"),
        if readmes > 0 { yes } else { no }
    ));
    out.push_str(&format!(
        "{:<32}: {}\n",
        language.pick("LICENSE present", "Файл LICENSE"),
        if licenses > 0 { yes } else { no }
    ));
    out.push_str(&format!(
        "{:<32}: {}\n",
        language.pick("Tests detected", "Обнаружены тесты"),
        if test_files > 0 {
            format!("{yes} ({test_files} {})", language.pick("files", "файлов"))
        } else {
            no.to_string()
        }
    ));
    out.push_str(&format!(
        "{:<32}: {}\n",
        language.pick("Docker detected", "Обнаружен Docker"),
        if docker_files > 0 || compose_files > 0 {
            yes
        } else {
            no
        }
    ));
    out.push_str(&format!(
        "{:<32}: {}\n",
        language.pick("CI/CD detected", "Обнаружен CI/CD"),
        if ci_files > 0 {
            format!(
                "{yes} ({ci_files} {})",
                language.pick("GitHub Actions workflows", "workflow-файлов GitHub Actions")
            )
        } else {
            no.to_string()
        }
    ));
    out.push_str(&format!(
        "{:<32}: {}\n",
        language.pick(".env-like files", "Файлов вида .env"),
        env_files
    ));

    out.push_str(language.pick(
        "\n--- Detected stack ---\n",
        "\n--- Обнаруженный стек ---\n",
    ));
    for (group, values) in [
        ("frontend", &stack.frontend),
        ("backend", &stack.backend),
        ("tools", &stack.tools),
        ("testing", &stack.testing),
        ("styling", &stack.styling),
        ("infrastructure", &stack.infrastructure),
        ("package_managers", &stack.package_managers),
    ] {
        let joined = if values.is_empty() {
            not_detected.to_string()
        } else {
            values.join(", ")
        };
        out.push_str(&format!("{group}: {joined}\n"));
    }

    out.push_str(language.pick(
        "\n--- Detected languages by file count ---\n",
        "\n--- Обнаруженные языки по числу файлов ---\n",
    ));
    if inventory.by_language.is_empty() {
        out.push_str(language.pick(
            "No known language extensions detected.\n",
            "Известные расширения языков не обнаружены.\n",
        ));
    } else {
        for stat in inventory.by_language.iter().take(30) {
            out.push_str(&format!(
                "{:<28} {:>8} {}   {:>12}\n",
                stat.language,
                stat.count,
                language.pick("files", "файлов"),
                format_bytes(stat.total_size)
            ));
        }
    }

    out.push_str(language.pick(
        "\n--- Largest files ---\n",
        "\n--- Самые большие файлы ---\n",
    ));
    for file in sorted_by_size.iter().take(15) {
        out.push_str(&format!(
            "{:>12}  {}\n",
            format_bytes(file.size),
            file.relative_path
        ));
    }

    out.push_str(language.pick(
        "\n--- Useful next checks ---\n",
        "\n--- Полезные следующие шаги ---\n",
    ));
    if readmes == 0 {
        out.push_str(language.pick(
            "- Add or update README with setup/run instructions.\n",
            "- Добавьте или обновите README с инструкциями по установке и запуску.\n",
        ));
    }
    if licenses == 0 {
        out.push_str(language.pick(
            "- Add LICENSE if this project will be shared externally.\n",
            "- Добавьте LICENSE, если проект будет передан за пределы команды.\n",
        ));
    }
    if env_files > 0 {
        out.push_str(language.pick(
            "- Review .env-like files before sharing the export.\n",
            "- Проверьте файлы вида .env перед передачей экспорта.\n",
        ));
    }
    if test_files == 0 {
        out.push_str(language.pick(
            "- No obvious test files found; consider adding smoke/unit tests.\n",
            "- Явных тестовых файлов не найдено; рассмотрите добавление smoke/unit-тестов.\n",
        ));
    }
    if ci_files == 0 {
        out.push_str(language.pick(
            "- No GitHub Actions workflow detected; consider adding CI for checks.\n",
            "- Workflow GitHub Actions не обнаружен; рассмотрите добавление CI для проверок.\n",
        ));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::Fixture;

    #[test]
    fn writes_stack_language_and_largest_files_sections() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("main.py"), "print('hi')\n").unwrap();
            std::fs::write(root.join("README.md"), "# hi\n").unwrap();
            std::fs::write(
                root.join("package.json"),
                r#"{"dependencies": {"react": "18.0.0"}}"#,
            )
            .unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_summary_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.starts_with("=== Project Summary ==="));
        assert!(content.contains("README present"));
        assert!(content.contains("frontend: React"));
        assert!(content.contains("--- Largest files ---"));
        assert!(content.contains("Python"));
    }

    #[test]
    fn reports_no_readme_and_no_tests_hints_when_absent() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("main.py"), "print('hi')\n").unwrap();
        });
        let ctx = fixture.context("full");
        let out_dir = tempfile::tempdir().unwrap();
        let output_file = out_dir.path().join(JOB.filename);

        write_summary_report(&ctx, &output_file).unwrap();

        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("Add or update README"));
        assert!(content.contains("No obvious test files found"));
    }

    #[test]
    fn renders_the_same_underlying_data_in_english_and_russian() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("main.py"), "print('hi')\n").unwrap();
            std::fs::write(
                root.join("package.json"),
                r#"{"dependencies": {"react": "18.0.0"}}"#,
            )
            .unwrap();
        });
        let ctx = fixture.context("full");

        let english = render_summary_report(&ctx, Language::En);
        let russian = render_summary_report(&ctx, Language::Ru);

        assert!(english.starts_with("=== Project Summary ==="));
        assert!(english.contains("README present"));
        assert!(english.contains("frontend: React"));
        assert!(english.contains("not detected"));

        assert!(russian.starts_with("=== Сводка проекта ==="));
        assert!(russian.contains("Файл README"));
        assert!(russian.contains("frontend: React"));
        assert!(russian.contains("не обнаружено"));

        // Same underlying data drives both: the file count line must agree exactly.
        let file_count = ctx.inventory.files.len().to_string();
        let english_count_line = english
            .lines()
            .find(|line| line.starts_with("Total files"))
            .unwrap();
        let russian_count_line = russian
            .lines()
            .find(|line| line.starts_with("Всего файлов"))
            .unwrap();
        assert!(english_count_line.trim_end().ends_with(&file_count));
        assert!(russian_count_line.trim_end().ends_with(&file_count));
    }
}
