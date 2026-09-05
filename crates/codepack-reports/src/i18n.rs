//! A minimal RU/EN string-table pilot for report localization (BLUEPRINT §B.6),
//! applied to exactly one report this pass — `01_summary.txt`
//! (`crate::reports::summary`) — per the stage plan's explicit one-report scope.
//! Every other report in this crate stays English-only; extending the table to more
//! reports is future scope, recorded honestly rather than silently deferred (see
//! `task-checklist.md`).
//!
//! Wired since 2026-09-05 to `Config::artifact_language`, a field of its own — see
//! [`Language::from_config`]. The note below explains why it is not
//! `Config::language`, and still applies.
//!
//! This is deliberately **not** wired to `codepack_core::config::Config::language`:
//! that field is the *interface* language (BLUEPRINT §A.10), while BLUEPRINT §B.6
//! asks for a separate "artifact language" choice that does not exist as a `Config`
//! field yet. Wiring this pilot to the UI language field would also silently flip
//! `Config::default()`'s report output to Russian (its default is `"ru"`), which would
//! break every existing English-content assertion across Groups A-E without a
//! deliberate decision to do so. The mechanism is proven directly against
//! [`Language`] instead; wiring a real, dedicated "artifact language" setting through
//! is deferred honestly to a later pass, not invented here.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    En,
    Ru,
}

impl Language {
    /// The language a run's artifacts are written in, from
    /// `Config::artifact_language`.
    ///
    /// Anything this build does not recognise means English rather than an error: an
    /// unknown language code in a settings file should degrade to the language every
    /// report already has, not stop an export.
    pub fn from_config(config: &codepack_core::config::Config) -> Self {
        match config.artifact_language.trim().to_lowercase().as_str() {
            "ru" => Language::Ru,
            _ => Language::En,
        }
    }

    /// Picks `en` or `ru` depending on `self` — the whole mechanism, deliberately
    /// this small: a hand-written string table beats a templating dependency for a
    /// one-report pilot (per the stage plan's recommendation).
    pub fn pick(self, en: &'static str, ru: &'static str) -> &'static str {
        match self {
            Language::En => en,
            Language::Ru => ru,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with(artifact_language: &str) -> codepack_core::config::Config {
        codepack_core::config::Config {
            artifact_language: artifact_language.to_string(),
            ..codepack_core::config::Config::default()
        }
    }

    #[test]
    fn the_default_configuration_keeps_reports_in_english() {
        // Every release so far wrote English, and a new setting must not change what an
        // existing installation produces.
        let config = codepack_core::config::Config::default();
        assert_eq!(Language::from_config(&config), Language::En);
    }

    #[test]
    fn the_artifact_language_is_read_and_not_the_interface_language() {
        let mut config = config_with("ru");
        // The interface language is deliberately the opposite, so a reader of this test
        // can see which field is being consulted.
        config.language = "en".to_string();
        assert_eq!(Language::from_config(&config), Language::Ru);

        let mut other = config_with("en");
        other.language = "ru".to_string();
        assert_eq!(Language::from_config(&other), Language::En);
    }

    #[test]
    fn spelling_is_forgiving_about_case_and_padding() {
        for spelling in ["RU", " ru ", "Ru"] {
            assert_eq!(Language::from_config(&config_with(spelling)), Language::Ru);
        }
    }

    /// A language this build does not know degrades to the one every report already has,
    /// rather than stopping an export over a settings file.
    #[test]
    fn an_unknown_language_falls_back_to_english() {
        for spelling in ["de", "", "klingon"] {
            assert_eq!(Language::from_config(&config_with(spelling)), Language::En);
        }
    }

    #[test]
    fn pick_selects_the_matching_language() {
        assert_eq!(Language::En.pick("hello", "привет"), "hello");
        assert_eq!(Language::Ru.pick("hello", "привет"), "привет");
    }
}
