//! The vendor-neutral surface every provider implements.
//!
//! Nothing in this module names a vendor. That is the point: the owner chose to ship
//! one provider now with the abstraction in place, so a second arrives as a new module
//! under `providers/` rather than as a rewrite of everything that calls this.
//!
//! The surface is deliberately narrow — one question, one answer. Streaming, tool use,
//! and multi-turn state are all real provider features and all absent here, because
//! S13's agreed scope is a single exchange. A trait that guessed at those would be a
//! trait shaped by imagination rather than by a caller.

use codepack_ai::error::AiError;

/// What gets sent. Assembled by [`crate::plan`] from a bundle the user has already
/// exported and confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiRequest {
    /// The model identifier, exactly as the provider spells it. Not an enum: a provider
    /// ships new models far more often than this crate ships releases, and an enum would
    /// make the newest model the one thing the user cannot select.
    pub model: String,
    /// Instructions that frame the task, kept separate from the material so a provider
    /// that has a dedicated system channel can use it.
    pub system: String,
    /// The question plus the project context, already assembled.
    pub user: String,
    /// Upper bound on the reply. A provider that cannot express this must clamp on read.
    pub max_output_tokens: u32,
}

/// What came back. No provider-specific fields: a caller that needed one would be a
/// caller the abstraction is failing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiAnswer {
    pub text: String,
    pub model: String,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    /// Set when the provider stopped for a reason the user should know about — hitting
    /// the output cap, or declining the request. `None` means it finished normally.
    pub stopped_early: Option<String>,
}

/// One AI backend.
///
/// Implementations must not log, persist, or otherwise retain the key they are given;
/// it arrives as a borrowed argument for exactly that reason, so an implementation that
/// wanted to keep one would have to say so in its own type.
pub trait AiProvider: Send + Sync {
    /// The stable identifier used in configuration and in the credential store.
    fn id(&self) -> &'static str;

    /// Human-readable name for the interface.
    fn display_name(&self) -> &'static str;

    /// Models this build knows about, most capable first. Advisory only — [`AiRequest`]
    /// carries a free-form string so a model released after this build still works.
    fn known_models(&self) -> &'static [ModelInfo];

    /// Perform one exchange. Blocking: this crate has no async runtime and the desktop
    /// calls it from a background thread.
    fn ask(&self, key: &str, request: &AiRequest) -> Result<AiAnswer, AiError>;
}

/// A model the interface can offer as a starting point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelInfo {
    pub id: &'static str,
    pub display_name: &'static str,
    /// Total context window in tokens, used to warn before a bundle that cannot fit.
    pub context_tokens: u64,
}
