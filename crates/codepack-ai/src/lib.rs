//! Stage S13 — the offline half of the AI integration.
//!
//! Claude Code and Codex already read the filesystem, so they get a prompt file next to
//! the bundle and a command to run: no network, no key, invariant I1 untouched. That is
//! all this crate does, and it is the only part either front end uses.
//!
//! ## Where the API path went
//!
//! It was the `api` feature here, on by default, and it is now `codepack-ai-api` — a
//! crate in this repository that is **excluded from the workspace**. Both front ends
//! already took this crate with `default-features = false`, so no binary ever linked a
//! transport; but a workspace member is compiled with its own defaults by
//! `cargo test --workspace`, so `keyring` and `ureq` were built on every platform for
//! code no user could reach, and on Linux `keyring` wants a Secret Service backend. A
//! dead path was obstructing the build everywhere but Windows (audit 2026-09-05 No. 26;
//! owner decision 2026-09-06, Q41).
//!
//! The consequence worth stating: **no crate in this workspace may reach the network at
//! all now.** The `network isolation` gate step used to allow exactly one exception and
//! now allows none, which is a stronger promise than invariant I1 originally made.
//!
//! Nothing here starts on its own. [`handoff::prepare`] writes one Markdown file when a
//! user asks for it.

pub mod error;
pub mod handoff;

pub use error::{AiError, Refusal};
pub use handoff::{AGENTS, Handoff, LocalAgent};
