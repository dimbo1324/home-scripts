//! API keys, and the one place they are allowed to live.
//!
//! The key goes into the OS credential store (Windows Credential Manager, macOS
//! Keychain, Linux Secret Service) and nowhere else — not `Config`, not the settings
//! file, not the SQLite history, not a log line, not an export. BLUEPRINT §D.4 states
//! that requirement and S13's own definition of done repeats it, because a key that
//! reaches a settings file is a key that reaches the next bundle the user shares.
//!
//! Nothing here returns a key to a caller that only needs to know whether one exists;
//! [`has_key`] answers that question without reading the secret, so the desktop can
//! render its status without the key ever crossing the IPC boundary.

use std::sync::Once;

use keyring::Entry;

use codepack_ai::error::AiError;

/// The credential-store service name. Stable: changing it orphans every stored key.
const SERVICE: &str = "codepack";

static STORE_READY: Once = Once::new();

/// Install the platform credential store exactly once, blocking every other caller
/// until it is there.
///
/// Works around a race in `keyring` 4.1.5. Its `Entry::new` guards initialisation with
/// a compare-exchange:
///
/// ```text
/// if SET_CREDENTIAL_STORE.compare_exchange(false, true, ..) == Ok(false) {
///     set_credential_store()?
/// }
/// let inner = keyring_core::Entry::new(..)?;
/// ```
///
/// The thread that wins the exchange installs the store. Every thread that *loses* falls
/// straight through to `keyring_core::Entry::new` **without waiting**, and sees
/// `NoDefaultStore`. Two concurrent first calls are enough — which the desktop can
/// easily produce, since reading the key and rendering its status are separate actions.
/// Reproduced here as a roughly one-in-five test failure before this guard existed.
///
/// `Once::call_once` gives the guarantee the atomic flag does not: the losing threads
/// block until initialisation has finished.
fn ensure_store() {
    STORE_READY.call_once(|| {
        // Constructing an entry is what installs the store; this one is never used and
        // touches no credential.
        let _ = Entry::new(SERVICE, "store-initialisation");
    });
}

fn entry(provider: &str) -> Result<Entry, AiError> {
    ensure_store();
    Entry::new(SERVICE, provider).map_err(|error| AiError::KeyStore {
        message: error.to_string(),
    })
}

/// Store `key` for `provider`, replacing any existing one.
pub fn store_key(provider: &str, key: &str) -> Result<(), AiError> {
    entry(provider)?
        .set_password(key)
        .map_err(|error| AiError::KeyStore {
            message: error.to_string(),
        })
}

/// Read the stored key. Callers should hold it as briefly as possible and must never
/// place it in a struct that is serialized.
pub fn load_key(provider: &str) -> Result<String, AiError> {
    match entry(provider)?.get_password() {
        Ok(key) => Ok(key),
        Err(keyring::Error::NoEntry) => Err(AiError::NoKey {
            provider: provider.to_string(),
        }),
        Err(error) => Err(AiError::KeyStore {
            message: error.to_string(),
        }),
    }
}

/// Whether a key is stored, without reading it.
///
/// A store failure reads as "no key": the caller uses this to decide whether to offer
/// the send button, and a broken credential store means the send cannot work anyway.
/// Reporting the failure here instead would put an OS-level diagnostic in front of a
/// user who has not asked for anything yet.
pub fn has_key(provider: &str) -> bool {
    // Reuses `load_key` rather than re-deriving the "is it there" question, so the two
    // can never disagree about what counts as a stored key.
    load_key(provider).is_ok()
}

/// Remove the stored key. Deleting one that is not there is success, not an error —
/// the caller asked for a state, and that state is what it gets.
pub fn clear_key(provider: &str) -> Result<(), AiError> {
    match entry(provider)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(AiError::KeyStore {
            message: error.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A provider name unique to one test.
    ///
    /// These tests touch the **real** credential store, which is machine-global shared
    /// state, and cargo runs them in parallel. Sharing one name made them race: a test
    /// asserting "no key is present" could run between another's store and clear, and
    /// the suite passed or failed depending on scheduling. A flaky security test is
    /// worse than no test, because it teaches everyone to re-run the gate.
    ///
    /// The process id keeps concurrent `cargo test` invocations apart too.
    fn test_provider(case: &str) -> String {
        format!("codepack-test-do-not-use-{}-{case}", std::process::id())
    }

    #[test]
    fn a_missing_key_is_reported_as_missing_rather_than_as_a_store_failure() {
        let provider = test_provider("missing");
        let _ = clear_key(&provider);

        let Err(error) = load_key(&provider) else {
            panic!("a key that was never stored must not load");
        };
        assert!(
            matches!(error, AiError::NoKey { .. }),
            "expected NoKey, got {error:?}"
        );
        assert!(!has_key(&provider));
    }

    #[test]
    fn clearing_a_key_that_is_not_there_succeeds() {
        // Asking for a state the store is already in is success, not an error.
        assert!(clear_key(&test_provider("clear-absent")).is_ok());
    }

    #[test]
    fn a_stored_key_round_trips_and_can_be_removed() {
        // Skipped rather than failed where no credential store is reachable (a headless
        // CI container). A test that cannot run is not a test that failed, and pretending
        // otherwise would make the gate lie.
        let provider = test_provider("round-trip");
        if store_key(&provider, "test-value").is_err() {
            return;
        }
        assert_eq!(load_key(&provider).unwrap(), "test-value");
        assert!(has_key(&provider));

        clear_key(&provider).unwrap();
        assert!(!has_key(&provider));
    }
}
