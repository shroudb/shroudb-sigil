use std::sync::Arc;

use shroudb_acl::PolicyEvaluator;
use shroudb_chronicle_core::ops::ChronicleOps;
use shroudb_crypto::SensitiveBytes;
use shroudb_server_bootstrap::Capability;
use shroudb_sigil_core::error::SigilError;

/// Shorthand for a pinned boxed future.
type BoxFut<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, SigilError>> + Send + 'a>>;

/// Trait for Cipher operations (encrypt/decrypt PII fields).
///
/// `actor` identifies the caller responsible for the operation so the
/// underlying Cipher audit trail is attributable. Sigil's
/// `CallerContext` threads the end-user actor through envelope writes;
/// system operations (background reconciliation, startup provisioning)
/// pass a stable sentinel. Never pass an empty string.
pub trait CipherOps: Send + Sync {
    fn encrypt(&self, plaintext: &[u8], context: Option<&str>, actor: &str) -> BoxFut<'_, String>;
    fn decrypt(
        &self,
        ciphertext: &str,
        context: Option<&str>,
        actor: &str,
    ) -> BoxFut<'_, SensitiveBytes>;
}

/// Trait for Veil operations (blind index for searchable encrypted fields).
///
/// `actor` identifies the caller responsible for the operation so the
/// underlying Veil audit trail is attributable. Same convention as
/// `CipherOps`.
pub trait VeilOps: Send + Sync {
    /// Store blind tokens for an entry.
    ///
    /// When `blind` is false: `data` is plaintext — Veil tokenizes and blinds server-side.
    /// When `blind` is true: `data` is a base64-encoded BlindTokenSet JSON — Veil stores directly.
    fn put(
        &self,
        entry_id: &str,
        data: &[u8],
        field: Option<&str>,
        blind: bool,
        actor: &str,
    ) -> BoxFut<'_, ()>;
    fn delete(&self, entry_id: &str, actor: &str) -> BoxFut<'_, ()>;
    /// Search a blind index.
    ///
    /// When `blind` is false: `query` is plain text — Veil tokenizes and blinds server-side.
    /// When `blind` is true: `query` is a base64-encoded BlindTokenSet JSON.
    fn search(
        &self,
        query: &str,
        field: Option<&str>,
        limit: Option<usize>,
        blind: bool,
        actor: &str,
    ) -> BoxFut<'_, Vec<(String, f64)>>;
}

/// Trait for Keep operations (versioned secret storage).
///
/// Secrets are stored under a path string and versioned automatically.
/// Values are raw bytes (base64 encoding handled internally).
///
/// Sigil is an opaque envelope store — it never reads secrets back.
/// Applications retrieve secrets via Keep or Courier directly.
///
/// `actor` identifies the caller responsible for the operation so the
/// underlying Keep audit trail is attributable.
pub trait KeepOps: Send + Sync {
    fn store_secret(&self, path: &str, value: &[u8], actor: &str) -> BoxFut<'_, u64>;
    fn delete_secret(&self, path: &str, actor: &str) -> BoxFut<'_, ()>;
}

/// Engine capabilities provided at construction time.
///
/// Every slot is a [`Capability<T>`] — the explicit tri-state from
/// `shroudb-server-bootstrap`. *Absence is never silent.* Callers must
/// pick `Enabled`, `DisabledForTests`, or `DisabledWithJustification`.
pub struct Capabilities {
    pub cipher: Capability<Box<dyn CipherOps>>,
    pub veil: Capability<Box<dyn VeilOps>>,
    pub keep: Capability<Box<dyn KeepOps>>,
    pub sentry: Capability<Arc<dyn PolicyEvaluator>>,
    pub chronicle: Capability<Arc<dyn ChronicleOps>>,
}

impl Capabilities {
    /// Construct for unit tests — every slot `DisabledForTests`. Never
    /// use in production code.
    pub fn for_tests() -> Self {
        Self {
            cipher: Capability::DisabledForTests,
            veil: Capability::DisabledForTests,
            keep: Capability::DisabledForTests,
            sentry: Capability::DisabledForTests,
            chronicle: Capability::DisabledForTests,
        }
    }

    /// Construct with explicit values for every slot. Standalone
    /// servers should build each `Capability<...>` from config (via
    /// `shroudb-engine-bootstrap` resolvers for audit/policy + remote
    /// clients for cipher/veil/keep).
    pub fn new(
        cipher: Capability<Box<dyn CipherOps>>,
        veil: Capability<Box<dyn VeilOps>>,
        keep: Capability<Box<dyn KeepOps>>,
        sentry: Capability<Arc<dyn PolicyEvaluator>>,
        chronicle: Capability<Arc<dyn ChronicleOps>>,
    ) -> Self {
        Self {
            cipher,
            veil,
            keep,
            sentry,
            chronicle,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_tests_initializes_all_slots_disabled_for_tests() {
        let caps = Capabilities::for_tests();
        assert!(!caps.cipher.is_enabled());
        assert!(!caps.veil.is_enabled());
        assert!(!caps.keep.is_enabled());
        assert!(!caps.sentry.is_enabled());
        assert!(!caps.chronicle.is_enabled());
    }

    #[test]
    fn new_accepts_explicit_capability_values() {
        let caps = Capabilities::new(
            Capability::DisabledForTests,
            Capability::DisabledForTests,
            Capability::DisabledForTests,
            Capability::DisabledForTests,
            Capability::DisabledForTests,
        );
        assert!(!caps.cipher.is_enabled());
    }
}
