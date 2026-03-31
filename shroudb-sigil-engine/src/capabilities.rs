use std::sync::Arc;

use shroudb_acl::PolicyEvaluator;
use shroudb_crypto::SensitiveBytes;
use shroudb_sigil_core::error::SigilError;

/// Shorthand for a pinned boxed future.
type BoxFut<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, SigilError>> + Send + 'a>>;

/// Trait for Cipher operations (encrypt/decrypt PII fields).
pub trait CipherOps: Send + Sync {
    fn encrypt(&self, plaintext: &[u8], context: Option<&str>) -> BoxFut<'_, String>;
    fn decrypt(&self, ciphertext: &str, context: Option<&str>) -> BoxFut<'_, SensitiveBytes>;
}

/// Trait for Veil operations (blind index for searchable encrypted fields).
pub trait VeilOps: Send + Sync {
    fn put(&self, entry_id: &str, plaintext: &[u8], field: Option<&str>) -> BoxFut<'_, ()>;
    fn delete(&self, entry_id: &str) -> BoxFut<'_, ()>;
    fn search(
        &self,
        query: &str,
        field: Option<&str>,
        limit: Option<usize>,
    ) -> BoxFut<'_, Vec<(String, f64)>>;
}

/// Trait for Keep operations (versioned secret storage).
///
/// Secrets are stored under a path string and versioned automatically.
/// Values are raw bytes (base64 encoding handled internally).
///
/// Sigil is an opaque envelope store — it never reads secrets back.
/// Applications retrieve secrets via Keep or Courier directly.
pub trait KeepOps: Send + Sync {
    fn store_secret(&self, path: &str, value: &[u8]) -> BoxFut<'_, u64>;
    fn delete_secret(&self, path: &str) -> BoxFut<'_, ()>;
}

/// Engine capabilities provided at construction time.
///
/// In standalone mode: built from config (remote endpoints or absent).
/// In Moat mode: populated with engine instances directly — no probing, no races.
#[derive(Default)]
pub struct Capabilities {
    pub cipher: Option<Box<dyn CipherOps>>,
    pub veil: Option<Box<dyn VeilOps>>,
    pub keep: Option<Box<dyn KeepOps>>,
    pub sentry: Option<Arc<dyn PolicyEvaluator>>,
}
