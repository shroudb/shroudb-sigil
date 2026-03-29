use shroudb_sigil_core::error::SigilError;

/// Shorthand for a pinned boxed future.
type BoxFut<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, SigilError>> + Send + 'a>>;

/// Trait for Cipher operations (encrypt/decrypt PII fields).
pub trait CipherOps: Send + Sync {
    fn encrypt(&self, plaintext: &[u8], context: Option<&str>) -> BoxFut<'_, String>;
    fn decrypt(&self, ciphertext: &str, context: Option<&str>) -> BoxFut<'_, Vec<u8>>;
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
pub trait KeepOps: Send + Sync {
    fn store_secret(&self, key: &[u8], value: &[u8]) -> BoxFut<'_, u64>;
    fn get_secret(&self, key: &[u8]) -> BoxFut<'_, Vec<u8>>;
}

/// Trait for Sentry operations (post-verify authorization enrichment).
pub trait SentryOps: Send + Sync {
    fn evaluate(&self, user_id: &str, context: &serde_json::Value)
    -> BoxFut<'_, serde_json::Value>;
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
    pub sentry: Option<Box<dyn SentryOps>>,
}

impl Capabilities {
    pub fn has_cipher(&self) -> bool {
        self.cipher.is_some()
    }

    pub fn has_veil(&self) -> bool {
        self.veil.is_some()
    }

    pub fn has_keep(&self) -> bool {
        self.keep.is_some()
    }

    pub fn has_sentry(&self) -> bool {
        self.sentry.is_some()
    }
}
