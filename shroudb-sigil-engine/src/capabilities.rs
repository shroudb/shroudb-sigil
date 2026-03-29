use shroudb_sigil_core::error::SigilError;

/// Trait for Cipher operations (encrypt/decrypt PII fields).
///
/// Encrypt takes raw plaintext bytes and an optional AAD context string.
/// Returns a ciphertext envelope string (with embedded key version).
///
/// Decrypt takes the ciphertext envelope string and the same context.
/// Returns the original plaintext bytes.
pub trait CipherOps: Send + Sync {
    fn encrypt(
        &self,
        plaintext: &[u8],
        context: Option<&str>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, SigilError>> + Send + '_>>;

    fn decrypt(
        &self,
        ciphertext: &str,
        context: Option<&str>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, SigilError>> + Send + '_>>;
}

/// Trait for Veil operations (blind index for searchable encrypted fields).
pub trait VeilOps: Send + Sync {
    fn index(
        &self,
        plaintext: &[u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, SigilError>> + Send + '_>>;
}

/// Trait for Keep operations (versioned secret storage).
pub trait KeepOps: Send + Sync {
    fn store_secret(
        &self,
        key: &[u8],
        value: &[u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<u64, SigilError>> + Send + '_>>;

    fn get_secret(
        &self,
        key: &[u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, SigilError>> + Send + '_>>;
}

/// Trait for Sentry operations (post-verify authorization enrichment).
pub trait SentryOps: Send + Sync {
    fn evaluate(
        &self,
        user_id: &str,
        context: &serde_json::Value,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<serde_json::Value, SigilError>> + Send + '_>,
    >;
}

/// Engine capabilities provided at construction time.
///
/// In standalone mode: built from config (remote endpoints or absent).
/// In Moat mode: populated with engine instances directly — no probing, no races.
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
