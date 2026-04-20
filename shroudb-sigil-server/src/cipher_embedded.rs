//! Embedded CipherOps adapter for the standalone Sigil server.
//!
//! When `[cipher] mode = "embedded"` is set, Sigil runs an in-process
//! `CipherEngine` on the same `StorageEngine` (distinct namespace) and
//! implements `CipherOps` by calling it directly — no separate Cipher
//! deployment required.
//!
//! Mirrors the `EmbeddedCipherOps` adapter Moat uses when Cipher is
//! co-located. Standalone Sigil now supports the same posture so
//! single-node deploys don't have to run a Cipher sidecar.

use std::sync::Arc;

use shroudb_cipher_engine::engine::CipherEngine;
use shroudb_sigil_core::error::SigilError;
use shroudb_sigil_engine::capabilities::CipherOps;
use shroudb_store::Store;

type BoxFut<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, SigilError>> + Send + 'a>>;

pub struct EmbeddedCipherOps<S: Store> {
    engine: Arc<CipherEngine<S>>,
    keyring: String,
}

impl<S: Store> EmbeddedCipherOps<S> {
    pub fn new(engine: Arc<CipherEngine<S>>, keyring: impl Into<String>) -> Self {
        Self {
            engine,
            keyring: keyring.into(),
        }
    }
}

impl<S: Store + 'static> CipherOps for EmbeddedCipherOps<S> {
    fn encrypt(&self, plaintext: &[u8], context: Option<&str>, _actor: &str) -> BoxFut<'_, String> {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(plaintext);
        let ctx = context.map(|s| s.to_string());
        Box::pin(async move {
            let result = self
                .engine
                .encrypt(&self.keyring, &b64, ctx.as_deref(), None, false)
                .await
                .map_err(|e| SigilError::Internal(format!("cipher encrypt: {e}")))?;
            Ok(result.ciphertext)
        })
    }

    fn decrypt(
        &self,
        ciphertext: &str,
        context: Option<&str>,
        _actor: &str,
    ) -> BoxFut<'_, shroudb_crypto::SensitiveBytes> {
        let ct = ciphertext.to_string();
        let ctx = context.map(|s| s.to_string());
        Box::pin(async move {
            let result = self
                .engine
                .decrypt(&self.keyring, &ct, ctx.as_deref())
                .await
                .map_err(|e| SigilError::Internal(format!("cipher decrypt: {e}")))?;
            Ok(shroudb_crypto::SensitiveBytes::new(
                result.plaintext.into_vec(),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shroudb_cipher_core::keyring::KeyringAlgorithm;
    use shroudb_cipher_engine::engine::CipherConfig;
    use shroudb_cipher_engine::keyring_manager::KeyringCreateOpts;
    use shroudb_server_bootstrap::Capability;

    async fn build_ops() -> EmbeddedCipherOps<shroudb_storage::EmbeddedStore> {
        let store =
            shroudb_storage::test_util::create_test_store("sigil-cipher-embedded-test").await;
        let engine = CipherEngine::new(
            store,
            CipherConfig::default(),
            Capability::DisabledForTests,
            Capability::DisabledForTests,
        )
        .await
        .expect("cipher engine init");
        engine
            .keyring_manager()
            .create(
                "sigil-pii",
                KeyringAlgorithm::Aes256Gcm,
                KeyringCreateOpts::default(),
            )
            .await
            .expect("create keyring");
        EmbeddedCipherOps::new(Arc::new(engine), "sigil-pii")
    }

    #[tokio::test]
    async fn encrypt_decrypt_round_trip_preserves_plaintext() {
        let ops = build_ops().await;
        let plaintext = b"alice@example.com";
        let ciphertext = ops
            .encrypt(plaintext, Some("user:1"), "test-actor")
            .await
            .expect("encrypt");
        let decrypted = ops
            .decrypt(&ciphertext, Some("user:1"), "test-actor")
            .await
            .expect("decrypt");
        assert_eq!(decrypted.as_bytes(), plaintext);
    }

    #[tokio::test]
    async fn decrypt_fails_on_wrong_context() {
        let ops = build_ops().await;
        let ciphertext = ops
            .encrypt(b"secret", Some("user:1"), "test-actor")
            .await
            .expect("encrypt");
        let result = ops.decrypt(&ciphertext, Some("user:2"), "test-actor").await;
        assert!(
            result.is_err(),
            "wrong AAD context must fail-closed — Cipher binds context into the GCM tag"
        );
    }
}
