//! Embedded KeepOps adapter for the standalone Sigil server.
//!
//! When `[keep] mode = "embedded"` is set, Sigil runs an in-process
//! `KeepEngine` on the same `StorageEngine` (distinct namespace) and
//! implements `KeepOps` by calling it directly.

use std::sync::Arc;

use shroudb_keep_engine::engine::KeepEngine;
use shroudb_sigil_core::error::SigilError;
use shroudb_sigil_engine::capabilities::KeepOps;
use shroudb_store::Store;

type BoxFut<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, SigilError>> + Send + 'a>>;

pub struct EmbeddedKeepOps<S: Store> {
    engine: Arc<KeepEngine<S>>,
}

impl<S: Store> EmbeddedKeepOps<S> {
    pub fn new(engine: Arc<KeepEngine<S>>) -> Self {
        Self { engine }
    }
}

impl<S: Store + 'static> KeepOps for EmbeddedKeepOps<S> {
    fn store_secret(&self, path: &str, value: &[u8]) -> BoxFut<'_, u64> {
        use base64::Engine as _;
        let p = path.to_string();
        let b64 = base64::engine::general_purpose::STANDARD.encode(value);
        Box::pin(async move {
            let result = self
                .engine
                .put(&p, &b64, None)
                .await
                .map_err(|e| SigilError::Internal(format!("keep put: {e}")))?;
            Ok(result.version as u64)
        })
    }

    fn delete_secret(&self, path: &str) -> BoxFut<'_, ()> {
        let p = path.to_string();
        Box::pin(async move {
            self.engine
                .delete(&p, None)
                .await
                .map_err(|e| SigilError::Internal(format!("keep delete: {e}")))?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shroudb_crypto::SecretBytes;
    use shroudb_keep_engine::engine::KeepConfig;
    use shroudb_server_bootstrap::Capability;

    fn test_master_key() -> SecretBytes {
        SecretBytes::new(vec![0x42u8; 32])
    }

    async fn build_ops() -> EmbeddedKeepOps<shroudb_storage::EmbeddedStore> {
        let store = shroudb_storage::test_util::create_test_store("sigil-keep-embedded-test").await;
        let engine = KeepEngine::new(
            store,
            KeepConfig::default(),
            test_master_key(),
            Capability::DisabledForTests,
            Capability::DisabledForTests,
        )
        .await
        .expect("keep engine init");
        EmbeddedKeepOps::new(Arc::new(engine))
    }

    #[tokio::test]
    async fn store_secret_returns_incrementing_version() {
        let ops = build_ops().await;
        let v1 = ops
            .store_secret("users/1/api-key", b"secret-v1")
            .await
            .expect("store v1");
        let v2 = ops
            .store_secret("users/1/api-key", b"secret-v2")
            .await
            .expect("store v2");
        assert_eq!(v1, 1);
        assert_eq!(v2, 2, "put at same path bumps version");
    }

    #[tokio::test]
    async fn delete_secret_removes_path() {
        let ops = build_ops().await;
        ops.store_secret("users/1/api-key", b"secret")
            .await
            .unwrap();
        ops.delete_secret("users/1/api-key")
            .await
            .expect("delete succeeds");
    }
}
