use std::future::Future;
use std::pin::Pin;

use deadpool::managed::{self, Manager, Metrics, RecycleResult};
use shroudb_cipher_client::CipherClient;

use crate::capabilities::CipherOps;
use shroudb_sigil_core::error::SigilError;

const DEFAULT_POOL_SIZE: usize = 8;

struct CipherConnManager {
    addr: String,
    auth_token: Option<String>,
}

impl Manager for CipherConnManager {
    type Type = CipherClient;
    type Error = SigilError;

    async fn create(&self) -> Result<CipherClient, SigilError> {
        let mut client = CipherClient::connect(&self.addr)
            .await
            .map_err(|e| SigilError::Internal(format!("cipher connect failed: {e}")))?;
        if let Some(ref token) = self.auth_token {
            client
                .auth(token)
                .await
                .map_err(|e| SigilError::Internal(format!("cipher auth failed: {e}")))?;
        }
        Ok(client)
    }

    async fn recycle(
        &self,
        _client: &mut CipherClient,
        _metrics: &Metrics,
    ) -> RecycleResult<SigilError> {
        // CipherClient has no ping/health method — assume the connection is
        // alive and let the pool create a fresh one if the next operation fails.
        Ok(())
    }
}

type CipherPool = managed::Pool<CipherConnManager>;

/// CipherOps implementation backed by a remote Cipher server via TCP.
///
/// Maintains a connection pool to avoid per-call TCP connect + authenticate overhead.
pub struct RemoteCipherOps {
    pool: CipherPool,
    keyring: String,
}

impl RemoteCipherOps {
    /// Connect to a Cipher server and verify connectivity.
    ///
    /// Establishes an initial connection to validate the address and auth
    /// token, then builds a pool for subsequent requests.
    pub async fn connect(
        addr: &str,
        keyring: String,
        auth_token: Option<&str>,
        pool_size: Option<usize>,
    ) -> Result<Self, SigilError> {
        // Probe to verify connectivity before building the pool.
        let mut probe = CipherClient::connect(addr)
            .await
            .map_err(|e| SigilError::Internal(format!("cipher connect failed: {e}")))?;
        if let Some(token) = auth_token {
            probe
                .auth(token)
                .await
                .map_err(|e| SigilError::Internal(format!("cipher auth failed: {e}")))?;
        }
        drop(probe);

        let size = match pool_size {
            Some(0) | None => DEFAULT_POOL_SIZE,
            Some(n) => n,
        };

        let mgr = CipherConnManager {
            addr: addr.to_string(),
            auth_token: auth_token.map(String::from),
        };
        let pool = CipherPool::builder(mgr)
            .max_size(size)
            .build()
            .map_err(|e| SigilError::Internal(format!("cipher pool build failed: {e}")))?;

        Ok(Self { pool, keyring })
    }
}

impl CipherOps for RemoteCipherOps {
    fn encrypt(
        &self,
        plaintext: &[u8],
        context: Option<&str>,
    ) -> Pin<Box<dyn Future<Output = Result<String, SigilError>> + Send + '_>> {
        let b64 = base64_encode(plaintext);
        let context_owned = context.map(String::from);
        Box::pin(async move {
            let ctx_ref = context_owned.as_deref();
            let mut client = self
                .pool
                .get()
                .await
                .map_err(|e| SigilError::Internal(format!("cipher pool get failed: {e}")))?;
            let result = client
                .encrypt(&self.keyring, &b64, ctx_ref, None, false)
                .await
                .map_err(|e| SigilError::Crypto(format!("cipher encrypt failed: {e}")))?;
            Ok(result.ciphertext)
        })
    }

    fn decrypt(
        &self,
        ciphertext: &str,
        context: Option<&str>,
    ) -> Pin<Box<dyn Future<Output = Result<shroudb_crypto::SensitiveBytes, SigilError>> + Send + '_>>
    {
        let ciphertext_owned = ciphertext.to_string();
        let context_owned = context.map(String::from);
        Box::pin(async move {
            let ctx_ref = context_owned.as_deref();
            let mut client = self
                .pool
                .get()
                .await
                .map_err(|e| SigilError::Internal(format!("cipher pool get failed: {e}")))?;
            let result = client
                .decrypt(&self.keyring, &ciphertext_owned, ctx_ref)
                .await
                .map_err(|e| SigilError::Crypto(format!("cipher decrypt failed: {e}")))?;
            let bytes = base64_decode(&result.plaintext)
                .map_err(|e| SigilError::Crypto(format!("base64 decode failed: {e}")))?;
            Ok(shroudb_crypto::SensitiveBytes::new(bytes))
        })
    }
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn base64_decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(data)
}
