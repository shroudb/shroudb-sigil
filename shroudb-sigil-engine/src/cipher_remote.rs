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
        // Remote Cipher gets the caller identity from the connection's AUTH
        // context, not from the command. Present for trait-shape parity with
        // embedded bridges that thread actor into the engine's audit path.
        _actor: &str,
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
        // Remote Cipher gets the caller identity from the connection's AUTH
        // context. Present for trait-shape parity.
        _actor: &str,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Base64 round-trips are the only logic here worth pinning as a
    /// unit test — the pool + client paths require a running remote
    /// Cipher server and are exercised by integration tests in
    /// `tests/cipher_remote_*.rs`.
    #[test]
    fn base64_round_trip() {
        let plain = b"hello encrypted world";
        let encoded = base64_encode(plain);
        let decoded = base64_decode(&encoded).expect("decode ok");
        assert_eq!(decoded, plain);
    }

    /// Pins the CipherOps trait shape at this call site: both methods
    /// carry an actor parameter (opaque to the remote path — see
    /// method doc comment). If the trait signature drifts, this test
    /// fails to compile.
    #[test]
    #[allow(clippy::type_complexity)]
    fn cipher_ops_trait_signature_includes_actor() {
        fn _assert_takes_actor<T: CipherOps>() {
            // The trait's method signatures are type-level. Reference
            // both methods by their Fn-like shape to keep this test
            // failing at compile time if a parameter is removed.
            let _enc: for<'a> fn(
                &'a T,
                &'a [u8],
                Option<&'a str>,
                &'a str,
            ) -> Pin<
                Box<dyn Future<Output = Result<String, SigilError>> + Send + 'a>,
            > = T::encrypt;
            let _dec: for<'a> fn(
                &'a T,
                &'a str,
                Option<&'a str>,
                &'a str,
            ) -> Pin<
                Box<
                    dyn Future<Output = Result<shroudb_crypto::SensitiveBytes, SigilError>>
                        + Send
                        + 'a,
                >,
            > = T::decrypt;
        }
    }
}
