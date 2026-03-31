use std::future::Future;
use std::pin::Pin;

use shroudb_cipher_client::CipherClient;

use crate::capabilities::CipherOps;
use shroudb_sigil_core::error::SigilError;

/// CipherOps implementation backed by a remote Cipher server via TCP.
///
/// Creates a fresh `CipherClient` connection per call to allow concurrent
/// operations without serializing through a single connection.
pub struct RemoteCipherOps {
    addr: String,
    auth_token: Option<String>,
    keyring: String,
}

impl RemoteCipherOps {
    /// Connect to a Cipher server and verify connectivity.
    ///
    /// Establishes an initial connection to validate the address and auth
    /// token, then stores the parameters for per-request connections.
    pub async fn connect(
        addr: &str,
        keyring: String,
        auth_token: Option<&str>,
    ) -> Result<Self, SigilError> {
        let mut client = CipherClient::connect(addr)
            .await
            .map_err(|e| SigilError::Internal(format!("cipher connect failed: {e}")))?;

        if let Some(token) = auth_token {
            client
                .auth(token)
                .await
                .map_err(|e| SigilError::Internal(format!("cipher auth failed: {e}")))?;
        }

        Ok(Self {
            addr: addr.to_string(),
            auth_token: auth_token.map(String::from),
            keyring,
        })
    }

    /// Create a fresh client connection, authenticating if configured.
    async fn fresh_client(&self) -> Result<CipherClient, SigilError> {
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
            let mut client = self.fresh_client().await?;
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
            let mut client = self.fresh_client().await?;
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
