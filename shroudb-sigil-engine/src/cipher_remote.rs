use std::future::Future;
use std::pin::Pin;

use shroudb_cipher_client::CipherClient;
use tokio::sync::Mutex;

use crate::capabilities::CipherOps;
use shroudb_sigil_core::error::SigilError;

/// CipherOps implementation backed by a remote Cipher server via TCP.
///
/// Wraps `CipherClient` with a configured keyring name. All PII field
/// encryption/decryption routes through this keyring.
pub struct RemoteCipherOps {
    client: Mutex<CipherClient>,
    keyring: String,
}

impl RemoteCipherOps {
    pub fn new(client: CipherClient, keyring: String) -> Self {
        Self {
            client: Mutex::new(client),
            keyring,
        }
    }

    /// Connect to a Cipher server and optionally authenticate.
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

        Ok(Self::new(client, keyring))
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
            let mut client = self.client.lock().await;
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
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, SigilError>> + Send + '_>> {
        let ciphertext_owned = ciphertext.to_string();
        let context_owned = context.map(String::from);
        Box::pin(async move {
            let ctx_ref = context_owned.as_deref();
            let mut client = self.client.lock().await;
            let result = client
                .decrypt(&self.keyring, &ciphertext_owned, ctx_ref)
                .await
                .map_err(|e| SigilError::Crypto(format!("cipher decrypt failed: {e}")))?;
            base64_decode(&result.plaintext)
                .map_err(|e| SigilError::Crypto(format!("base64 decode failed: {e}")))
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
