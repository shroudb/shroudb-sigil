use std::future::Future;
use std::pin::Pin;

use shroudb_keep_client::KeepClient;

use crate::capabilities::KeepOps;
use shroudb_sigil_core::error::SigilError;

/// KeepOps implementation backed by a remote Keep server via TCP.
///
/// Creates a fresh `KeepClient` connection per call to allow concurrent
/// operations without serializing through a single connection.
pub struct RemoteKeepOps {
    addr: String,
    auth_token: Option<String>,
}

impl RemoteKeepOps {
    /// Connect to a Keep server and verify connectivity.
    ///
    /// Establishes an initial connection to validate the address and auth
    /// token, then stores the parameters for per-request connections.
    pub async fn connect(addr: &str, auth_token: Option<&str>) -> Result<Self, SigilError> {
        let mut client = KeepClient::connect(addr)
            .await
            .map_err(|e| SigilError::Internal(format!("keep connect failed: {e}")))?;

        if let Some(token) = auth_token {
            client
                .auth(token)
                .await
                .map_err(|e| SigilError::Internal(format!("keep auth failed: {e}")))?;
        }

        Ok(Self {
            addr: addr.to_string(),
            auth_token: auth_token.map(String::from),
        })
    }

    /// Create a fresh client connection, authenticating if configured.
    async fn fresh_client(&self) -> Result<KeepClient, SigilError> {
        let mut client = KeepClient::connect(&self.addr)
            .await
            .map_err(|e| SigilError::Internal(format!("keep connect failed: {e}")))?;

        if let Some(ref token) = self.auth_token {
            client
                .auth(token)
                .await
                .map_err(|e| SigilError::Internal(format!("keep auth failed: {e}")))?;
        }

        Ok(client)
    }
}

impl KeepOps for RemoteKeepOps {
    fn store_secret(
        &self,
        path: &str,
        value: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<u64, SigilError>> + Send + '_>> {
        let b64 = base64_encode(value);
        let path = path.to_string();
        Box::pin(async move {
            let mut client = self.fresh_client().await?;
            let result = client
                .put(&path, &b64)
                .await
                .map_err(|e| SigilError::Internal(format!("keep put failed: {e}")))?;
            Ok(result.version as u64)
        })
    }

    fn delete_secret(
        &self,
        path: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), SigilError>> + Send + '_>> {
        let path = path.to_string();
        Box::pin(async move {
            let mut client = self.fresh_client().await?;
            client
                .delete(&path)
                .await
                .map_err(|e| SigilError::Internal(format!("keep delete failed: {e}")))?;
            Ok(())
        })
    }
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}
