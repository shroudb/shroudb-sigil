use std::future::Future;
use std::pin::Pin;

use shroudb_keep_client::KeepClient;
use tokio::sync::Mutex;

use crate::capabilities::KeepOps;
use shroudb_sigil_core::error::SigilError;

/// KeepOps implementation backed by a remote Keep server via TCP.
pub struct RemoteKeepOps {
    client: Mutex<KeepClient>,
}

impl RemoteKeepOps {
    pub fn new(client: KeepClient) -> Self {
        Self {
            client: Mutex::new(client),
        }
    }

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

        Ok(Self::new(client))
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
            let mut client = self.client.lock().await;
            let result = client
                .put(&path, &b64)
                .await
                .map_err(|e| SigilError::Internal(format!("keep put failed: {e}")))?;
            Ok(result.version as u64)
        })
    }

    fn get_secret(
        &self,
        path: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, SigilError>> + Send + '_>> {
        let path = path.to_string();
        Box::pin(async move {
            let mut client = self.client.lock().await;
            let result = client
                .get(&path, None)
                .await
                .map_err(|e| SigilError::Internal(format!("keep get failed: {e}")))?;
            base64_decode(&result.value)
                .map_err(|e| SigilError::Internal(format!("base64 decode failed: {e}")))
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
