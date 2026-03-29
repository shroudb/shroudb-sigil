use std::future::Future;
use std::pin::Pin;

use shroudb_veil_client::VeilClient;
use tokio::sync::Mutex;

use crate::capabilities::VeilOps;
use shroudb_sigil_core::error::SigilError;

/// VeilOps implementation backed by a remote Veil server via TCP.
///
/// Wraps `VeilClient` with a configured index name. All searchable PII
/// field operations route through this index.
pub struct RemoteVeilOps {
    client: Mutex<VeilClient>,
    index: String,
}

impl RemoteVeilOps {
    pub fn new(client: VeilClient, index: String) -> Self {
        Self {
            client: Mutex::new(client),
            index,
        }
    }

    pub async fn connect(
        addr: &str,
        index: String,
        auth_token: Option<&str>,
    ) -> Result<Self, SigilError> {
        let mut client = VeilClient::connect(addr)
            .await
            .map_err(|e| SigilError::Internal(format!("veil connect failed: {e}")))?;

        if let Some(token) = auth_token {
            client
                .auth(token)
                .await
                .map_err(|e| SigilError::Internal(format!("veil auth failed: {e}")))?;
        }

        Ok(Self::new(client, index))
    }
}

impl VeilOps for RemoteVeilOps {
    fn put(
        &self,
        entry_id: &str,
        plaintext: &[u8],
        field: Option<&str>,
    ) -> Pin<Box<dyn Future<Output = Result<(), SigilError>> + Send + '_>> {
        let b64 = base64_encode(plaintext);
        let entry_id = entry_id.to_string();
        let field = field.map(String::from);
        Box::pin(async move {
            let mut client = self.client.lock().await;
            client
                .put(&self.index, &entry_id, &b64, field.as_deref())
                .await
                .map_err(|e| SigilError::Internal(format!("veil put failed: {e}")))?;
            Ok(())
        })
    }

    fn delete(
        &self,
        entry_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), SigilError>> + Send + '_>> {
        let entry_id = entry_id.to_string();
        Box::pin(async move {
            let mut client = self.client.lock().await;
            client
                .delete(&self.index, &entry_id)
                .await
                .map_err(|e| SigilError::Internal(format!("veil delete failed: {e}")))?;
            Ok(())
        })
    }

    fn search(
        &self,
        query: &str,
        field: Option<&str>,
        limit: Option<usize>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<(String, f64)>, SigilError>> + Send + '_>> {
        let query = query.to_string();
        let field = field.map(String::from);
        Box::pin(async move {
            let mut client = self.client.lock().await;
            let result = client
                .search(
                    &self.index,
                    &query,
                    Some("contains"),
                    field.as_deref(),
                    limit,
                )
                .await
                .map_err(|e| SigilError::Internal(format!("veil search failed: {e}")))?;
            Ok(result
                .results
                .into_iter()
                .map(|hit| (hit.id, hit.score))
                .collect())
        })
    }
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}
