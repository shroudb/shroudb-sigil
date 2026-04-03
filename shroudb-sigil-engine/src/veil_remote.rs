use std::future::Future;
use std::pin::Pin;

use shroudb_veil_client::VeilClient;

use crate::capabilities::VeilOps;
use shroudb_sigil_core::error::SigilError;

/// VeilOps implementation backed by a remote Veil server via TCP.
///
/// Creates a fresh `VeilClient` connection per call to allow concurrent
/// operations without serializing through a single connection.
pub struct RemoteVeilOps {
    addr: String,
    auth_token: Option<String>,
    index: String,
}

impl RemoteVeilOps {
    /// Connect to a Veil server and verify connectivity.
    ///
    /// Establishes an initial connection to validate the address and auth
    /// token, then stores the parameters for per-request connections.
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

        Ok(Self {
            addr: addr.to_string(),
            auth_token: auth_token.map(String::from),
            index,
        })
    }

    /// Create a fresh client connection, authenticating if configured.
    async fn fresh_client(&self) -> Result<VeilClient, SigilError> {
        let mut client = VeilClient::connect(&self.addr)
            .await
            .map_err(|e| SigilError::Internal(format!("veil connect failed: {e}")))?;

        if let Some(ref token) = self.auth_token {
            client
                .auth(token)
                .await
                .map_err(|e| SigilError::Internal(format!("veil auth failed: {e}")))?;
        }

        Ok(client)
    }
}

impl VeilOps for RemoteVeilOps {
    fn put(
        &self,
        entry_id: &str,
        data: &[u8],
        field: Option<&str>,
        blind: bool,
    ) -> Pin<Box<dyn Future<Output = Result<(), SigilError>> + Send + '_>> {
        let b64 = base64_encode(data);
        let entry_id = entry_id.to_string();
        let field = field.map(String::from);
        Box::pin(async move {
            let mut client = self.fresh_client().await?;
            client
                .put(&self.index, &entry_id, &b64, field.as_deref(), blind)
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
            let mut client = self.fresh_client().await?;
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
        blind: bool,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<(String, f64)>, SigilError>> + Send + '_>> {
        let query = query.to_string();
        let field = field.map(String::from);
        Box::pin(async move {
            let mut client = self.fresh_client().await?;
            let result = client
                .search(
                    &self.index,
                    &query,
                    Some("contains"),
                    field.as_deref(),
                    limit,
                    blind,
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
