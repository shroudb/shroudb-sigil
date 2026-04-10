use std::future::Future;
use std::pin::Pin;

use deadpool::managed::{self, Manager, Metrics, RecycleResult};
use shroudb_veil_client::VeilClient;

use crate::capabilities::VeilOps;
use shroudb_sigil_core::error::SigilError;

const DEFAULT_POOL_SIZE: usize = 8;

struct VeilConnManager {
    addr: String,
    auth_token: Option<String>,
}

impl Manager for VeilConnManager {
    type Type = VeilClient;
    type Error = SigilError;

    async fn create(&self) -> Result<VeilClient, SigilError> {
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

    async fn recycle(
        &self,
        _client: &mut VeilClient,
        _metrics: &Metrics,
    ) -> RecycleResult<SigilError> {
        Ok(())
    }
}

type VeilPool = managed::Pool<VeilConnManager>;

/// VeilOps implementation backed by a remote Veil server via TCP.
///
/// Maintains a connection pool to avoid per-call TCP connect + authenticate overhead.
pub struct RemoteVeilOps {
    pool: VeilPool,
    index: String,
}

impl RemoteVeilOps {
    /// Connect to a Veil server and verify connectivity.
    ///
    /// Establishes an initial connection to validate the address and auth
    /// token, then builds a pool for subsequent requests.
    pub async fn connect(
        addr: &str,
        index: String,
        auth_token: Option<&str>,
        pool_size: Option<usize>,
    ) -> Result<Self, SigilError> {
        let mut probe = VeilClient::connect(addr)
            .await
            .map_err(|e| SigilError::Internal(format!("veil connect failed: {e}")))?;
        if let Some(token) = auth_token {
            probe
                .auth(token)
                .await
                .map_err(|e| SigilError::Internal(format!("veil auth failed: {e}")))?;
        }
        drop(probe);

        let size = match pool_size {
            Some(0) | None => DEFAULT_POOL_SIZE,
            Some(n) => n,
        };

        let mgr = VeilConnManager {
            addr: addr.to_string(),
            auth_token: auth_token.map(String::from),
        };
        let pool = VeilPool::builder(mgr)
            .max_size(size)
            .build()
            .map_err(|e| SigilError::Internal(format!("veil pool build failed: {e}")))?;

        Ok(Self { pool, index })
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
        let wire_data = if blind {
            String::from_utf8_lossy(data).into_owned()
        } else {
            base64_encode(data)
        };
        let entry_id = entry_id.to_string();
        let field = field.map(String::from);
        Box::pin(async move {
            let mut client = self
                .pool
                .get()
                .await
                .map_err(|e| SigilError::Internal(format!("veil pool get failed: {e}")))?;
            client
                .put(&self.index, &entry_id, &wire_data, field.as_deref(), blind)
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
            let mut client = self
                .pool
                .get()
                .await
                .map_err(|e| SigilError::Internal(format!("veil pool get failed: {e}")))?;
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
            let mut client = self
                .pool
                .get()
                .await
                .map_err(|e| SigilError::Internal(format!("veil pool get failed: {e}")))?;
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
