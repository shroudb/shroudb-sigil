use std::future::Future;
use std::pin::Pin;

use deadpool::managed::{self, Manager, Metrics, RecycleResult};
use shroudb_keep_client::KeepClient;

use crate::capabilities::KeepOps;
use shroudb_sigil_core::error::SigilError;

const DEFAULT_POOL_SIZE: usize = 8;

struct KeepConnManager {
    addr: String,
    auth_token: Option<String>,
}

impl Manager for KeepConnManager {
    type Type = KeepClient;
    type Error = SigilError;

    async fn create(&self) -> Result<KeepClient, SigilError> {
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

    async fn recycle(
        &self,
        _client: &mut KeepClient,
        _metrics: &Metrics,
    ) -> RecycleResult<SigilError> {
        Ok(())
    }
}

type KeepPool = managed::Pool<KeepConnManager>;

/// KeepOps implementation backed by a remote Keep server via TCP.
///
/// Maintains a connection pool to avoid per-call TCP connect + authenticate overhead.
pub struct RemoteKeepOps {
    pool: KeepPool,
}

impl RemoteKeepOps {
    /// Connect to a Keep server and verify connectivity.
    ///
    /// Establishes an initial connection to validate the address and auth
    /// token, then builds a pool for subsequent requests.
    pub async fn connect(
        addr: &str,
        auth_token: Option<&str>,
        pool_size: Option<usize>,
    ) -> Result<Self, SigilError> {
        let mut probe = KeepClient::connect(addr)
            .await
            .map_err(|e| SigilError::Internal(format!("keep connect failed: {e}")))?;
        if let Some(token) = auth_token {
            probe
                .auth(token)
                .await
                .map_err(|e| SigilError::Internal(format!("keep auth failed: {e}")))?;
        }
        drop(probe);

        let size = match pool_size {
            Some(0) | None => DEFAULT_POOL_SIZE,
            Some(n) => n,
        };

        let mgr = KeepConnManager {
            addr: addr.to_string(),
            auth_token: auth_token.map(String::from),
        };
        let pool = KeepPool::builder(mgr)
            .max_size(size)
            .build()
            .map_err(|e| SigilError::Internal(format!("keep pool build failed: {e}")))?;

        Ok(Self { pool })
    }
}

impl KeepOps for RemoteKeepOps {
    fn store_secret(
        &self,
        path: &str,
        value: &[u8],
        // Remote Keep gets caller identity from the connection's AUTH
        // context. Present for trait-shape parity.
        _actor: &str,
    ) -> Pin<Box<dyn Future<Output = Result<u64, SigilError>> + Send + '_>> {
        let b64 = base64_encode(value);
        let path = path.to_string();
        Box::pin(async move {
            let mut client = self
                .pool
                .get()
                .await
                .map_err(|e| SigilError::Internal(format!("keep pool get failed: {e}")))?;
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
        // Remote Keep gets caller identity from the connection's AUTH
        // context. Present for trait-shape parity.
        _actor: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), SigilError>> + Send + '_>> {
        let path = path.to_string();
        Box::pin(async move {
            let mut client = self
                .pool
                .get()
                .await
                .map_err(|e| SigilError::Internal(format!("keep pool get failed: {e}")))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_encodes_bytes() {
        assert_eq!(base64_encode(b"hi"), "aGk=");
    }

    /// Pins the KeepOps trait shape: both methods carry an actor.
    #[test]
    #[allow(clippy::type_complexity)]
    fn keep_ops_trait_signature_includes_actor() {
        fn _assert_takes_actor<T: KeepOps>() {
            let _s: for<'a> fn(
                &'a T,
                &'a str,
                &'a [u8],
                &'a str,
            ) -> Pin<
                Box<dyn Future<Output = Result<u64, SigilError>> + Send + 'a>,
            > = T::store_secret;
            let _d: for<'a> fn(
                &'a T,
                &'a str,
                &'a str,
            ) -> Pin<
                Box<dyn Future<Output = Result<(), SigilError>> + Send + 'a>,
            > = T::delete_secret;
        }
    }
}
