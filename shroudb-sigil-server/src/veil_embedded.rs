//! Embedded VeilOps adapter for the standalone Sigil server.
//!
//! When `[veil] mode = "embedded"` is set, Sigil runs an in-process
//! `VeilEngine` on the same `StorageEngine` (distinct namespace) and
//! implements `VeilOps` by calling it directly.

use std::sync::Arc;

use shroudb_sigil_core::error::SigilError;
use shroudb_sigil_engine::capabilities::VeilOps;
use shroudb_store::Store;
use shroudb_veil_engine::engine::VeilEngine;

type BoxFut<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, SigilError>> + Send + 'a>>;

pub struct EmbeddedVeilOps<S: Store> {
    engine: Arc<VeilEngine<S>>,
    index: String,
}

impl<S: Store> EmbeddedVeilOps<S> {
    pub fn new(engine: Arc<VeilEngine<S>>, index: impl Into<String>) -> Self {
        Self {
            engine,
            index: index.into(),
        }
    }
}

impl<S: Store + 'static> VeilOps for EmbeddedVeilOps<S> {
    fn put(
        &self,
        entry_id: &str,
        data: &[u8],
        field: Option<&str>,
        blind: bool,
        actor: &str,
    ) -> BoxFut<'_, ()> {
        use base64::Engine as _;
        let id = entry_id.to_string();
        let wire_data = if blind {
            String::from_utf8_lossy(data).into_owned()
        } else {
            base64::engine::general_purpose::STANDARD.encode(data)
        };
        let field = field.map(|f| f.to_string());
        let actor = actor.to_string();
        Box::pin(async move {
            self.engine
                .put(
                    &self.index,
                    &id,
                    &wire_data,
                    field.as_deref(),
                    blind,
                    Some(&actor),
                )
                .await
                .map(|_| ())
                .map_err(|e| SigilError::Internal(format!("veil put: {e}")))
        })
    }

    fn delete(&self, entry_id: &str, actor: &str) -> BoxFut<'_, ()> {
        let id = entry_id.to_string();
        let actor = actor.to_string();
        Box::pin(async move {
            self.engine
                .delete(&self.index, &id, Some(&actor))
                .await
                .map_err(|e| SigilError::Internal(format!("veil delete: {e}")))
        })
    }

    fn search(
        &self,
        query: &str,
        field: Option<&str>,
        limit: Option<usize>,
        blind: bool,
        actor: &str,
    ) -> BoxFut<'_, Vec<(String, f64)>> {
        let q = query.to_string();
        let f = field.map(|s| s.to_string());
        let actor = actor.to_string();
        Box::pin(async move {
            self.engine
                .search(
                    &self.index,
                    &q,
                    shroudb_veil_engine::engine::SearchOptions {
                        mode: shroudb_veil_core::matching::MatchMode::Exact,
                        field: f.as_deref(),
                        limit,
                        blind,
                    },
                    Some(&actor),
                )
                .await
                .map(|results| results.hits.into_iter().map(|m| (m.id, m.score)).collect())
                .map_err(|e| SigilError::Internal(format!("veil search: {e}")))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shroudb_server_bootstrap::Capability;
    use shroudb_veil_engine::engine::VeilConfig;

    async fn build_ops() -> EmbeddedVeilOps<shroudb_storage::EmbeddedStore> {
        let store = shroudb_storage::test_util::create_test_store("sigil-veil-embedded-test").await;
        let engine = VeilEngine::new(
            store,
            VeilConfig::default(),
            Capability::DisabledForTests,
            Capability::DisabledForTests,
        )
        .await
        .expect("veil engine init");
        let index = "sigil-searchable";
        engine
            .index_manager()
            .create(index)
            .await
            .expect("create index");
        EmbeddedVeilOps::new(Arc::new(engine), index)
    }

    #[tokio::test]
    async fn put_and_search_round_trips_entry() {
        let ops = build_ops().await;
        let entry = b"alice@example.com";
        ops.put("user-1", entry, Some("email"), false, "test-actor")
            .await
            .expect("put");

        let hits = ops
            .search(
                "alice@example.com",
                Some("email"),
                None,
                false,
                "test-actor",
            )
            .await
            .expect("search");
        assert!(
            hits.iter().any(|(id, _)| id == "user-1"),
            "exact match must surface inserted entry, got: {hits:?}"
        );
    }

    #[tokio::test]
    async fn delete_removes_entry_from_search_hits() {
        let ops = build_ops().await;
        ops.put(
            "user-1",
            b"bob@example.com",
            Some("email"),
            false,
            "test-actor",
        )
        .await
        .unwrap();
        ops.delete("user-1", "test-actor").await.expect("delete");

        let hits = ops
            .search("bob@example.com", Some("email"), None, false, "test-actor")
            .await
            .unwrap();
        assert!(
            !hits.iter().any(|(id, _)| id == "user-1"),
            "deleted entry must not appear in search results"
        );
    }
}
