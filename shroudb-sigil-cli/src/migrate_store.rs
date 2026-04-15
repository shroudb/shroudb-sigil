//! Drive `migrate::migrate_schema_json` over a ShrouDB embedded store.
//!
//! The v2.0 Sigil server rejects v1 schemas on read, so this tool runs
//! offline against a stopped server's store directory. Stop the server,
//! point at the store, migrate, restart.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use shroudb_storage::{
    ChainedMasterKeySource, EmbeddedStore, EnvMasterKey, EphemeralKey, FileMasterKey,
    MasterKeySource, StorageEngine, StorageEngineConfig,
};
use shroudb_store::Store;

use crate::migrate::{MigrationOutcome, migrate_schema_json};

const SCHEMAS_NAMESPACE: &str = "sigil.schemas";

/// Per-run migration statistics.
#[derive(Debug, Default, Clone)]
pub struct MigrationReport {
    pub migrated: usize,
    pub already_v2: usize,
    pub errors: Vec<SchemaError>,
}

#[derive(Debug, Clone)]
pub struct SchemaError {
    pub schema_name: String,
    pub message: String,
}

/// Run the migration against a ShrouDB embedded store at `data_dir`.
///
/// Master key is resolved via the same chain as the Sigil server
/// (`SHROUDB_MASTER_KEY` env → `master.key` file in data_dir → ephemeral),
/// so operators running this against a normally-configured store need no
/// extra setup.
///
/// When `dry_run` is true, no writes occur — the report reflects what *would*
/// have happened, and an approximation of the migrated bytes is discarded.
pub async fn run_migration(data_dir: &Path, dry_run: bool) -> Result<MigrationReport> {
    let store = open_store(data_dir).await?;
    run_against_store(store.as_ref(), dry_run).await
}

/// Same as `run_migration`, but takes an already-opened `Store` — exposed
/// for tests that drive the migration over an in-memory store.
pub async fn run_against_store<S: Store + ?Sized>(
    store: &S,
    dry_run: bool,
) -> Result<MigrationReport> {
    let mut report = MigrationReport::default();

    let page = store
        .list(SCHEMAS_NAMESPACE, None, None, 10_000)
        .await
        .context("failed to list schemas namespace — is this a Sigil store?")?;

    for key_bytes in &page.keys {
        let schema_name = String::from_utf8(key_bytes.clone())
            .unwrap_or_else(|_| format!("<non-utf8:{} bytes>", key_bytes.len()));
        let entry = match store.get(SCHEMAS_NAMESPACE, key_bytes, None).await {
            Ok(e) => e,
            Err(e) => {
                report.errors.push(SchemaError {
                    schema_name: schema_name.clone(),
                    message: format!("read failed: {e}"),
                });
                continue;
            }
        };

        match migrate_schema_json(&entry.value) {
            Ok(MigrationOutcome::AlreadyV2) => {
                tracing::debug!(schema = %schema_name, "already v2, skipping");
                report.already_v2 += 1;
            }
            Ok(MigrationOutcome::Migrated(new_bytes)) => {
                if dry_run {
                    tracing::info!(
                        schema = %schema_name,
                        bytes = new_bytes.len(),
                        "would migrate (dry-run)"
                    );
                } else {
                    match store
                        .put(SCHEMAS_NAMESPACE, key_bytes, &new_bytes, None)
                        .await
                    {
                        Ok(_) => {
                            tracing::info!(schema = %schema_name, "migrated");
                        }
                        Err(e) => {
                            report.errors.push(SchemaError {
                                schema_name: schema_name.clone(),
                                message: format!("write failed: {e}"),
                            });
                            continue;
                        }
                    }
                }
                report.migrated += 1;
            }
            Err(e) => {
                report.errors.push(SchemaError {
                    schema_name: schema_name.clone(),
                    message: e.to_string(),
                });
            }
        }
    }

    Ok(report)
}

async fn open_store(data_dir: &Path) -> Result<Arc<EmbeddedStore>> {
    let key_source: Box<dyn MasterKeySource> = Box::new(ChainedMasterKeySource::new(vec![
        Box::new(EnvMasterKey::new()),
        Box::new(FileMasterKey::new()),
        Box::new(EphemeralKey),
    ]));

    let cfg = StorageEngineConfig {
        data_dir: PathBuf::from(data_dir),
        ..Default::default()
    };
    let engine = StorageEngine::open(cfg, key_source.as_ref())
        .await
        .with_context(|| format!("failed to open storage engine at {}", data_dir.display()))?;
    Ok(Arc::new(EmbeddedStore::new(Arc::new(engine), "sigil")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shroudb_store::NamespaceConfig;

    async fn make_store() -> Arc<EmbeddedStore> {
        shroudb_storage::test_util::create_test_store("sigil").await
    }

    async fn seed_schema(store: &EmbeddedStore, name: &str, body: &[u8]) {
        store
            .namespace_create(SCHEMAS_NAMESPACE, NamespaceConfig::default())
            .await
            .ok();
        store
            .put(SCHEMAS_NAMESPACE, name.as_bytes(), body, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn migrates_v1_schema_and_writes_v2() {
        let store = make_store().await;
        let v1 = br#"{"name":"myapp","fields":[
            {"name":"password","field_type":"string","annotations":{"credential":true}}
        ]}"#;
        seed_schema(&store, "myapp", v1).await;

        let report = run_against_store(store.as_ref(), false).await.unwrap();
        assert_eq!(report.migrated, 1);
        assert_eq!(report.already_v2, 0);
        assert!(report.errors.is_empty());

        // Re-read and confirm it's v2-shaped.
        let entry = store.get(SCHEMAS_NAMESPACE, b"myapp", None).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&entry.value).unwrap();
        assert_eq!(v["fields"][0]["kind"]["type"], "credential");
    }

    #[tokio::test]
    async fn dry_run_does_not_write() {
        let store = make_store().await;
        let v1 = br#"{"name":"myapp","fields":[
            {"name":"role","field_type":"string","annotations":{"index":true}}
        ]}"#;
        seed_schema(&store, "myapp", v1).await;

        let report = run_against_store(store.as_ref(), true).await.unwrap();
        assert_eq!(report.migrated, 1);

        // Bytes on disk unchanged.
        let entry = store.get(SCHEMAS_NAMESPACE, b"myapp", None).await.unwrap();
        assert!(entry.value.windows(11).any(|w| w == b"annotations"));
        assert!(!entry.value.windows(4).any(|w| w == b"kind"));
    }

    #[tokio::test]
    async fn already_v2_schema_is_skipped() {
        let store = make_store().await;
        let v2 = br#"{"name":"myapp","fields":[
            {"name":"password","field_type":"string","kind":{"type":"credential","lockout":{"max_attempts":5,"duration_secs":900}}}
        ]}"#;
        seed_schema(&store, "myapp", v2).await;

        let report = run_against_store(store.as_ref(), false).await.unwrap();
        assert_eq!(report.migrated, 0);
        assert_eq!(report.already_v2, 1);
    }

    #[tokio::test]
    async fn idempotent_on_rerun() {
        let store = make_store().await;
        let v1 = br#"{"name":"myapp","fields":[
            {"name":"pw","field_type":"string","annotations":{"credential":true}}
        ]}"#;
        seed_schema(&store, "myapp", v1).await;

        let first = run_against_store(store.as_ref(), false).await.unwrap();
        assert_eq!(first.migrated, 1);
        let second = run_against_store(store.as_ref(), false).await.unwrap();
        assert_eq!(second.migrated, 0);
        assert_eq!(second.already_v2, 1);
    }

    #[tokio::test]
    async fn mixed_v1_and_v2_schemas_each_handled() {
        let store = make_store().await;
        let v1 = br#"{"name":"legacy","fields":[
            {"name":"pw","field_type":"string","annotations":{"credential":true}}
        ]}"#;
        let v2 = br#"{"name":"modern","fields":[
            {"name":"pw","field_type":"string","kind":{"type":"credential"}}
        ]}"#;
        seed_schema(&store, "legacy", v1).await;
        seed_schema(&store, "modern", v2).await;

        let report = run_against_store(store.as_ref(), false).await.unwrap();
        assert_eq!(report.migrated, 1);
        assert_eq!(report.already_v2, 1);
    }

    #[tokio::test]
    async fn malformed_schema_is_reported_and_skipped() {
        let store = make_store().await;
        seed_schema(&store, "broken", b"{not json").await;
        seed_schema(
            &store,
            "good",
            br#"{"name":"good","fields":[
                {"name":"pw","field_type":"string","annotations":{"credential":true}}
            ]}"#,
        )
        .await;

        let report = run_against_store(store.as_ref(), false).await.unwrap();
        assert_eq!(report.migrated, 1);
        assert_eq!(report.errors.len(), 1);
        assert_eq!(report.errors[0].schema_name, "broken");
    }
}
