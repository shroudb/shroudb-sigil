use std::sync::Arc;

use shroudb_sigil_core::error::SigilError;
use shroudb_sigil_core::schema::Schema;
use shroudb_store::{NamespaceConfig, Store, StoreError};

/// Namespace for storing schema definitions.
const SCHEMAS_NAMESPACE: &str = "sigil.schemas";

/// Store-backed schema registry.
///
/// Schemas are stored as JSON-serialized entries in the `sigil.schemas`
/// namespace, keyed by schema name. On registration, the required
/// namespaces for the schema are auto-created.
pub struct SchemaRegistry<S: Store> {
    store: Arc<S>,
}

impl<S: Store> SchemaRegistry<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self { store }
    }

    /// Ensure the schemas namespace exists.
    pub async fn init(&self) -> Result<(), SigilError> {
        match self
            .store
            .namespace_create(SCHEMAS_NAMESPACE, NamespaceConfig::default())
            .await
        {
            Ok(()) => Ok(()),
            Err(StoreError::NamespaceExists(_)) => Ok(()),
            Err(e) => Err(SigilError::Store(e.to_string())),
        }
    }

    /// Register a new schema. Validates, stores, and creates namespaces.
    pub async fn register(&self, schema: Schema) -> Result<u64, SigilError> {
        schema.validate()?;

        // Check for duplicates
        if self.get(&schema.name).await.is_ok() {
            return Err(SigilError::SchemaExists(schema.name.clone()));
        }

        // Serialize schema
        let value = serde_json::to_vec(&schema).map_err(|e| SigilError::Internal(e.to_string()))?;

        // Store schema definition
        let version = self
            .store
            .put(SCHEMAS_NAMESPACE, schema.name.as_bytes(), &value, None)
            .await
            .map_err(|e| SigilError::Store(e.to_string()))?;

        // Auto-create namespaces for the schema
        self.create_schema_namespaces(&schema.name).await?;

        Ok(version)
    }

    /// Retrieve a schema by name.
    pub async fn get(&self, name: &str) -> Result<Schema, SigilError> {
        let entry = self
            .store
            .get(SCHEMAS_NAMESPACE, name.as_bytes(), None)
            .await
            .map_err(|e| match e {
                StoreError::NotFound => SigilError::SchemaNotFound(name.to_string()),
                other => SigilError::Store(other.to_string()),
            })?;

        serde_json::from_slice(&entry.value).map_err(|e| SigilError::Internal(e.to_string()))
    }

    /// List all registered schema names.
    pub async fn list(&self) -> Result<Vec<String>, SigilError> {
        let page = self
            .store
            .list(SCHEMAS_NAMESPACE, None, None, 10_000)
            .await
            .map_err(|e| SigilError::Store(e.to_string()))?;

        let names = page
            .keys
            .into_iter()
            .filter_map(|k| String::from_utf8(k).ok())
            .collect();

        Ok(names)
    }

    /// Create the required namespaces for a schema.
    async fn create_schema_namespaces(&self, schema_name: &str) -> Result<(), SigilError> {
        let namespaces = [
            format!("sigil.{schema_name}.envelopes"),
            format!("sigil.{schema_name}.credentials"),
            format!("sigil.{schema_name}.keys"),
            format!("sigil.{schema_name}.sessions"),
        ];

        for ns in &namespaces {
            match self
                .store
                .namespace_create(ns, NamespaceConfig::default())
                .await
            {
                Ok(()) | Err(StoreError::NamespaceExists(_)) => {}
                Err(e) => return Err(SigilError::Store(e.to_string())),
            }
        }

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use shroudb_sigil_core::schema::{FieldAnnotations, FieldDef, FieldType};

    pub(crate) async fn create_test_store() -> Arc<shroudb_storage::EmbeddedStore> {
        shroudb_storage::test_util::create_test_store("sigil-test").await
    }

    fn test_schema(name: &str) -> Schema {
        Schema {
            name: name.to_string(),
            fields: vec![
                FieldDef {
                    name: "email".to_string(),
                    field_type: FieldType::String,
                    annotations: FieldAnnotations {
                        pii: true,
                        ..Default::default()
                    },
                },
                FieldDef {
                    name: "password".to_string(),
                    field_type: FieldType::String,
                    annotations: FieldAnnotations {
                        credential: true,
                        ..Default::default()
                    },
                },
                FieldDef {
                    name: "org_id".to_string(),
                    field_type: FieldType::String,
                    annotations: FieldAnnotations {
                        index: true,
                        ..Default::default()
                    },
                },
            ],
        }
    }

    /// Integration test using EmbeddedStore backed by a real StorageEngine.
    #[tokio::test]
    async fn register_and_get_schema() {
        let store = create_test_store().await;
        let registry = SchemaRegistry::new(store);
        registry.init().await.unwrap();

        let schema = test_schema("myapp");
        let version = registry.register(schema).await.unwrap();
        assert_eq!(version, 1);

        let retrieved = registry.get("myapp").await.unwrap();
        assert_eq!(retrieved.name, "myapp");
        assert_eq!(retrieved.fields.len(), 3);
        assert!(retrieved.fields[1].annotations.credential);
    }

    #[tokio::test]
    async fn register_duplicate_rejected() {
        let store = create_test_store().await;
        let registry = SchemaRegistry::new(store);
        registry.init().await.unwrap();

        registry.register(test_schema("myapp")).await.unwrap();
        let err = registry.register(test_schema("myapp")).await.unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[tokio::test]
    async fn get_nonexistent_returns_not_found() {
        let store = create_test_store().await;
        let registry = SchemaRegistry::new(store);
        registry.init().await.unwrap();

        let err = registry.get("nope").await.unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[tokio::test]
    async fn list_schemas() {
        let store = create_test_store().await;
        let registry = SchemaRegistry::new(store);
        registry.init().await.unwrap();

        registry.register(test_schema("app-a")).await.unwrap();
        registry.register(test_schema("app-b")).await.unwrap();

        let names = registry.list().await.unwrap();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"app-a".to_string()));
        assert!(names.contains(&"app-b".to_string()));
    }

    #[tokio::test]
    async fn register_creates_namespaces() {
        let store = create_test_store().await;
        let registry = SchemaRegistry::new(store.clone());
        registry.init().await.unwrap();

        registry.register(test_schema("myapp")).await.unwrap();

        // Verify namespaces were created
        let info = store.namespace_info("sigil.myapp.envelopes").await;
        assert!(info.is_ok(), "sigil.myapp.envelopes namespace should exist");

        let info = store.namespace_info("sigil.myapp.credentials").await;
        assert!(
            info.is_ok(),
            "sigil.myapp.credentials namespace should exist"
        );

        let info = store.namespace_info("sigil.myapp.keys").await;
        assert!(info.is_ok(), "sigil.myapp.keys namespace should exist");

        let info = store.namespace_info("sigil.myapp.sessions").await;
        assert!(info.is_ok(), "sigil.myapp.sessions namespace should exist");
    }

    #[tokio::test]
    async fn invalid_schema_rejected() {
        let store = create_test_store().await;
        let registry = SchemaRegistry::new(store);
        registry.init().await.unwrap();

        let invalid = Schema {
            name: "".to_string(),
            fields: vec![],
        };
        assert!(registry.register(invalid).await.is_err());
    }
}
