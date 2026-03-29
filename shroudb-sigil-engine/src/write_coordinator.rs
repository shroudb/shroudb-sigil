use std::collections::HashMap;
use std::sync::Arc;

use shroudb_sigil_core::error::SigilError;
use shroudb_sigil_core::routing::{FieldTreatment, route_field};
use shroudb_sigil_core::schema::Schema;
use shroudb_store::Store;

use crate::capabilities::Capabilities;
use crate::credential::CredentialManager;

/// A completed write operation that can be rolled back.
struct CompensatingOp {
    namespace: String,
    key: Vec<u8>,
}

/// User record stored in the `sigil.{schema}.users` namespace.
/// Contains non-sensitive field values and metadata — the "commit point."
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct UserRecord {
    pub user_id: String,
    /// Non-sensitive field values (index, inert fields).
    pub fields: HashMap<String, serde_json::Value>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Coordinates all-or-nothing multi-field writes.
///
/// A single `USER CREATE` can touch credentials (Argon2id hash),
/// PII (Cipher encrypt), searchable fields (Veil index), secrets (Keep),
/// and plaintext indexes. If any operation fails, all completed operations
/// are rolled back via compensating DELETEs.
pub struct WriteCoordinator<S: Store> {
    store: Arc<S>,
    credentials: Arc<CredentialManager<S>>,
    capabilities: Arc<Capabilities>,
}

impl<S: Store> WriteCoordinator<S> {
    pub fn new(
        store: Arc<S>,
        credentials: Arc<CredentialManager<S>>,
        capabilities: Arc<Capabilities>,
    ) -> Self {
        Self {
            store,
            credentials,
            capabilities,
        }
    }

    /// Create a user by routing each field to the appropriate handler.
    /// All-or-nothing: if any field fails, all completed writes are rolled back.
    pub async fn create_user(
        &self,
        schema: &Schema,
        user_id: &str,
        fields: &HashMap<String, serde_json::Value>,
    ) -> Result<UserRecord, SigilError> {
        self.create_user_inner(schema, user_id, fields, false).await
    }

    /// Import a user with pre-hashed credential fields.
    ///
    /// Same as `create_user` except credential fields are treated as hashes
    /// (validated and stored directly) instead of plaintext (hashed with Argon2id).
    /// Non-credential fields are processed identically to `create_user`.
    pub async fn import_user(
        &self,
        schema: &Schema,
        user_id: &str,
        fields: &HashMap<String, serde_json::Value>,
    ) -> Result<UserRecord, SigilError> {
        self.create_user_inner(schema, user_id, fields, true).await
    }

    async fn create_user_inner(
        &self,
        schema: &Schema,
        user_id: &str,
        fields: &HashMap<String, serde_json::Value>,
        import_mode: bool,
    ) -> Result<UserRecord, SigilError> {
        // Validate all required fields are present
        for field_def in &schema.fields {
            if !fields.contains_key(&field_def.name) {
                return Err(SigilError::MissingField(field_def.name.clone()));
            }
        }

        // Check for existing user
        let users_ns = users_namespace(&schema.name);
        if self
            .store
            .get(&users_ns, user_id.as_bytes(), None)
            .await
            .is_ok()
        {
            return Err(SigilError::UserExists);
        }

        let mut completed_ops: Vec<CompensatingOp> = Vec::new();
        let mut user_fields: HashMap<String, serde_json::Value> = HashMap::new();

        // Process each field according to its treatment
        for field_def in &schema.fields {
            let value = &fields[&field_def.name];
            let treatment = route_field(&field_def.annotations);

            let result = self
                .process_field(
                    &schema.name,
                    user_id,
                    &field_def.name,
                    value,
                    treatment,
                    import_mode,
                )
                .await;

            match result {
                Ok(field_result) => {
                    if let Some(op) = field_result.compensating_op {
                        completed_ops.push(op);
                    }
                    if let Some(stored_value) = field_result.user_record_value {
                        user_fields.insert(field_def.name.clone(), stored_value);
                    }
                }
                Err(e) => {
                    self.rollback(completed_ops).await;
                    return Err(e);
                }
            }
        }

        // Write the user index entry — the "commit point"
        let now = now_secs();
        let user_record = UserRecord {
            user_id: user_id.to_string(),
            fields: user_fields,
            created_at: now,
            updated_at: now,
        };

        let value =
            serde_json::to_vec(&user_record).map_err(|e| SigilError::Internal(e.to_string()))?;

        if let Err(e) = self
            .store
            .put(&users_ns, user_id.as_bytes(), &value, None)
            .await
        {
            self.rollback(completed_ops).await;
            return Err(SigilError::Store(e.to_string()));
        }

        Ok(user_record)
    }

    /// Get a user record, decrypting PII fields if Cipher is available.
    pub async fn get_user(&self, schema: &Schema, user_id: &str) -> Result<UserRecord, SigilError> {
        let ns = users_namespace(&schema.name);
        let entry = self
            .store
            .get(&ns, user_id.as_bytes(), None)
            .await
            .map_err(|_| SigilError::UserNotFound)?;

        let mut record: UserRecord = serde_json::from_slice(&entry.value)
            .map_err(|e| SigilError::Internal(e.to_string()))?;

        // Decrypt PII fields if Cipher is available
        if let Some(ref cipher) = self.capabilities.cipher {
            for field_def in &schema.fields {
                let treatment = route_field(&field_def.annotations);
                if matches!(
                    treatment,
                    FieldTreatment::EncryptedPii | FieldTreatment::SearchableEncrypted
                ) && let Some(ciphertext_val) = record.fields.get(&field_def.name)
                    && let Some(ciphertext) = ciphertext_val.as_str()
                {
                    let context = format!("{}/{}/{}", schema.name, user_id, field_def.name);
                    match cipher.decrypt(ciphertext, Some(&context)).await {
                        Ok(plaintext) => {
                            let plaintext_str = String::from_utf8(plaintext)
                                .unwrap_or_else(|e| hex::encode(e.into_bytes()));
                            record
                                .fields
                                .insert(field_def.name.clone(), serde_json::json!(plaintext_str));
                        }
                        Err(e) => {
                            tracing::warn!(
                                field = %field_def.name,
                                error = %e,
                                "failed to decrypt PII field"
                            );
                        }
                    }
                }
            }
        }

        Ok(record)
    }

    /// Update non-credential fields on an existing user.
    /// Credential fields cannot be updated through this method — use
    /// password change/reset instead.
    pub async fn update_user(
        &self,
        schema: &Schema,
        user_id: &str,
        fields: &HashMap<String, serde_json::Value>,
    ) -> Result<UserRecord, SigilError> {
        let users_ns = users_namespace(&schema.name);
        let entry = self
            .store
            .get(&users_ns, user_id.as_bytes(), None)
            .await
            .map_err(|_| SigilError::UserNotFound)?;

        let mut record: UserRecord = serde_json::from_slice(&entry.value)
            .map_err(|e| SigilError::Internal(e.to_string()))?;

        for (field_name, value) in fields {
            // Find the field definition in the schema
            let field_def = schema
                .fields
                .iter()
                .find(|f| f.name == *field_name)
                .ok_or_else(|| SigilError::InvalidField {
                    field: field_name.clone(),
                    reason: "field not in schema".into(),
                })?;

            let treatment = shroudb_sigil_core::routing::route_field(&field_def.annotations);

            // Reject credential updates through this path
            if treatment == shroudb_sigil_core::routing::FieldTreatment::Credential {
                return Err(SigilError::InvalidField {
                    field: field_name.clone(),
                    reason:
                        "credential fields cannot be updated via USER UPDATE; use PASSWORD CHANGE"
                            .into(),
                });
            }

            // For non-credential fields, update the user record value
            match treatment {
                shroudb_sigil_core::routing::FieldTreatment::PlaintextIndex
                | shroudb_sigil_core::routing::FieldTreatment::Inert => {
                    record.fields.insert(field_name.clone(), value.clone());
                }
                shroudb_sigil_core::routing::FieldTreatment::EncryptedPii => {
                    let cipher = self
                        .capabilities
                        .cipher
                        .as_ref()
                        .ok_or_else(|| SigilError::CapabilityMissing("cipher".into()))?;
                    let plaintext = value.as_str().ok_or_else(|| SigilError::InvalidField {
                        field: field_name.clone(),
                        reason: "PII field must be a string".into(),
                    })?;
                    let context = format!("{}/{}/{}", schema.name, user_id, field_name);
                    let ciphertext = cipher.encrypt(plaintext.as_bytes(), Some(&context)).await?;
                    record
                        .fields
                        .insert(field_name.clone(), serde_json::json!(ciphertext));
                }
                shroudb_sigil_core::routing::FieldTreatment::SearchableEncrypted => {
                    let cipher = self
                        .capabilities
                        .cipher
                        .as_ref()
                        .ok_or_else(|| SigilError::CapabilityMissing("cipher".into()))?;
                    let veil = self
                        .capabilities
                        .veil
                        .as_ref()
                        .ok_or_else(|| SigilError::CapabilityMissing("veil".into()))?;
                    let plaintext = value.as_str().ok_or_else(|| SigilError::InvalidField {
                        field: field_name.clone(),
                        reason: "searchable PII field must be a string".into(),
                    })?;
                    let context = format!("{}/{}/{}", schema.name, user_id, field_name);
                    let ciphertext = cipher.encrypt(plaintext.as_bytes(), Some(&context)).await?;
                    let entry_id = format!("{}/{}", user_id, field_name);
                    veil.put(&entry_id, plaintext.as_bytes(), Some(field_name))
                        .await?;
                    record
                        .fields
                        .insert(field_name.clone(), serde_json::json!(ciphertext));
                }
                shroudb_sigil_core::routing::FieldTreatment::VersionedSecret => {
                    let keep = self
                        .capabilities
                        .keep
                        .as_ref()
                        .ok_or_else(|| SigilError::CapabilityMissing("keep".into()))?;
                    let secret_bytes = value.to_string().into_bytes();
                    let key = format!("{}/{}/{}", schema.name, user_id, field_name);
                    keep.store_secret(key.as_bytes(), &secret_bytes).await?;
                }
                shroudb_sigil_core::routing::FieldTreatment::Credential => unreachable!(),
            }
        }

        record.updated_at = now_secs();
        let value = serde_json::to_vec(&record).map_err(|e| SigilError::Internal(e.to_string()))?;
        self.store
            .put(&users_ns, user_id.as_bytes(), &value, None)
            .await
            .map_err(|e| SigilError::Store(e.to_string()))?;

        Ok(record)
    }

    /// Delete a user and all associated data (credentials + sessions).
    pub async fn delete_user(&self, schema_name: &str, user_id: &str) -> Result<(), SigilError> {
        let users_ns = users_namespace(schema_name);
        let creds_ns = format!("sigil.{schema_name}.credentials");
        let sessions_ns = format!("sigil.{schema_name}.sessions");

        // Delete user record
        let _ = self.store.delete(&users_ns, user_id.as_bytes()).await;
        // Delete credential record
        let _ = self.store.delete(&creds_ns, user_id.as_bytes()).await;

        // Revoke all sessions for this user
        if let Ok(page) = self.store.list(&sessions_ns, None, None, 10_000).await {
            for key in &page.keys {
                if let Ok(entry) = self.store.get(&sessions_ns, key, None).await
                    && let Ok(record) = serde_json::from_slice::<
                        shroudb_sigil_core::session::RefreshTokenRecord,
                    >(&entry.value)
                    && record.user_id == user_id
                {
                    let _ = self.store.delete(&sessions_ns, key).await;
                }
            }
        }

        Ok(())
    }

    async fn process_field(
        &self,
        schema_name: &str,
        user_id: &str,
        field_name: &str,
        value: &serde_json::Value,
        treatment: FieldTreatment,
        import_mode: bool,
    ) -> Result<FieldWriteResult, SigilError> {
        match treatment {
            FieldTreatment::Credential => {
                let field_value = value.as_str().ok_or_else(|| SigilError::InvalidField {
                    field: field_name.to_string(),
                    reason: "credential field must be a string".into(),
                })?;

                if import_mode {
                    // Import: value is a pre-hashed password — validate and store directly
                    self.credentials
                        .import_password(schema_name, user_id, field_value)
                        .await?;
                } else {
                    // Create: value is plaintext — hash with Argon2id
                    self.credentials
                        .set_password(schema_name, user_id, field_value)
                        .await?;
                }

                Ok(FieldWriteResult {
                    compensating_op: Some(CompensatingOp {
                        namespace: format!("sigil.{schema_name}.credentials"),
                        key: user_id.as_bytes().to_vec(),
                    }),
                    // Don't store the password in the user record
                    user_record_value: None,
                })
            }

            FieldTreatment::EncryptedPii => {
                let cipher = self
                    .capabilities
                    .cipher
                    .as_ref()
                    .ok_or_else(|| SigilError::CapabilityMissing("cipher".into()))?;

                let plaintext = value.as_str().ok_or_else(|| SigilError::InvalidField {
                    field: field_name.to_string(),
                    reason: "PII field must be a string".into(),
                })?;

                let context = format!("{schema_name}/{user_id}/{field_name}");
                let ciphertext = cipher.encrypt(plaintext.as_bytes(), Some(&context)).await?;

                Ok(FieldWriteResult {
                    compensating_op: None,
                    user_record_value: Some(serde_json::json!(ciphertext)),
                })
            }

            FieldTreatment::SearchableEncrypted => {
                let cipher = self
                    .capabilities
                    .cipher
                    .as_ref()
                    .ok_or_else(|| SigilError::CapabilityMissing("cipher".into()))?;
                let veil = self
                    .capabilities
                    .veil
                    .as_ref()
                    .ok_or_else(|| SigilError::CapabilityMissing("veil".into()))?;

                let plaintext = value.as_str().ok_or_else(|| SigilError::InvalidField {
                    field: field_name.to_string(),
                    reason: "searchable PII field must be a string".into(),
                })?;

                let context = format!("{schema_name}/{user_id}/{field_name}");
                let ciphertext = cipher.encrypt(plaintext.as_bytes(), Some(&context)).await?;
                let entry_id = format!("{user_id}/{field_name}");
                veil.put(&entry_id, plaintext.as_bytes(), Some(field_name))
                    .await?;

                Ok(FieldWriteResult {
                    compensating_op: None,
                    user_record_value: Some(serde_json::json!(ciphertext)),
                })
            }

            FieldTreatment::VersionedSecret => {
                let keep = self
                    .capabilities
                    .keep
                    .as_ref()
                    .ok_or_else(|| SigilError::CapabilityMissing("keep".into()))?;

                let secret_bytes = value.to_string().into_bytes();
                let key = format!("{schema_name}/{user_id}/{field_name}");
                keep.store_secret(key.as_bytes(), &secret_bytes).await?;

                Ok(FieldWriteResult {
                    compensating_op: None,
                    user_record_value: None,
                })
            }

            FieldTreatment::PlaintextIndex | FieldTreatment::Inert => {
                // Store directly in the user record
                Ok(FieldWriteResult {
                    compensating_op: None,
                    user_record_value: Some(value.clone()),
                })
            }
        }
    }

    async fn rollback(&self, ops: Vec<CompensatingOp>) {
        for op in ops.into_iter().rev() {
            if let Err(e) = self.store.delete(&op.namespace, &op.key).await {
                tracing::error!(
                    namespace = %op.namespace,
                    error = %e,
                    "compensating DELETE failed during rollback"
                );
            }
        }
    }
}

struct FieldWriteResult {
    /// If set, this operation can be rolled back with a DELETE.
    compensating_op: Option<CompensatingOp>,
    /// If set, this value is stored in the user record (non-sensitive fields only).
    user_record_value: Option<serde_json::Value>,
}

fn users_namespace(schema: &str) -> String {
    format!("sigil.{schema}.users")
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use shroudb_sigil_core::credential::PasswordPolicy;
    use shroudb_sigil_core::schema::{FieldAnnotations, FieldDef, FieldType, Schema};
    use shroudb_store::Store as _;

    use super::*;
    use crate::capabilities::Capabilities;
    use crate::credential::CredentialManager;
    use crate::schema_registry::SchemaRegistry;
    use crate::schema_registry::tests::create_test_store;

    fn test_schema() -> Schema {
        Schema {
            name: "myapp".to_string(),
            fields: vec![
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
                FieldDef {
                    name: "display_name".to_string(),
                    field_type: FieldType::String,
                    annotations: FieldAnnotations::default(),
                },
            ],
        }
    }

    async fn setup() -> (
        Arc<shroudb_storage::EmbeddedStore>,
        WriteCoordinator<shroudb_storage::EmbeddedStore>,
    ) {
        let store = create_test_store().await;

        // Register schema (creates namespaces)
        let registry = SchemaRegistry::new(store.clone());
        registry.init().await.unwrap();
        registry.register(test_schema()).await.unwrap();

        let credentials = Arc::new(CredentialManager::new(
            store.clone(),
            PasswordPolicy::default(),
        ));
        let capabilities = Arc::new(Capabilities::default());
        let coordinator = WriteCoordinator::new(store.clone(), credentials, capabilities);

        (store, coordinator)
    }

    fn user_fields() -> HashMap<String, serde_json::Value> {
        let mut fields = HashMap::new();
        fields.insert(
            "password".to_string(),
            serde_json::Value::String("correcthorse".into()),
        );
        fields.insert(
            "org_id".to_string(),
            serde_json::Value::String("acme-corp".into()),
        );
        fields.insert(
            "display_name".to_string(),
            serde_json::Value::String("Alice".into()),
        );
        fields
    }

    #[tokio::test]
    async fn create_user_stores_fields() {
        let (_store, coord) = setup().await;
        let schema = test_schema();

        let record = coord
            .create_user(&schema, "user1", &user_fields())
            .await
            .unwrap();

        assert_eq!(record.user_id, "user1");
        // org_id and display_name stored in user record (index + inert)
        assert_eq!(record.fields["org_id"], "acme-corp");
        assert_eq!(record.fields["display_name"], "Alice");
        // password NOT in user record (credential → separate namespace)
        assert!(!record.fields.contains_key("password"));
    }

    #[tokio::test]
    async fn create_user_password_verifiable() {
        let (store, coord) = setup().await;
        let schema = test_schema();

        coord
            .create_user(&schema, "user1", &user_fields())
            .await
            .unwrap();

        // Password was stored via CredentialManager — verify it works
        let cred_mgr = CredentialManager::new(store, PasswordPolicy::default());
        let valid = cred_mgr
            .verify("myapp", "user1", "correcthorse")
            .await
            .unwrap();
        assert!(valid);
    }

    #[tokio::test]
    async fn duplicate_user_rejected() {
        let (_store, coord) = setup().await;
        let schema = test_schema();

        coord
            .create_user(&schema, "user1", &user_fields())
            .await
            .unwrap();

        let err = coord
            .create_user(&schema, "user1", &user_fields())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[tokio::test]
    async fn missing_field_rejected() {
        let (_store, coord) = setup().await;
        let schema = test_schema();

        let mut fields = user_fields();
        fields.remove("org_id");

        let err = coord
            .create_user(&schema, "user1", &fields)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("org_id"));
    }

    #[tokio::test]
    async fn get_user_returns_record() {
        let (_store, coord) = setup().await;
        let schema = test_schema();

        coord
            .create_user(&schema, "user1", &user_fields())
            .await
            .unwrap();

        let record = coord.get_user(&schema, "user1").await.unwrap();
        assert_eq!(record.user_id, "user1");
        assert_eq!(record.fields["org_id"], "acme-corp");
    }

    #[tokio::test]
    async fn get_nonexistent_user() {
        let (_store, coord) = setup().await;
        let schema = test_schema();
        let err = coord.get_user(&schema, "nope").await.unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[tokio::test]
    async fn delete_user() {
        let (_store, coord) = setup().await;
        let schema = test_schema();

        coord
            .create_user(&schema, "user1", &user_fields())
            .await
            .unwrap();

        coord.delete_user("myapp", "user1").await.unwrap();

        assert!(coord.get_user(&schema, "user1").await.is_err());
    }

    #[tokio::test]
    async fn pii_field_rejected_without_cipher() {
        let store = create_test_store().await;
        let registry = SchemaRegistry::new(store.clone());
        registry.init().await.unwrap();

        let schema = Schema {
            name: "pii-app".to_string(),
            fields: vec![FieldDef {
                name: "email".to_string(),
                field_type: FieldType::String,
                annotations: FieldAnnotations {
                    pii: true,
                    ..Default::default()
                },
            }],
        };
        registry.register(schema.clone()).await.unwrap();

        let credentials = Arc::new(CredentialManager::new(
            store.clone(),
            PasswordPolicy::default(),
        ));
        let capabilities = Arc::new(Capabilities::default()); // no cipher
        let coord = WriteCoordinator::new(store, credentials, capabilities);

        let mut fields = HashMap::new();
        fields.insert(
            "email".to_string(),
            serde_json::Value::String("a@b.com".into()),
        );

        let err = coord
            .create_user(&schema, "user1", &fields)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("cipher"));
    }

    #[tokio::test]
    async fn rollback_on_failure() {
        let (store, coord) = setup().await;

        // Create a schema with a credential field + a PII field (no cipher available)
        let schema = Schema {
            name: "rollback-test".to_string(),
            fields: vec![
                FieldDef {
                    name: "password".to_string(),
                    field_type: FieldType::String,
                    annotations: FieldAnnotations {
                        credential: true,
                        ..Default::default()
                    },
                },
                FieldDef {
                    name: "email".to_string(),
                    field_type: FieldType::String,
                    annotations: FieldAnnotations {
                        pii: true,
                        ..Default::default()
                    },
                },
            ],
        };

        let registry = SchemaRegistry::new(store.clone());
        registry.register(schema.clone()).await.unwrap();

        let mut fields = HashMap::new();
        fields.insert("password".into(), serde_json::json!("secret123"));
        fields.insert("email".into(), serde_json::json!("a@b.com"));

        // This should fail on the email field (no cipher) and rollback the password
        let err = coord
            .create_user(&schema, "user1", &fields)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("cipher"));

        // Verify the password was rolled back (compensating DELETE)
        let cred_ns = "sigil.rollback-test.credentials";
        let result = store.get(cred_ns, b"user1", None).await;
        assert!(result.is_err(), "credential should have been rolled back");
    }
}
