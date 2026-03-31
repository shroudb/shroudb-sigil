use std::collections::HashMap;
use std::sync::Arc;

use shroudb_acl::{PolicyEffect, PolicyPrincipal, PolicyRequest, PolicyResource};
use shroudb_sigil_core::error::SigilError;
use shroudb_sigil_core::record::EnvelopeRecord;
use shroudb_sigil_core::routing::{FieldTreatment, route_field};
use shroudb_sigil_core::schema::Schema;
use shroudb_store::Store;

use zeroize::Zeroize;

use crate::capabilities::Capabilities;
use crate::credential::CredentialManager;

/// A completed write operation that can be rolled back.
enum CompensatingOp {
    /// Delete a key from a Store namespace (credentials, envelope fields).
    Store { namespace: String, key: Vec<u8> },
    /// Delete a blind index entry from Veil.
    Veil { entry_id: String },
    /// Delete a secret from Keep.
    Keep { path: String },
}

/// Coordinates all-or-nothing multi-field writes.
///
/// A single envelope create can touch credentials (Argon2id hash),
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

    /// Emit an audit event to Chronicle. Fails closed: if Chronicle is configured
    /// but unreachable, the calling operation fails. Security infrastructure must
    /// not allow unaudited credential operations.
    async fn emit_audit_event(
        &self,
        operation: &str,
        resource: &str,
        actor: &str,
    ) -> Result<(), SigilError> {
        let Some(chronicle) = &self.capabilities.chronicle else {
            return Ok(());
        };
        let event = shroudb_chronicle_core::event::Event {
            id: uuid::Uuid::new_v4().to_string(),
            correlation_id: None,
            timestamp: now_secs() * 1000,
            engine: shroudb_chronicle_core::event::Engine::Sigil,
            operation: operation.to_string(),
            resource: resource.to_string(),
            result: shroudb_chronicle_core::event::EventResult::Ok,
            duration_ms: 0,
            actor: actor.to_string(),
            metadata: Default::default(),
        };
        chronicle
            .record(event)
            .await
            .map_err(|e| SigilError::Internal(format!("audit event failed: {e}")))
    }

    async fn check_policy(
        &self,
        entity_id: &str,
        schema_name: &str,
        action: &str,
    ) -> Result<(), SigilError> {
        let Some(sentry) = &self.capabilities.sentry else {
            return Ok(());
        };
        let request = PolicyRequest {
            principal: PolicyPrincipal {
                id: entity_id.to_string(),
                roles: vec![],
                claims: Default::default(),
            },
            resource: PolicyResource {
                id: schema_name.to_string(),
                resource_type: "schema".to_string(),
                attributes: Default::default(),
            },
            action: action.to_string(),
        };
        let decision = sentry
            .evaluate(&request)
            .await
            .map_err(|e| SigilError::Internal(format!("policy evaluation failed: {e}")))?;
        if decision.effect == PolicyEffect::Deny {
            return Err(SigilError::PolicyDenied {
                action: action.to_string(),
                resource: schema_name.to_string(),
                policy: decision.matched_policy.unwrap_or_default(),
            });
        }
        Ok(())
    }

    /// Create an envelope by routing each field to the appropriate handler.
    /// All-or-nothing: if any field fails, all completed writes are rolled back.
    pub async fn create_envelope(
        &self,
        schema: &Schema,
        entity_id: &str,
        fields: &HashMap<String, serde_json::Value>,
    ) -> Result<EnvelopeRecord, SigilError> {
        self.create_envelope_inner(schema, entity_id, fields, false)
            .await
    }

    /// Import an envelope with pre-hashed credential fields.
    ///
    /// Same as `create_envelope` except credential fields are treated as hashes
    /// (validated and stored directly) instead of plaintext (hashed with Argon2id).
    /// Non-credential fields are processed identically to `create_envelope`.
    pub async fn import_envelope(
        &self,
        schema: &Schema,
        entity_id: &str,
        fields: &HashMap<String, serde_json::Value>,
    ) -> Result<EnvelopeRecord, SigilError> {
        self.create_envelope_inner(schema, entity_id, fields, true)
            .await
    }

    async fn create_envelope_inner(
        &self,
        schema: &Schema,
        entity_id: &str,
        fields: &HashMap<String, serde_json::Value>,
        import_mode: bool,
    ) -> Result<EnvelopeRecord, SigilError> {
        // Validate all required fields are present
        for field_def in &schema.fields {
            if !fields.contains_key(&field_def.name) {
                return Err(SigilError::MissingField(field_def.name.clone()));
            }
        }

        // Check for existing entity
        let envelopes_ns = envelopes_namespace(&schema.name);
        if self
            .store
            .get(&envelopes_ns, entity_id.as_bytes(), None)
            .await
            .is_ok()
        {
            return Err(SigilError::EntityExists);
        }

        self.check_policy(entity_id, &schema.name, "create").await?;

        let mut completed_ops: Vec<CompensatingOp> = Vec::new();
        let mut record_fields: HashMap<String, serde_json::Value> = HashMap::new();

        // Process each field according to its treatment
        for field_def in &schema.fields {
            let value = &fields[&field_def.name];
            let treatment = route_field(&field_def.annotations);

            let result = self
                .process_field(
                    &schema.name,
                    entity_id,
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
                    if let Some(stored_value) = field_result.record_value {
                        record_fields.insert(field_def.name.clone(), stored_value);
                    }
                }
                Err(e) => {
                    return Err(self.rollback_and_fail(completed_ops, e).await);
                }
            }
        }

        // Audit event before commit — fail closed if Chronicle is unreachable
        if let Err(e) = self
            .emit_audit_event(
                "create",
                &format!("{}/{}", schema.name, entity_id),
                entity_id,
            )
            .await
        {
            return Err(self.rollback_and_fail(completed_ops, e).await);
        }

        // Write the envelope record — the "commit point"
        let now = now_secs();
        let record = EnvelopeRecord {
            entity_id: entity_id.to_string(),
            fields: record_fields,
            created_at: now,
            updated_at: now,
        };

        let value = serde_json::to_vec(&record).map_err(|e| SigilError::Internal(e.to_string()))?;

        if let Err(e) = self
            .store
            .put(&envelopes_ns, entity_id.as_bytes(), &value, None)
            .await
        {
            let cause = SigilError::Store(e.to_string());
            return Err(self.rollback_and_fail(completed_ops, cause).await);
        }

        Ok(record)
    }

    /// Look up an entity_id by searching a field value via Veil blind index.
    pub async fn lookup_by_field(
        &self,
        field_name: &str,
        field_value: &str,
    ) -> Result<String, SigilError> {
        let veil = self
            .capabilities
            .veil
            .as_ref()
            .ok_or_else(|| SigilError::CapabilityMissing("veil".into()))?;

        let results: Vec<(String, f64)> =
            veil.search(field_value, Some(field_name), Some(1)).await?;

        let (entry_id, _score) = results
            .into_iter()
            .next()
            .ok_or(SigilError::EntityNotFound)?;

        // Entry ID format: "{entity_id}/{field_name}"
        entry_id
            .split('/')
            .next()
            .map(String::from)
            .ok_or_else(|| SigilError::Internal("malformed veil entry id".into()))
    }

    /// Get an envelope record with PII fields redacted.
    ///
    /// PII fields are stored encrypted and are NOT decrypted on read.
    /// The response shows `"[encrypted]"` for PII fields. Plaintext PII
    /// is only accessible via Courier's just-in-time access when there's
    /// a legitimate, auditable reason (e.g., sending a notification).
    pub async fn get_envelope(
        &self,
        schema: &Schema,
        entity_id: &str,
    ) -> Result<EnvelopeRecord, SigilError> {
        let ns = envelopes_namespace(&schema.name);
        let entry = self
            .store
            .get(&ns, entity_id.as_bytes(), None)
            .await
            .map_err(|_| SigilError::EntityNotFound)?;

        let mut record: EnvelopeRecord = serde_json::from_slice(&entry.value)
            .map_err(|e| SigilError::Internal(e.to_string()))?;

        // Redact PII fields — never return plaintext or ciphertext
        for field_def in &schema.fields {
            let treatment = route_field(&field_def.annotations);
            if matches!(
                treatment,
                FieldTreatment::EncryptedPii | FieldTreatment::SearchableEncrypted
            ) && record.fields.contains_key(&field_def.name)
            {
                record
                    .fields
                    .insert(field_def.name.clone(), serde_json::json!("[encrypted]"));
            }
        }

        Ok(record)
    }

    /// Update non-credential fields on an existing envelope.
    /// Credential fields cannot be updated through this method — use
    /// credential change/reset instead.
    pub async fn update_envelope(
        &self,
        schema: &Schema,
        entity_id: &str,
        fields: &HashMap<String, serde_json::Value>,
    ) -> Result<EnvelopeRecord, SigilError> {
        let envelopes_ns = envelopes_namespace(&schema.name);
        let entry = self
            .store
            .get(&envelopes_ns, entity_id.as_bytes(), None)
            .await
            .map_err(|_| SigilError::EntityNotFound)?;

        let mut record: EnvelopeRecord = serde_json::from_slice(&entry.value)
            .map_err(|e| SigilError::Internal(e.to_string()))?;

        // Validate all fields before making any changes
        for field_name in fields.keys() {
            let field_def = schema
                .fields
                .iter()
                .find(|f| f.name == *field_name)
                .ok_or_else(|| SigilError::InvalidField {
                    field: field_name.clone(),
                    reason: "field not in schema".into(),
                })?;

            let treatment = route_field(&field_def.annotations);
            if treatment == FieldTreatment::Credential {
                return Err(SigilError::InvalidField {
                    field: field_name.clone(),
                    reason:
                        "credential fields cannot be updated via ENVELOPE UPDATE; use CREDENTIAL CHANGE"
                            .into(),
                });
            }
        }

        self.check_policy(entity_id, &schema.name, "update").await?;

        // Process fields with rollback tracking (same pattern as create)
        let mut completed_ops: Vec<CompensatingOp> = Vec::new();

        for (field_name, value) in fields {
            let field_def = schema
                .fields
                .iter()
                .find(|f| f.name == *field_name)
                .unwrap(); // safe: validated above

            let treatment = route_field(&field_def.annotations);

            let result = match treatment {
                FieldTreatment::PlaintextIndex | FieldTreatment::Inert => {
                    record.fields.insert(field_name.clone(), value.clone());
                    Ok(None)
                }
                FieldTreatment::EncryptedPii => {
                    let cipher = self
                        .capabilities
                        .cipher
                        .as_ref()
                        .ok_or_else(|| SigilError::CapabilityMissing("cipher".into()))?;
                    let plaintext = value.as_str().ok_or_else(|| SigilError::InvalidField {
                        field: field_name.clone(),
                        reason: "PII field must be a string".into(),
                    })?;
                    let context = format!("{}/{}/{}", schema.name, entity_id, field_name);
                    let ciphertext = cipher.encrypt(plaintext.as_bytes(), Some(&context)).await?;
                    record
                        .fields
                        .insert(field_name.clone(), serde_json::json!(ciphertext));
                    Ok(None)
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
                        field: field_name.clone(),
                        reason: "searchable PII field must be a string".into(),
                    })?;
                    let context = format!("{}/{}/{}", schema.name, entity_id, field_name);
                    let ciphertext = cipher.encrypt(plaintext.as_bytes(), Some(&context)).await?;
                    let entry_id = format!("{}/{}", entity_id, field_name);
                    veil.put(&entry_id, plaintext.as_bytes(), Some(field_name))
                        .await?;
                    record
                        .fields
                        .insert(field_name.clone(), serde_json::json!(ciphertext));
                    Ok(Some(CompensatingOp::Veil { entry_id }))
                }
                FieldTreatment::VersionedSecret => {
                    let keep = self
                        .capabilities
                        .keep
                        .as_ref()
                        .ok_or_else(|| SigilError::CapabilityMissing("keep".into()))?;
                    let mut secret_bytes = value.to_string().into_bytes();
                    let key = format!("{}/{}/{}", schema.name, entity_id, field_name);
                    let result = keep.store_secret(&key, &secret_bytes).await;
                    secret_bytes.zeroize();
                    result?;
                    Ok(Some(CompensatingOp::Keep { path: key }))
                }
                FieldTreatment::Credential => unreachable!(),
            };

            match result {
                Ok(Some(op)) => completed_ops.push(op),
                Ok(None) => {}
                Err(e) => {
                    return Err(self.rollback_and_fail(completed_ops, e).await);
                }
            }
        }

        // Audit event before commit — fail closed if Chronicle is unreachable
        if let Err(e) = self
            .emit_audit_event(
                "update",
                &format!("{}/{}", schema.name, entity_id),
                entity_id,
            )
            .await
        {
            return Err(self.rollback_and_fail(completed_ops, e).await);
        }

        record.updated_at = now_secs();
        let value = serde_json::to_vec(&record).map_err(|e| SigilError::Internal(e.to_string()))?;
        if let Err(e) = self
            .store
            .put(&envelopes_ns, entity_id.as_bytes(), &value, None)
            .await
        {
            let cause = SigilError::Store(e.to_string());
            return Err(self.rollback_and_fail(completed_ops, cause).await);
        }

        Ok(record)
    }

    /// Delete an envelope and all associated data (credentials, sessions,
    /// blind index entries).
    ///
    /// Deletion order: associated data first (credentials, blind indexes,
    /// sessions), then the envelope record last. The envelope record is the
    /// commit point — if any pre-deletion fails, the envelope remains intact
    /// and the error is propagated.
    pub async fn delete_envelope(
        &self,
        schema: &Schema,
        entity_id: &str,
    ) -> Result<(), SigilError> {
        self.check_policy(entity_id, &schema.name, "delete").await?;

        let schema_name = &schema.name;
        let envelopes_ns = envelopes_namespace(schema_name);
        let creds_ns = format!("sigil.{schema_name}.credentials");
        let sessions_ns = format!("sigil.{schema_name}.sessions");

        // Verify envelope exists before deleting associated data
        self.store
            .get(&envelopes_ns, entity_id.as_bytes(), None)
            .await
            .map_err(|_| SigilError::EntityNotFound)?;

        // Phase 1: Delete associated data (before envelope commit point)

        // Delete credential records
        for field_def in &schema.fields {
            let treatment = route_field(&field_def.annotations);
            match treatment {
                FieldTreatment::Credential => {
                    let key = credential_store_key(entity_id, &field_def.name);
                    if let Err(e) = self.store.delete(&creds_ns, key.as_bytes()).await {
                        tracing::debug!(
                            key = %key,
                            error = %e,
                            "credential not found during delete (may not have been populated)"
                        );
                    }
                }
                FieldTreatment::SearchableEncrypted => {
                    if let Some(veil) = &self.capabilities.veil {
                        let entry_id = format!("{entity_id}/{}", field_def.name);
                        if let Err(e) = veil.delete(&entry_id).await {
                            tracing::warn!(
                                entry_id = %entry_id,
                                error = %e,
                                "blind index entry not cleaned up during delete"
                            );
                        }
                    }
                }
                FieldTreatment::VersionedSecret => {
                    if let Some(keep) = &self.capabilities.keep {
                        let path = format!("{schema_name}/{entity_id}/{}", field_def.name);
                        if let Err(e) = keep.delete_secret(&path).await {
                            tracing::debug!(
                                path = %path,
                                error = %e,
                                "secret not found during delete"
                            );
                        }
                    }
                }
                _ => {}
            }
        }

        // Delete all sessions for this entity
        if let Ok(page) = self.store.list(&sessions_ns, None, None, 10_000).await {
            // Collect matching session keys first, then delete all
            let mut session_keys = Vec::new();
            for key in &page.keys {
                if let Ok(entry) = self.store.get(&sessions_ns, key, None).await
                    && let Ok(record) = serde_json::from_slice::<
                        shroudb_sigil_core::session::RefreshTokenRecord,
                    >(&entry.value)
                    && record.entity_id == entity_id
                {
                    session_keys.push(key.clone());
                }
            }
            for key in &session_keys {
                if let Err(e) = self.store.delete(&sessions_ns, key).await {
                    tracing::warn!(
                        error = %e,
                        "session not cleaned up during delete"
                    );
                }
            }
        }

        // Audit event before commit — fail closed if Chronicle is unreachable
        self.emit_audit_event(
            "delete",
            &format!("{}/{}", schema_name, entity_id),
            entity_id,
        )
        .await?;

        // Phase 2: Delete envelope record (commit point)
        self.store
            .delete(&envelopes_ns, entity_id.as_bytes())
            .await
            .map_err(|e| SigilError::Store(e.to_string()))?;

        Ok(())
    }

    async fn process_field(
        &self,
        schema_name: &str,
        entity_id: &str,
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
                        .import_credential(schema_name, entity_id, field_name, field_value)
                        .await?;
                } else {
                    // Create: value is plaintext — hash with Argon2id
                    self.credentials
                        .set_credential(schema_name, entity_id, field_name, field_value)
                        .await?;
                }

                Ok(FieldWriteResult {
                    compensating_op: Some(CompensatingOp::Store {
                        namespace: format!("sigil.{schema_name}.credentials"),
                        key: credential_store_key(entity_id, field_name).into_bytes(),
                    }),
                    // Don't store the credential in the envelope record
                    record_value: None,
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

                let context = format!("{schema_name}/{entity_id}/{field_name}");
                let ciphertext = cipher.encrypt(plaintext.as_bytes(), Some(&context)).await?;

                Ok(FieldWriteResult {
                    compensating_op: None,
                    record_value: Some(serde_json::json!(ciphertext)),
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

                let context = format!("{schema_name}/{entity_id}/{field_name}");
                let ciphertext = cipher.encrypt(plaintext.as_bytes(), Some(&context)).await?;
                let entry_id = format!("{entity_id}/{field_name}");
                veil.put(&entry_id, plaintext.as_bytes(), Some(field_name))
                    .await?;

                Ok(FieldWriteResult {
                    compensating_op: Some(CompensatingOp::Veil { entry_id }),
                    record_value: Some(serde_json::json!(ciphertext)),
                })
            }

            FieldTreatment::VersionedSecret => {
                let keep = self
                    .capabilities
                    .keep
                    .as_ref()
                    .ok_or_else(|| SigilError::CapabilityMissing("keep".into()))?;

                let mut secret_bytes = value.to_string().into_bytes();
                let key = format!("{schema_name}/{entity_id}/{field_name}");
                let result = keep.store_secret(&key, &secret_bytes).await;
                secret_bytes.zeroize();
                result?;

                Ok(FieldWriteResult {
                    compensating_op: Some(CompensatingOp::Keep { path: key }),
                    record_value: None,
                })
            }

            FieldTreatment::PlaintextIndex | FieldTreatment::Inert => {
                // Store directly in the envelope record
                Ok(FieldWriteResult {
                    compensating_op: None,
                    record_value: Some(value.clone()),
                })
            }
        }
    }

    /// Rollback completed operations and surface any orphans in the error.
    async fn rollback_and_fail(&self, ops: Vec<CompensatingOp>, cause: SigilError) -> SigilError {
        let orphans = self.rollback(ops).await;
        if orphans.is_empty() {
            cause
        } else {
            tracing::warn!(
                orphans = ?orphans,
                "rollback left orphaned data that could not be cleaned up"
            );
            SigilError::Internal(format!(
                "{cause} (rollback orphans: {})",
                orphans.join(", ")
            ))
        }
    }

    /// Execute compensating operations in reverse order. Returns descriptions
    /// of any operations that failed — these represent orphaned data that
    /// could not be cleaned up.
    async fn rollback(&self, ops: Vec<CompensatingOp>) -> Vec<String> {
        let mut orphans = Vec::new();
        for op in ops.into_iter().rev() {
            match op {
                CompensatingOp::Store { namespace, key } => {
                    if let Err(e) = self.store.delete(&namespace, &key).await {
                        let desc = format!("store:{namespace}/{}", String::from_utf8_lossy(&key));
                        tracing::error!(
                            orphan = %desc,
                            error = %e,
                            "compensating store DELETE failed during rollback"
                        );
                        orphans.push(desc);
                    }
                }
                CompensatingOp::Veil { entry_id } => {
                    if let Some(veil) = &self.capabilities.veil
                        && let Err(e) = veil.delete(&entry_id).await
                    {
                        let desc = format!("veil:{entry_id}");
                        tracing::error!(
                            orphan = %desc,
                            error = %e,
                            "compensating veil DELETE failed during rollback"
                        );
                        orphans.push(desc);
                    }
                }
                CompensatingOp::Keep { path } => {
                    if let Some(keep) = &self.capabilities.keep
                        && let Err(e) = keep.delete_secret(&path).await
                    {
                        let desc = format!("keep:{path}");
                        tracing::error!(
                            orphan = %desc,
                            error = %e,
                            "compensating keep DELETE failed during rollback"
                        );
                        orphans.push(desc);
                    }
                }
            }
        }
        orphans
    }
}

struct FieldWriteResult {
    /// If set, this operation can be rolled back with a DELETE.
    compensating_op: Option<CompensatingOp>,
    /// If set, this value is stored in the envelope record (non-sensitive fields only).
    record_value: Option<serde_json::Value>,
}

fn envelopes_namespace(schema: &str) -> String {
    format!("sigil.{schema}.envelopes")
}

/// Storage key for a credential record: `{entity_id}/{field_name}`.
/// Multi-credential schemas store each credential field separately.
pub(crate) fn credential_store_key(entity_id: &str, field_name: &str) -> String {
    format!("{entity_id}/{field_name}")
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
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

    fn entity_fields() -> HashMap<String, serde_json::Value> {
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
    async fn create_envelope_stores_fields() {
        let (_store, coord) = setup().await;
        let schema = test_schema();

        let record = coord
            .create_envelope(&schema, "user1", &entity_fields())
            .await
            .unwrap();

        assert_eq!(record.entity_id, "user1");
        // org_id and display_name stored in envelope record (index + inert)
        assert_eq!(record.fields["org_id"], "acme-corp");
        assert_eq!(record.fields["display_name"], "Alice");
        // password NOT in envelope record (credential → separate namespace)
        assert!(!record.fields.contains_key("password"));
    }

    #[tokio::test]
    async fn create_envelope_credential_verifiable() {
        let (store, coord) = setup().await;
        let schema = test_schema();

        coord
            .create_envelope(&schema, "user1", &entity_fields())
            .await
            .unwrap();

        // Credential was stored via CredentialManager — verify it works
        let cred_mgr = CredentialManager::new(store, PasswordPolicy::default());
        let valid = cred_mgr
            .verify("myapp", "user1", "password", "correcthorse")
            .await
            .unwrap();
        assert!(valid);
    }

    #[tokio::test]
    async fn duplicate_envelope_rejected() {
        let (_store, coord) = setup().await;
        let schema = test_schema();

        coord
            .create_envelope(&schema, "user1", &entity_fields())
            .await
            .unwrap();

        let err = coord
            .create_envelope(&schema, "user1", &entity_fields())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[tokio::test]
    async fn missing_field_rejected() {
        let (_store, coord) = setup().await;
        let schema = test_schema();

        let mut fields = entity_fields();
        fields.remove("org_id");

        let err = coord
            .create_envelope(&schema, "user1", &fields)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("org_id"));
    }

    #[tokio::test]
    async fn get_envelope_returns_record() {
        let (_store, coord) = setup().await;
        let schema = test_schema();

        coord
            .create_envelope(&schema, "user1", &entity_fields())
            .await
            .unwrap();

        let record = coord.get_envelope(&schema, "user1").await.unwrap();
        assert_eq!(record.entity_id, "user1");
        assert_eq!(record.fields["org_id"], "acme-corp");
    }

    #[tokio::test]
    async fn get_nonexistent_envelope() {
        let (_store, coord) = setup().await;
        let schema = test_schema();
        let err = coord.get_envelope(&schema, "nope").await.unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[tokio::test]
    async fn delete_envelope() {
        let (_store, coord) = setup().await;
        let schema = test_schema();

        coord
            .create_envelope(&schema, "user1", &entity_fields())
            .await
            .unwrap();

        coord.delete_envelope(&schema, "user1").await.unwrap();

        assert!(coord.get_envelope(&schema, "user1").await.is_err());
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
            .create_envelope(&schema, "user1", &fields)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("cipher"));
    }

    /// In-memory KeepOps for testing rollback behavior.
    struct TestKeepOps {
        secrets: Arc<std::sync::Mutex<HashMap<String, Vec<u8>>>>,
    }

    impl TestKeepOps {
        fn new() -> Self {
            Self {
                secrets: Arc::new(std::sync::Mutex::new(HashMap::new())),
            }
        }
    }

    impl crate::capabilities::KeepOps for TestKeepOps {
        fn store_secret(
            &self,
            path: &str,
            value: &[u8],
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<u64, SigilError>> + Send + '_>>
        {
            let path = path.to_string();
            let value = value.to_vec();
            Box::pin(async move {
                self.secrets.lock().unwrap().insert(path, value);
                Ok(1)
            })
        }

        fn delete_secret(
            &self,
            path: &str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), SigilError>> + Send + '_>>
        {
            let path = path.to_string();
            Box::pin(async move {
                self.secrets.lock().unwrap().remove(&path);
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn rollback_keep_secret_on_subsequent_failure() {
        // Schema: secret field first, then PII field (no cipher → fails).
        // Verify: secret stored by Keep is deleted during rollback.
        let store = create_test_store().await;
        let registry = SchemaRegistry::new(store.clone());
        registry.init().await.unwrap();

        let schema = Schema {
            name: "keep-rollback".to_string(),
            fields: vec![
                FieldDef {
                    name: "api_key".to_string(),
                    field_type: FieldType::String,
                    annotations: FieldAnnotations {
                        secret: true,
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
        registry.register(schema.clone()).await.unwrap();

        let keep = TestKeepOps::new();
        let keep_secrets = keep.secrets.clone();
        let capabilities = Arc::new(Capabilities {
            keep: Some(Box::new(keep)),
            ..Default::default() // no cipher — will fail on PII field
        });

        let credentials = Arc::new(CredentialManager::new(
            store.clone(),
            PasswordPolicy::default(),
        ));
        let coord = WriteCoordinator::new(store.clone(), credentials, capabilities);

        let mut fields = HashMap::new();
        fields.insert("api_key".into(), serde_json::json!("sk-secret-key-12345"));
        fields.insert("email".into(), serde_json::json!("user@example.com"));

        // Create should fail on the PII field (no cipher)
        let err = coord
            .create_envelope(&schema, "user1", &fields)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("cipher"),
            "expected cipher missing error, got: {err}"
        );

        // The secret should have been rolled back (delete_secret called)
        assert!(
            keep_secrets.lock().unwrap().is_empty(),
            "secret should have been deleted during rollback, but Keep still contains: {:?}",
            keep_secrets.lock().unwrap().keys().collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn rollback_credential_and_keep_on_subsequent_failure() {
        // Schema: credential + secret + PII. No cipher → fails on PII.
        // Verify: both credential and secret are rolled back.
        let store = create_test_store().await;
        let registry = SchemaRegistry::new(store.clone());
        registry.init().await.unwrap();

        let schema = Schema {
            name: "multi-rollback".to_string(),
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
                    name: "api_key".to_string(),
                    field_type: FieldType::String,
                    annotations: FieldAnnotations {
                        secret: true,
                        ..Default::default()
                    },
                },
                FieldDef {
                    name: "ssn".to_string(),
                    field_type: FieldType::String,
                    annotations: FieldAnnotations {
                        pii: true,
                        ..Default::default()
                    },
                },
            ],
        };
        registry.register(schema.clone()).await.unwrap();

        let keep = TestKeepOps::new();
        let keep_secrets = keep.secrets.clone();
        let capabilities = Arc::new(Capabilities {
            keep: Some(Box::new(keep)),
            ..Default::default()
        });

        let credentials = Arc::new(CredentialManager::new(
            store.clone(),
            PasswordPolicy::default(),
        ));
        let coord = WriteCoordinator::new(store.clone(), credentials, capabilities);

        let mut fields = HashMap::new();
        fields.insert("password".into(), serde_json::json!("hunter2-longpassword"));
        fields.insert("api_key".into(), serde_json::json!("sk-prod-abc"));
        fields.insert("ssn".into(), serde_json::json!("123-45-6789"));

        let err = coord
            .create_envelope(&schema, "user1", &fields)
            .await
            .unwrap_err();
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("cipher"),
            "expected cipher missing error, got: {err_msg}"
        );

        // Credential should be rolled back
        let cred_ns = "sigil.multi-rollback.credentials";
        let cred_key = credential_store_key("user1", "password");
        let result = store.get(cred_ns, cred_key.as_bytes(), None).await;
        assert!(result.is_err(), "credential should have been rolled back");

        // Secret should be rolled back
        assert!(
            keep_secrets.lock().unwrap().is_empty(),
            "secret should have been deleted during rollback"
        );
    }

    /// Mock CipherOps that returns a deterministic ciphertext.
    struct TestCipherOps;

    impl crate::capabilities::CipherOps for TestCipherOps {
        fn encrypt(
            &self,
            _plaintext: &[u8],
            _context: Option<&str>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<String, SigilError>> + Send + '_>,
        > {
            Box::pin(async { Ok("test-ciphertext".to_string()) })
        }

        fn decrypt(
            &self,
            _ciphertext: &str,
            _context: Option<&str>,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<shroudb_crypto::SensitiveBytes, SigilError>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async { Ok(shroudb_crypto::SensitiveBytes::new(vec![])) })
        }
    }

    /// Mock VeilOps that tracks put/delete calls for verification.
    struct TestVeilOps {
        entries: Arc<std::sync::Mutex<HashMap<String, Vec<u8>>>>,
    }

    impl TestVeilOps {
        fn new() -> Self {
            Self {
                entries: Arc::new(std::sync::Mutex::new(HashMap::new())),
            }
        }
    }

    impl crate::capabilities::VeilOps for TestVeilOps {
        fn put(
            &self,
            entry_id: &str,
            plaintext: &[u8],
            _field: Option<&str>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), SigilError>> + Send + '_>>
        {
            let id = entry_id.to_string();
            let data = plaintext.to_vec();
            Box::pin(async move {
                self.entries.lock().unwrap().insert(id, data);
                Ok(())
            })
        }

        fn delete(
            &self,
            entry_id: &str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), SigilError>> + Send + '_>>
        {
            let id = entry_id.to_string();
            Box::pin(async move {
                self.entries.lock().unwrap().remove(&id);
                Ok(())
            })
        }

        fn search(
            &self,
            _query: &str,
            _field: Option<&str>,
            _limit: Option<usize>,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<Vec<(String, f64)>, SigilError>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async { Ok(vec![]) })
        }
    }

    #[tokio::test]
    async fn rollback_veil_entry_on_subsequent_failure() {
        // Schema: searchable+pii field (Cipher + Veil) → secret field (Keep missing → fails).
        // Verify: Veil entry is deleted during rollback.
        let store = create_test_store().await;
        let registry = SchemaRegistry::new(store.clone());
        registry.init().await.unwrap();

        let schema = Schema {
            name: "veil-rollback".to_string(),
            fields: vec![
                FieldDef {
                    name: "email".to_string(),
                    field_type: FieldType::String,
                    annotations: FieldAnnotations {
                        pii: true,
                        searchable: true,
                        ..Default::default()
                    },
                },
                FieldDef {
                    name: "api_key".to_string(),
                    field_type: FieldType::String,
                    annotations: FieldAnnotations {
                        secret: true,
                        ..Default::default()
                    },
                },
            ],
        };
        registry.register(schema.clone()).await.unwrap();

        let veil = TestVeilOps::new();
        let veil_entries = veil.entries.clone();
        let capabilities = Arc::new(Capabilities {
            cipher: Some(Box::new(TestCipherOps)),
            veil: Some(Box::new(veil)),
            // No keep → will fail on the secret field
            ..Default::default()
        });

        let credentials = Arc::new(CredentialManager::new(
            store.clone(),
            PasswordPolicy::default(),
        ));
        let coord = WriteCoordinator::new(store.clone(), credentials, capabilities);

        let mut fields = HashMap::new();
        fields.insert("email".into(), serde_json::json!("user@example.com"));
        fields.insert("api_key".into(), serde_json::json!("sk-secret-12345"));

        // Should fail on secret field (no Keep)
        let err = coord
            .create_envelope(&schema, "user1", &fields)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("keep"),
            "expected keep missing error, got: {err}"
        );

        // Veil entry should have been rolled back
        assert!(
            veil_entries.lock().unwrap().is_empty(),
            "veil entry should have been deleted during rollback, but entries remain: {:?}",
            veil_entries.lock().unwrap().keys().collect::<Vec<_>>()
        );

        // Envelope should not exist
        assert!(coord.get_envelope(&schema, "user1").await.is_err());
    }

    #[tokio::test]
    async fn rollback_all_capabilities_on_failure() {
        // Schema: credential → searchable+pii (Cipher+Veil) → secret (Keep) → plain pii (no cipher for second encrypt).
        // Actually: credential → searchable+pii → secret → another pii field (fails: cipher succeeds but this tests full chain).
        // Simpler: use all three capabilities, then fail on a missing one.
        //
        // credential + searchable+pii + secret fields all succeed,
        // then a plain pii field fails because... we need a FailingCipherOps.
        //
        // Let's use: credential → secret (Keep) → searchable+pii (Cipher+Veil).
        // Provide Keep but NOT Cipher+Veil → fails on searchable+pii → rolls back credential + secret.
        let store = create_test_store().await;
        let registry = SchemaRegistry::new(store.clone());
        registry.init().await.unwrap();

        let schema = Schema {
            name: "full-rollback".to_string(),
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
                    name: "api_key".to_string(),
                    field_type: FieldType::String,
                    annotations: FieldAnnotations {
                        secret: true,
                        ..Default::default()
                    },
                },
                FieldDef {
                    name: "email".to_string(),
                    field_type: FieldType::String,
                    annotations: FieldAnnotations {
                        pii: true,
                        searchable: true,
                        ..Default::default()
                    },
                },
            ],
        };
        registry.register(schema.clone()).await.unwrap();

        let keep = TestKeepOps::new();
        let keep_secrets = keep.secrets.clone();
        let capabilities = Arc::new(Capabilities {
            keep: Some(Box::new(keep)),
            // No cipher, no veil → will fail on searchable+pii field
            ..Default::default()
        });

        let credentials = Arc::new(CredentialManager::new(
            store.clone(),
            PasswordPolicy::default(),
        ));
        let coord = WriteCoordinator::new(store.clone(), credentials, capabilities);

        let mut fields = HashMap::new();
        fields.insert(
            "password".into(),
            serde_json::json!("correct-horse-battery"),
        );
        fields.insert("api_key".into(), serde_json::json!("sk-test-key"));
        fields.insert("email".into(), serde_json::json!("user@test.com"));

        let err = coord
            .create_envelope(&schema, "user1", &fields)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("cipher"),
            "expected cipher missing error, got: {err}"
        );

        // Credential should be rolled back
        let cred_ns = "sigil.full-rollback.credentials";
        let cred_key = credential_store_key("user1", "password");
        assert!(
            store.get(cred_ns, cred_key.as_bytes(), None).await.is_err(),
            "credential should have been rolled back"
        );

        // Secret should be rolled back
        assert!(
            keep_secrets.lock().unwrap().is_empty(),
            "secret should have been deleted during rollback"
        );

        // Envelope should not exist
        assert!(coord.get_envelope(&schema, "user1").await.is_err());
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
            .create_envelope(&schema, "user1", &fields)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("cipher"));

        // Verify the credential was rolled back (compensating DELETE)
        let cred_ns = "sigil.rollback-test.credentials";
        let cred_key = credential_store_key("user1", "password");
        let result = store.get(cred_ns, cred_key.as_bytes(), None).await;
        assert!(result.is_err(), "credential should have been rolled back");
    }

    // ── Audit fail-closed tests ─────────────────────────────────────

    /// ChronicleOps that always fails, simulating an unreachable audit system.
    struct FailingChronicleOps;

    impl shroudb_chronicle_core::ops::ChronicleOps for FailingChronicleOps {
        fn record(
            &self,
            _event: shroudb_chronicle_core::event::Event,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>>
        {
            Box::pin(async { Err("chronicle unreachable".to_string()) })
        }

        fn record_batch(
            &self,
            _events: Vec<shroudb_chronicle_core::event::Event>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>>
        {
            Box::pin(async { Err("chronicle unreachable".to_string()) })
        }
    }

    #[tokio::test]
    async fn audit_event_failure_blocks_create() {
        // If Chronicle is configured but unreachable, create_envelope must fail.
        // Security infrastructure cannot allow unaudited operations.
        let store = create_test_store().await;
        let registry = SchemaRegistry::new(store.clone());
        registry.init().await.unwrap();

        let schema = Schema {
            name: "audit-test".to_string(),
            fields: vec![FieldDef {
                name: "org_id".to_string(),
                field_type: FieldType::String,
                annotations: FieldAnnotations {
                    index: true,
                    ..Default::default()
                },
            }],
        };
        registry.register(schema.clone()).await.unwrap();

        let capabilities = Arc::new(Capabilities {
            chronicle: Some(Arc::new(FailingChronicleOps)),
            ..Default::default()
        });
        let credentials = Arc::new(CredentialManager::new(
            store.clone(),
            PasswordPolicy::default(),
        ));
        let coord = WriteCoordinator::new(store.clone(), credentials, capabilities);

        let mut fields = HashMap::new();
        fields.insert("org_id".into(), serde_json::json!("acme"));

        let err = coord
            .create_envelope(&schema, "user1", &fields)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("audit"),
            "expected audit failure error, got: {err}"
        );

        // Envelope should NOT exist — operation failed before returning Ok
        assert!(
            coord.get_envelope(&schema, "user1").await.is_err(),
            "envelope should not exist after audit failure"
        );
    }

    #[tokio::test]
    async fn audit_event_failure_blocks_delete() {
        // Same for delete: if audit fails, the operation should fail.
        let store = create_test_store().await;
        let registry = SchemaRegistry::new(store.clone());
        registry.init().await.unwrap();

        let schema = Schema {
            name: "audit-del".to_string(),
            fields: vec![FieldDef {
                name: "name".to_string(),
                field_type: FieldType::String,
                annotations: FieldAnnotations::default(),
            }],
        };
        registry.register(schema.clone()).await.unwrap();

        // Create without chronicle (succeeds)
        let credentials = Arc::new(CredentialManager::new(
            store.clone(),
            PasswordPolicy::default(),
        ));
        let no_chronicle = Arc::new(Capabilities::default());
        let coord_create = WriteCoordinator::new(store.clone(), credentials.clone(), no_chronicle);

        let mut fields = HashMap::new();
        fields.insert("name".into(), serde_json::json!("Alice"));
        coord_create
            .create_envelope(&schema, "user1", &fields)
            .await
            .unwrap();

        // Now delete WITH failing chronicle
        let with_chronicle = Arc::new(Capabilities {
            chronicle: Some(Arc::new(FailingChronicleOps)),
            ..Default::default()
        });
        let coord_delete = WriteCoordinator::new(store.clone(), credentials, with_chronicle);

        let err = coord_delete
            .delete_envelope(&schema, "user1")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("audit"),
            "expected audit failure error, got: {err}"
        );
    }

    // ── Delete path correctness tests ───────────────────────────────

    /// VeilOps that fails on delete, simulating unreachable Veil during cleanup.
    struct FailingVeilDeleteOps;

    impl crate::capabilities::VeilOps for FailingVeilDeleteOps {
        fn put(
            &self,
            _entry_id: &str,
            _plaintext: &[u8],
            _field: Option<&str>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), SigilError>> + Send + '_>>
        {
            Box::pin(async { Ok(()) })
        }

        fn delete(
            &self,
            _entry_id: &str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), SigilError>> + Send + '_>>
        {
            Box::pin(async { Err(SigilError::Internal("veil unreachable".into())) })
        }

        fn search(
            &self,
            _query: &str,
            _field: Option<&str>,
            _limit: Option<usize>,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<Vec<(String, f64)>, SigilError>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async { Ok(vec![]) })
        }
    }

    #[tokio::test]
    async fn delete_succeeds_despite_veil_cleanup_failure() {
        // Delete is best-effort for associated data cleanup. If Veil blind
        // index cleanup fails, the envelope is still deleted (logged at WARN).
        let store = create_test_store().await;
        let registry = SchemaRegistry::new(store.clone());
        registry.init().await.unwrap();

        let schema = Schema {
            name: "del-veil-fail".to_string(),
            fields: vec![FieldDef {
                name: "email".to_string(),
                field_type: FieldType::String,
                annotations: FieldAnnotations {
                    pii: true,
                    searchable: true,
                    ..Default::default()
                },
            }],
        };
        registry.register(schema.clone()).await.unwrap();

        // Create with working capabilities
        let credentials = Arc::new(CredentialManager::new(
            store.clone(),
            PasswordPolicy::default(),
        ));
        let working_caps = Arc::new(Capabilities {
            cipher: Some(Box::new(TestCipherOps)),
            veil: Some(Box::new(TestVeilOps::new())),
            ..Default::default()
        });
        let coord = WriteCoordinator::new(store.clone(), credentials.clone(), working_caps);

        let mut fields = HashMap::new();
        fields.insert("email".into(), serde_json::json!("user@test.com"));
        coord
            .create_envelope(&schema, "user1", &fields)
            .await
            .unwrap();

        // Delete with failing Veil — should succeed anyway (best-effort cleanup)
        let failing_caps = Arc::new(Capabilities {
            cipher: Some(Box::new(TestCipherOps)),
            veil: Some(Box::new(FailingVeilDeleteOps)),
            ..Default::default()
        });
        let coord_del = WriteCoordinator::new(store.clone(), credentials, failing_caps);

        coord_del
            .delete_envelope(&schema, "user1")
            .await
            .expect("delete should succeed despite Veil cleanup failure");

        // Envelope should be gone — delete completed
        assert!(
            coord_del.get_envelope(&schema, "user1").await.is_err(),
            "envelope should be deleted"
        );
    }
}
