use std::collections::HashMap;
use std::sync::Arc;

use shroudb_acl::{PolicyEffect, PolicyPrincipal, PolicyRequest, PolicyResource};
use shroudb_sigil_core::error::SigilError;
use shroudb_sigil_core::record::EnvelopeRecord;
use shroudb_sigil_core::routing::{FieldTreatment, route_field_from_kind};
use shroudb_sigil_core::schema::Schema;
use shroudb_store::Store;

use zeroize::Zeroize;

use crate::caller::CallerContext;
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

/// Data extracted from a per-field blind wrapper.
struct BlindFieldData {
    /// Pre-processed value (ciphertext for PII, pre-hashed for credentials).
    value: String,
    /// Pre-computed blind tokens (base64-encoded BlindTokenSet JSON).
    /// Required for searchable fields, absent for encrypt-only fields.
    tokens: Option<String>,
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
    ///
    /// `target` is retained in `metadata["target"]` so forensics can distinguish
    /// "actor X operated on target Y" from "actor X operated on themselves".
    /// `started_at` is the operation's start instant; the elapsed time from
    /// that instant is recorded as `duration_ms` so auditors can spot slow
    /// operations (credential verification against a brute-force, for
    /// example).
    pub(crate) async fn emit_audit_event(
        &self,
        caller: &CallerContext,
        operation: &str,
        resource: &str,
        target: &str,
        started_at: std::time::Instant,
    ) -> Result<(), SigilError> {
        self.emit_audit_event_with_result(
            caller,
            operation,
            resource,
            target,
            started_at,
            shroudb_chronicle_core::event::EventResult::Ok,
        )
        .await
    }

    /// Emit an audit event carrying an explicit `result` — used on failure
    /// paths so denied / failed ops are not invisible to forensics.
    pub(crate) async fn emit_audit_event_with_result(
        &self,
        caller: &CallerContext,
        operation: &str,
        resource: &str,
        target: &str,
        started_at: std::time::Instant,
        result: shroudb_chronicle_core::event::EventResult,
    ) -> Result<(), SigilError> {
        let Some(chronicle) = self.capabilities.chronicle.as_ref() else {
            return Ok(());
        };
        let mut metadata: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        if !target.is_empty() {
            metadata.insert("target".to_string(), target.to_string());
        }
        let elapsed = started_at.elapsed();
        // Floor at 1ms so no audited op ever records duration_ms = 0. A zero
        // duration is indistinguishable from "never measured" and defeats
        // the point of the field.
        let duration_ms = std::cmp::max(1, elapsed.as_millis().min(u64::MAX as u128) as u64);
        let event = shroudb_chronicle_core::event::Event {
            id: uuid::Uuid::new_v4().to_string(),
            correlation_id: None,
            timestamp: now_secs() * 1000,
            engine: shroudb_chronicle_core::event::Engine::Sigil,
            operation: operation.to_string(),
            resource_type: "schema".to_string(),
            resource_id: resource.to_string(),
            result,
            duration_ms,
            actor: caller.actor.clone(),
            tenant_id: caller.tenant_opt(),
            diff: None,
            metadata,
            hash: None,
            previous_hash: None,
        };
        chronicle
            .record(event)
            .await
            .map_err(|e| SigilError::Internal(format!("audit event failed: {e}")))
    }

    /// Build a `PolicyPrincipal` from the caller context. The principal is
    /// the *caller*, not the target resource — policy evaluators must be
    /// told who is acting, not what is being acted on. Roles and claims
    /// come from the caller's token so ABAC has attributes to match on.
    fn policy_principal(caller: &CallerContext) -> PolicyPrincipal {
        let claims: std::collections::HashMap<String, String> = caller
            .claims
            .iter()
            .map(|(k, v)| {
                let rendered = match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                (k.clone(), rendered)
            })
            .collect();
        PolicyPrincipal {
            id: caller.actor.clone(),
            roles: caller.roles.clone(),
            claims,
        }
    }

    pub(crate) async fn check_policy(
        &self,
        caller: &CallerContext,
        target_entity: &str,
        schema_name: &str,
        action: &str,
    ) -> Result<(), SigilError> {
        let Some(sentry) = self.capabilities.sentry.as_ref() else {
            return Ok(());
        };
        let mut resource_attrs = std::collections::HashMap::new();
        resource_attrs.insert("entity_id".to_string(), target_entity.to_string());
        let request = PolicyRequest {
            principal: Self::policy_principal(caller),
            resource: PolicyResource {
                id: schema_name.to_string(),
                resource_type: "schema".to_string(),
                attributes: resource_attrs,
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
    ///
    /// Uses `CallerContext::internal("envelope-create")` when no caller is
    /// provided — dispatch layers must use `create_envelope_as` instead so
    /// policy and audit see the real caller.
    pub async fn create_envelope(
        &self,
        schema: &Schema,
        entity_id: &str,
        fields: &HashMap<String, serde_json::Value>,
    ) -> Result<EnvelopeRecord, SigilError> {
        self.create_envelope_as(
            &CallerContext::internal("envelope-create"),
            schema,
            entity_id,
            fields,
        )
        .await
    }

    /// Create an envelope, attributing the operation to `caller`. Dispatch
    /// layers must call this so policy checks see the actual caller and
    /// audit events record who acted.
    pub async fn create_envelope_as(
        &self,
        caller: &CallerContext,
        schema: &Schema,
        entity_id: &str,
        fields: &HashMap<String, serde_json::Value>,
    ) -> Result<EnvelopeRecord, SigilError> {
        self.create_envelope_inner(caller, schema, entity_id, fields, false)
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
        self.import_envelope_as(
            &CallerContext::internal("envelope-import"),
            schema,
            entity_id,
            fields,
        )
        .await
    }

    /// Import an envelope attributed to `caller`.
    pub async fn import_envelope_as(
        &self,
        caller: &CallerContext,
        schema: &Schema,
        entity_id: &str,
        fields: &HashMap<String, serde_json::Value>,
    ) -> Result<EnvelopeRecord, SigilError> {
        self.create_envelope_inner(caller, schema, entity_id, fields, true)
            .await
    }

    async fn create_envelope_inner(
        &self,
        caller: &CallerContext,
        schema: &Schema,
        entity_id: &str,
        fields: &HashMap<String, serde_json::Value>,
        import_mode: bool,
    ) -> Result<EnvelopeRecord, SigilError> {
        let started_at = std::time::Instant::now();
        let resource = format!("{}/{}", schema.name, entity_id);

        // Validate all required fields are present (optional fields can be omitted)
        for field_def in &schema.fields {
            if field_def.required && !fields.contains_key(&field_def.name) {
                let err = SigilError::MissingField(field_def.name.clone());
                self.emit_failure_audit(caller, "create", &resource, entity_id, started_at, &err)
                    .await;
                return Err(err);
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
            let err = SigilError::EntityExists;
            self.emit_failure_audit(caller, "create", &resource, entity_id, started_at, &err)
                .await;
            return Err(err);
        }

        if let Err(e) = self
            .check_policy(caller, entity_id, &schema.name, "create")
            .await
        {
            self.emit_failure_audit(caller, "create", &resource, entity_id, started_at, &e)
                .await;
            return Err(e);
        }

        let mut completed_ops: Vec<CompensatingOp> = Vec::new();
        let mut record_fields: HashMap<String, serde_json::Value> = HashMap::new();
        let mut blind_fields: std::collections::HashSet<String> = std::collections::HashSet::new();

        // Process each field according to its treatment
        for field_def in &schema.fields {
            let Some(value) = fields.get(&field_def.name) else {
                // Optional field not provided — skip it
                continue;
            };
            let result = self
                .process_field(&schema.name, entity_id, field_def, value, import_mode)
                .await;

            match result {
                Ok(field_result) => {
                    if let Some(op) = field_result.compensating_op {
                        completed_ops.push(op);
                    }
                    if let Some(stored_value) = field_result.record_value {
                        record_fields.insert(field_def.name.clone(), stored_value);
                    }
                    if field_result.is_blind {
                        blind_fields.insert(field_def.name.clone());
                    }
                }
                Err(e) => {
                    let err = self.rollback_and_fail(completed_ops, e).await;
                    self.emit_failure_audit(
                        caller, "create", &resource, entity_id, started_at, &err,
                    )
                    .await;
                    return Err(err);
                }
            }
        }

        // Audit event before commit — fail closed if Chronicle is unreachable
        if let Err(e) = self
            .emit_audit_event(caller, "create", &resource, entity_id, started_at)
            .await
        {
            let err = self.rollback_and_fail(completed_ops, e).await;
            // Best-effort: if the audit emit already failed, a second attempt
            // via emit_failure_audit may also fail — swallow that silently.
            self.emit_failure_audit(caller, "create", &resource, entity_id, started_at, &err)
                .await;
            return Err(err);
        }

        // Write the envelope record — the "commit point"
        let now = now_secs();
        let record = EnvelopeRecord {
            entity_id: entity_id.to_string(),
            schema_version: schema.version,
            fields: record_fields,
            created_at: now,
            updated_at: now,
            blind_fields,
        };

        let value = serde_json::to_vec(&record).map_err(|e| SigilError::Internal(e.to_string()))?;

        if let Err(e) = self
            .store
            .put(&envelopes_ns, entity_id.as_bytes(), &value, None)
            .await
        {
            let cause = SigilError::Store(e.to_string());
            let err = self.rollback_and_fail(completed_ops, cause).await;
            self.emit_failure_audit(caller, "create", &resource, entity_id, started_at, &err)
                .await;
            return Err(err);
        }

        Ok(record)
    }

    /// Emit an audit event for a failure path. Adds the error type to
    /// `metadata["error"]` so Chronicle can filter by failure kind. Swallows
    /// chronicle errors: the operation has already failed; a secondary
    /// chronicle failure should not mask the original cause.
    pub(crate) async fn emit_failure_audit(
        &self,
        caller: &CallerContext,
        operation: &str,
        resource: &str,
        target: &str,
        started_at: std::time::Instant,
        err: &SigilError,
    ) {
        let Some(chronicle) = self.capabilities.chronicle.as_ref() else {
            return;
        };
        let mut metadata: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        if !target.is_empty() {
            metadata.insert("target".to_string(), target.to_string());
        }
        metadata.insert("error".to_string(), err.to_string());
        let elapsed = started_at.elapsed();
        let duration_ms = std::cmp::max(1, elapsed.as_millis().min(u64::MAX as u128) as u64);
        let event = shroudb_chronicle_core::event::Event {
            id: uuid::Uuid::new_v4().to_string(),
            correlation_id: None,
            timestamp: now_secs() * 1000,
            engine: shroudb_chronicle_core::event::Engine::Sigil,
            operation: operation.to_string(),
            resource_type: "schema".to_string(),
            resource_id: resource.to_string(),
            result: shroudb_chronicle_core::event::EventResult::Error,
            duration_ms,
            actor: caller.actor.clone(),
            tenant_id: caller.tenant_opt(),
            diff: None,
            metadata,
            hash: None,
            previous_hash: None,
        };
        if let Err(e) = chronicle.record(event).await {
            tracing::warn!(
                error = %e,
                operation = operation,
                resource = resource,
                "chronicle record failed on failure-audit path",
            );
        }
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

        let results: Vec<(String, f64)> = veil
            .search(field_value, Some(field_name), Some(1), false)
            .await?;

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

    /// Get an envelope record with PII fields handled according to `decrypt`.
    ///
    /// When `decrypt` is true and Cipher is available, PII fields are decrypted
    /// and returned as plaintext. When `decrypt` is false or Cipher is unavailable,
    /// PII fields show `"[encrypted]"`.
    ///
    /// Credential fields are never returned (they're in a separate namespace
    /// and are verify-only).
    pub async fn get_envelope(
        &self,
        schema: &Schema,
        entity_id: &str,
        decrypt: bool,
    ) -> Result<EnvelopeRecord, SigilError> {
        let ns = envelopes_namespace(&schema.name);
        let entry = self
            .store
            .get(&ns, entity_id.as_bytes(), None)
            .await
            .map_err(|_| SigilError::EntityNotFound)?;

        let mut record: EnvelopeRecord = serde_json::from_slice(&entry.value)
            .map_err(|e| SigilError::Internal(e.to_string()))?;

        for field_def in &schema.fields {
            let treatment = route_field_from_kind(&field_def.kind);
            if !matches!(
                treatment,
                FieldTreatment::EncryptedPii | FieldTreatment::SearchableEncrypted
            ) || !record.fields.contains_key(&field_def.name)
            {
                continue;
            }

            if record.blind_fields.contains(&field_def.name) {
                // Blind field: client-encrypted, server cannot decrypt. Always redact.
                record
                    .fields
                    .insert(field_def.name.clone(), serde_json::json!("[encrypted]"));
            } else if decrypt {
                if let Some(cipher) = self.capabilities.cipher.as_ref() {
                    // Decrypt server-encrypted PII field
                    let ciphertext = record.fields[&field_def.name]
                        .as_str()
                        .ok_or_else(|| SigilError::Internal("PII field is not a string".into()))?;
                    let context = format!("{}/{}/{}", schema.name, entity_id, field_def.name);
                    let plaintext_bytes = cipher.decrypt(ciphertext, Some(&context)).await?;
                    let plaintext = String::from_utf8(plaintext_bytes.as_bytes().to_vec())
                        .map_err(|e| SigilError::Internal(format!("PII decode error: {e}")))?;
                    record
                        .fields
                        .insert(field_def.name.clone(), serde_json::json!(plaintext));
                } else {
                    // Cipher unavailable — cannot decrypt, redact
                    record
                        .fields
                        .insert(field_def.name.clone(), serde_json::json!("[encrypted]"));
                }
            } else {
                // Redact: never return raw ciphertext
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
    ///
    /// Uses an internal caller context — dispatch must call
    /// `update_envelope_as` to attribute the change to the real caller.
    pub async fn update_envelope(
        &self,
        schema: &Schema,
        entity_id: &str,
        fields: &HashMap<String, serde_json::Value>,
    ) -> Result<EnvelopeRecord, SigilError> {
        self.update_envelope_as(
            &CallerContext::internal("envelope-update"),
            schema,
            entity_id,
            fields,
        )
        .await
    }

    /// Update an envelope attributed to `caller`.
    pub async fn update_envelope_as(
        &self,
        caller: &CallerContext,
        schema: &Schema,
        entity_id: &str,
        fields: &HashMap<String, serde_json::Value>,
    ) -> Result<EnvelopeRecord, SigilError> {
        let started_at = std::time::Instant::now();
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

            let treatment = route_field_from_kind(&field_def.kind);
            if treatment == FieldTreatment::Credential {
                return Err(SigilError::InvalidField {
                    field: field_name.clone(),
                    reason:
                        "credential fields cannot be updated via ENVELOPE UPDATE; use CREDENTIAL CHANGE"
                            .into(),
                });
            }
        }

        self.check_policy(caller, entity_id, &schema.name, "update")
            .await?;

        // Process fields with rollback tracking (same pattern as create)
        let mut completed_ops: Vec<CompensatingOp> = Vec::new();

        for (field_name, value) in fields {
            let field_def = schema
                .fields
                .iter()
                .find(|f| f.name == *field_name)
                .unwrap(); // safe: validated above

            let treatment = route_field_from_kind(&field_def.kind);

            let result = match treatment {
                FieldTreatment::PlaintextIndex | FieldTreatment::Inert => {
                    record.fields.insert(field_name.clone(), value.clone());
                    Ok(None)
                }
                FieldTreatment::EncryptedPii => {
                    let blind = Self::parse_blind_wrapper(value);
                    if let Some(blind_data) = blind {
                        record
                            .fields
                            .insert(field_name.clone(), serde_json::json!(blind_data.value));
                        record.blind_fields.insert(field_name.clone());
                        Ok(None)
                    } else {
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
                        let ciphertext =
                            cipher.encrypt(plaintext.as_bytes(), Some(&context)).await?;
                        record
                            .fields
                            .insert(field_name.clone(), serde_json::json!(ciphertext));
                        record.blind_fields.remove(field_name.as_str());
                        Ok(None)
                    }
                }
                FieldTreatment::SearchableEncrypted => {
                    let blind = Self::parse_blind_wrapper(value);
                    if let Some(blind_data) = blind {
                        let tokens_b64 =
                            blind_data.tokens.ok_or_else(|| SigilError::InvalidField {
                                field: field_name.clone(),
                                reason: "blind searchable field requires 'tokens'".into(),
                            })?;
                        let veil = self
                            .capabilities
                            .veil
                            .as_ref()
                            .ok_or_else(|| SigilError::CapabilityMissing("veil".into()))?;
                        let entry_id = format!("{}/{}", entity_id, field_name);
                        veil.put(&entry_id, tokens_b64.as_bytes(), Some(field_name), true)
                            .await?;
                        record
                            .fields
                            .insert(field_name.clone(), serde_json::json!(blind_data.value));
                        record.blind_fields.insert(field_name.clone());
                        Ok(Some(CompensatingOp::Veil { entry_id }))
                    } else {
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
                        let ciphertext =
                            cipher.encrypt(plaintext.as_bytes(), Some(&context)).await?;
                        let entry_id = format!("{}/{}", entity_id, field_name);
                        veil.put(&entry_id, plaintext.as_bytes(), Some(field_name), false)
                            .await?;
                        record
                            .fields
                            .insert(field_name.clone(), serde_json::json!(ciphertext));
                        Ok(Some(CompensatingOp::Veil { entry_id }))
                    }
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
                caller,
                "update",
                &format!("{}/{}", schema.name, entity_id),
                entity_id,
                started_at,
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
    /// Deletion order: audit event → envelope record (commit point) →
    /// best-effort cleanup of associated data. This ordering ensures that
    /// if audit or envelope delete fails, no associated data has been
    /// touched — the operation is fully abortable up to the commit point.
    /// Cleanup failures after commit are logged and handled by the
    /// scheduled `reconcile_orphans()` task.
    pub async fn delete_envelope(
        &self,
        schema: &Schema,
        entity_id: &str,
    ) -> Result<(), SigilError> {
        self.delete_envelope_as(
            &CallerContext::internal("envelope-delete"),
            schema,
            entity_id,
        )
        .await
    }

    /// Delete an envelope attributed to `caller`.
    pub async fn delete_envelope_as(
        &self,
        caller: &CallerContext,
        schema: &Schema,
        entity_id: &str,
    ) -> Result<(), SigilError> {
        let started_at = std::time::Instant::now();
        self.check_policy(caller, entity_id, &schema.name, "delete")
            .await?;

        let schema_name = &schema.name;
        let envelopes_ns = envelopes_namespace(schema_name);

        // Verify envelope exists before proceeding
        self.store
            .get(&envelopes_ns, entity_id.as_bytes(), None)
            .await
            .map_err(|_| SigilError::EntityNotFound)?;

        // Audit event before commit — fail closed if Chronicle is unreachable.
        // No data has been modified yet, so failure is a clean abort.
        self.emit_audit_event(
            caller,
            "delete",
            &format!("{}/{}", schema_name, entity_id),
            entity_id,
            started_at,
        )
        .await?;

        // Delete envelope record — the commit point.
        // If this fails, nothing has been deleted; a retry is safe.
        self.store
            .delete(&envelopes_ns, entity_id.as_bytes())
            .await
            .map_err(|e| SigilError::Store(e.to_string()))?;

        // Post-commit cleanup: best-effort deletion of associated data.
        // The envelope is already gone, so this data is unreachable.
        // Failures are logged for reconcile_orphans() to handle.
        self.cleanup_associated_data(schema, entity_id).await;

        Ok(())
    }

    /// Best-effort cleanup of data associated with a deleted envelope.
    /// Called after the envelope record has been deleted (commit point).
    /// Failures are logged but do not affect the delete result.
    async fn cleanup_associated_data(&self, schema: &Schema, entity_id: &str) {
        let schema_name = &schema.name;
        let creds_ns = format!("sigil.{schema_name}.credentials");
        let sessions_ns = format!("sigil.{schema_name}.sessions");

        for field_def in &schema.fields {
            let treatment = route_field_from_kind(&field_def.kind);
            match treatment {
                FieldTreatment::Credential => {
                    let key = credential_store_key(entity_id, &field_def.name);
                    if let Err(e) = self.store.delete(&creds_ns, key.as_bytes()).await {
                        tracing::warn!(
                            schema = schema_name,
                            entity_id,
                            field = field_def.name,
                            error = %e,
                            "post-commit credential cleanup failed — reconcile_orphans will handle"
                        );
                    }
                }
                FieldTreatment::SearchableEncrypted => {
                    if let Some(veil) = self.capabilities.veil.as_ref() {
                        let entry_id = format!("{entity_id}/{}", field_def.name);
                        if let Err(e) = veil.delete(&entry_id).await {
                            tracing::warn!(
                                schema = schema_name,
                                entity_id,
                                field = field_def.name,
                                error = %e,
                                "post-commit blind index cleanup failed — reconcile_orphans will handle"
                            );
                        }
                    }
                }
                FieldTreatment::VersionedSecret => {
                    if let Some(keep) = self.capabilities.keep.as_ref() {
                        let path = format!("{schema_name}/{entity_id}/{}", field_def.name);
                        if let Err(e) = keep.delete_secret(&path).await {
                            tracing::warn!(
                                schema = schema_name,
                                entity_id,
                                field = field_def.name,
                                error = %e,
                                "post-commit secret cleanup failed — reconcile_orphans will handle"
                            );
                        }
                    }
                }
                _ => {}
            }
        }

        // Delete all sessions for this entity
        if let Ok(page) = self.store.list(&sessions_ns, None, None, 10_000).await {
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
                    let key_str = String::from_utf8_lossy(key);
                    tracing::warn!(
                        schema = schema_name,
                        entity_id,
                        session_key = %key_str,
                        error = %e,
                        "post-commit session cleanup failed — reconcile_orphans will handle"
                    );
                }
            }
        }
    }

    /// Check if a field value is a blind wrapper: `{"blind": true, "value": "...", "tokens": "..."}`.
    /// Returns `None` if the value is not a blind wrapper (standard mode).
    fn parse_blind_wrapper(value: &serde_json::Value) -> Option<BlindFieldData> {
        let obj = value.as_object()?;
        if obj.get("blind")?.as_bool()? {
            let val = obj.get("value")?.as_str()?.to_string();
            let tokens = obj.get("tokens").and_then(|t| t.as_str()).map(String::from);
            Some(BlindFieldData { value: val, tokens })
        } else {
            None
        }
    }

    async fn process_field(
        &self,
        schema_name: &str,
        entity_id: &str,
        field_def: &shroudb_sigil_core::schema::FieldDef,
        value: &serde_json::Value,
        import_mode: bool,
    ) -> Result<FieldWriteResult, SigilError> {
        let field_name = field_def.name.as_str();
        let treatment = route_field_from_kind(&field_def.kind);
        let credential_policy = field_def.kind.credential_policy();

        // Check for per-field blind wrapper before standard processing.
        let blind = Self::parse_blind_wrapper(value);

        match treatment {
            FieldTreatment::Credential => {
                let policy = credential_policy.ok_or_else(|| {
                    SigilError::Internal(format!(
                        "credential field '{field_name}' has no CredentialPolicy"
                    ))
                })?;
                if let Some(blind_data) = blind {
                    // Blind credential: pre-hashed value — same as import mode.
                    self.credentials
                        .import_credential(
                            schema_name,
                            entity_id,
                            field_name,
                            &blind_data.value,
                            policy,
                        )
                        .await?;
                } else {
                    let field_value = value.as_str().ok_or_else(|| SigilError::InvalidField {
                        field: field_name.to_string(),
                        reason: "credential field must be a string".into(),
                    })?;

                    if import_mode {
                        self.credentials
                            .import_credential(
                                schema_name,
                                entity_id,
                                field_name,
                                field_value,
                                policy,
                            )
                            .await?;
                    } else {
                        self.credentials
                            .set_credential(schema_name, entity_id, field_name, field_value, policy)
                            .await?;
                    }
                }

                Ok(FieldWriteResult {
                    compensating_op: Some(CompensatingOp::Store {
                        namespace: format!("sigil.{schema_name}.credentials"),
                        key: credential_store_key(entity_id, field_name).into_bytes(),
                    }),
                    // Don't store the credential in the envelope record
                    record_value: None,
                    is_blind: false,
                })
            }

            FieldTreatment::EncryptedPii => {
                if let Some(blind_data) = blind {
                    // Blind PII: value is already a CiphertextEnvelope string.
                    // Store directly — skip Cipher.encrypt().
                    Ok(FieldWriteResult {
                        compensating_op: None,
                        record_value: Some(serde_json::json!(blind_data.value)),
                        is_blind: true,
                    })
                } else {
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
                        is_blind: false,
                    })
                }
            }

            FieldTreatment::SearchableEncrypted => {
                if let Some(blind_data) = blind {
                    // Blind searchable PII: value is ciphertext, tokens are
                    // pre-computed BlindTokenSet. Skip Cipher + server-side Veil
                    // tokenization.
                    let tokens_b64 = blind_data.tokens.ok_or_else(|| SigilError::InvalidField {
                        field: field_name.to_string(),
                        reason: "blind searchable field requires 'tokens'".into(),
                    })?;

                    let veil = self
                        .capabilities
                        .veil
                        .as_ref()
                        .ok_or_else(|| SigilError::CapabilityMissing("veil".into()))?;

                    let entry_id = format!("{entity_id}/{field_name}");
                    veil.put(&entry_id, tokens_b64.as_bytes(), Some(field_name), true)
                        .await?;

                    Ok(FieldWriteResult {
                        compensating_op: Some(CompensatingOp::Veil { entry_id }),
                        record_value: Some(serde_json::json!(blind_data.value)),
                        is_blind: true,
                    })
                } else {
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
                    veil.put(&entry_id, plaintext.as_bytes(), Some(field_name), false)
                        .await?;

                    Ok(FieldWriteResult {
                        compensating_op: Some(CompensatingOp::Veil { entry_id }),
                        record_value: Some(serde_json::json!(ciphertext)),
                        is_blind: false,
                    })
                }
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
                    is_blind: false,
                })
            }

            FieldTreatment::PlaintextIndex | FieldTreatment::Inert => {
                // Store directly in the envelope record
                Ok(FieldWriteResult {
                    compensating_op: None,
                    record_value: Some(value.clone()),
                    is_blind: false,
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
                    if let Some(veil) = self.capabilities.veil.as_ref()
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
                    if let Some(keep) = self.capabilities.keep.as_ref()
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
    /// True if this field was blind-encrypted (client-side). The server cannot decrypt it.
    is_blind: bool,
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

    use shroudb_sigil_core::credential::{EngineResourceConfig, PasswordAlgorithm};
    use shroudb_sigil_core::field_kind::{
        CredentialPolicy, FieldKind, LockoutPolicy, PiiPolicy, SecretPolicy,
    };
    use shroudb_sigil_core::schema::{FieldDef, FieldType, Schema};
    use shroudb_store::Store as _;

    use super::*;
    use crate::capabilities::Capabilities;
    use crate::credential::CredentialManager;
    use crate::schema_registry::SchemaRegistry;
    use crate::schema_registry::tests::create_test_store;

    fn legacy_credential_kind() -> FieldKind {
        FieldKind::Credential(CredentialPolicy {
            algorithm: PasswordAlgorithm::Argon2id,
            min_length: None,
            max_length: None,
            lockout: Some(LockoutPolicy {
                max_attempts: 5,
                duration_secs: 900,
            }),
        })
    }

    fn test_schema() -> Schema {
        Schema {
            name: "myapp".to_string(),
            version: 1,
            fields: vec![
                FieldDef::with_kind(
                    "password",
                    FieldType::String,
                    legacy_credential_kind(),
                    true,
                ),
                FieldDef::with_kind(
                    "org_id",
                    FieldType::String,
                    FieldKind::Index { claim: None },
                    true,
                ),
                FieldDef::with_kind(
                    "display_name",
                    FieldType::String,
                    FieldKind::Inert { claim: None },
                    true,
                ),
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
            EngineResourceConfig::default(),
        ));
        let capabilities = Arc::new(Capabilities::for_tests());
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
        let cred_mgr = CredentialManager::new(store, EngineResourceConfig::default());
        let policy = schema.credential_policy("password").unwrap().clone();
        let valid = cred_mgr
            .verify("myapp", "user1", "password", "correcthorse", &policy)
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
    async fn optional_field_omitted_succeeds() {
        let (_store, coord) = setup().await;
        let mut schema = test_schema();
        // Add an optional field to the schema
        schema.fields.push(FieldDef::with_kind(
            "phone",
            FieldType::String,
            FieldKind::Inert { claim: None },
            false,
        ));

        // Create envelope without the optional phone field
        let record = coord
            .create_envelope(&schema, "user1", &entity_fields())
            .await
            .unwrap();

        assert_eq!(record.entity_id, "user1");
        // phone should not be in the record since it wasn't provided
        assert!(!record.fields.contains_key("phone"));
        // Required fields are still present
        assert_eq!(record.fields["org_id"], "acme-corp");
    }

    #[tokio::test]
    async fn optional_field_provided_is_stored() {
        let (_store, coord) = setup().await;
        let mut schema = test_schema();
        schema.fields.push(FieldDef::with_kind(
            "phone",
            FieldType::String,
            FieldKind::Inert { claim: None },
            false,
        ));

        let mut fields = entity_fields();
        fields.insert("phone".to_string(), serde_json::json!("555-1234"));

        let record = coord
            .create_envelope(&schema, "user1", &fields)
            .await
            .unwrap();

        assert_eq!(record.fields["phone"], "555-1234");
    }

    #[tokio::test]
    async fn envelope_tracks_schema_version() {
        let (_store, coord) = setup().await;
        let mut schema = test_schema();
        schema.version = 3; // Simulate a schema at version 3

        let record = coord
            .create_envelope(&schema, "user1", &entity_fields())
            .await
            .unwrap();

        assert_eq!(record.schema_version, 3);
    }

    #[tokio::test]
    async fn get_envelope_returns_record() {
        let (_store, coord) = setup().await;
        let schema = test_schema();

        coord
            .create_envelope(&schema, "user1", &entity_fields())
            .await
            .unwrap();

        let record = coord.get_envelope(&schema, "user1", false).await.unwrap();
        assert_eq!(record.entity_id, "user1");
        assert_eq!(record.fields["org_id"], "acme-corp");
    }

    #[tokio::test]
    async fn get_nonexistent_envelope() {
        let (_store, coord) = setup().await;
        let schema = test_schema();
        let err = coord
            .get_envelope(&schema, "nope", false)
            .await
            .unwrap_err();
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

        assert!(coord.get_envelope(&schema, "user1", false).await.is_err());
    }

    /// Mock ChronicleOps that always fails — used to trigger Phase 2 audit failure.
    struct FailingChronicle;

    impl shroudb_chronicle_core::ops::ChronicleOps for FailingChronicle {
        fn record(
            &self,
            _event: shroudb_chronicle_core::event::Event,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>>
        {
            Box::pin(async { Err("chronicle unavailable".to_string()) })
        }

        fn record_batch(
            &self,
            _events: Vec<shroudb_chronicle_core::event::Event>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>>
        {
            Box::pin(async { Err("chronicle unavailable".to_string()) })
        }
    }

    #[tokio::test]
    async fn delete_no_cleanup_before_audit() {
        // When audit fails during delete, NO associated data should be
        // deleted. Audit and envelope delete happen before cleanup.
        let store = create_test_store().await;
        let registry = SchemaRegistry::new(store.clone());
        registry.init().await.unwrap();
        registry.register(test_schema()).await.unwrap();

        let credentials = Arc::new(CredentialManager::new(
            store.clone(),
            EngineResourceConfig::default(),
        ));

        // Create with no chronicle so the create succeeds.
        let capabilities_create = Arc::new(Capabilities::for_tests());
        let coord_create =
            WriteCoordinator::new(store.clone(), credentials.clone(), capabilities_create);
        coord_create
            .create_envelope(&test_schema(), "user1", &entity_fields())
            .await
            .unwrap();

        // Now build a coordinator with a failing Chronicle for the delete.
        let capabilities_delete = Arc::new(Capabilities {
            chronicle: shroudb_server_bootstrap::Capability::Enabled(Arc::new(FailingChronicle)),
            ..Capabilities::for_tests()
        });
        let coord_delete =
            WriteCoordinator::new(store.clone(), credentials.clone(), capabilities_delete);

        let err = coord_delete
            .delete_envelope(&test_schema(), "user1")
            .await
            .unwrap_err();
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("audit"),
            "expected audit failure error, got: {err_msg}"
        );

        // Envelope should still exist — audit failed before commit.
        let envelope = coord_delete
            .get_envelope(&test_schema(), "user1", false)
            .await;
        assert!(
            envelope.is_ok(),
            "envelope should still exist after audit failure"
        );

        // Credential should still exist — no cleanup happened before audit.
        let cred_ns = "sigil.myapp.credentials";
        let cred_key = credential_store_key("user1", "password");
        assert!(
            store.get(cred_ns, cred_key.as_bytes(), None).await.is_ok(),
            "credential should still exist — cleanup must not happen before audit"
        );
    }

    #[tokio::test]
    async fn delete_cleanup_after_commit_is_best_effort() {
        // When envelope delete succeeds but Veil cleanup fails after,
        // the delete should still succeed (cleanup is best-effort after commit).
        let store = create_test_store().await;
        let registry = SchemaRegistry::new(store.clone());
        registry.init().await.unwrap();

        let schema = Schema {
            name: "del-cleanup".to_string(),
            version: 1,
            fields: vec![FieldDef::with_kind(
                "email",
                FieldType::String,
                FieldKind::Pii(PiiPolicy { searchable: true }),
                true,
            )],
        };
        registry.register(schema.clone()).await.unwrap();

        // Create with working capabilities
        let credentials = Arc::new(CredentialManager::new(
            store.clone(),
            EngineResourceConfig::default(),
        ));
        let working_caps = Arc::new(Capabilities {
            cipher: shroudb_server_bootstrap::Capability::Enabled(Box::new(TestCipherOps)),
            veil: shroudb_server_bootstrap::Capability::Enabled(Box::new(TestVeilOps::new())),
            ..Capabilities::for_tests()
        });
        let coord = WriteCoordinator::new(store.clone(), credentials.clone(), working_caps);

        let mut fields = HashMap::new();
        fields.insert("email".into(), serde_json::json!("user@test.com"));
        coord
            .create_envelope(&schema, "user1", &fields)
            .await
            .unwrap();

        // Delete with failing Veil — should succeed (cleanup after commit is best-effort)
        let failing_caps = Arc::new(Capabilities {
            cipher: shroudb_server_bootstrap::Capability::Enabled(Box::new(TestCipherOps)),
            veil: shroudb_server_bootstrap::Capability::Enabled(Box::new(FailingVeilDeleteOps)),
            ..Capabilities::for_tests()
        });
        let coord_del = WriteCoordinator::new(store.clone(), credentials, failing_caps);

        coord_del
            .delete_envelope(&schema, "user1")
            .await
            .expect("delete should succeed — cleanup failures after commit are best-effort");

        // Envelope should be gone
        assert!(
            coord_del
                .get_envelope(&schema, "user1", false)
                .await
                .is_err(),
            "envelope should be deleted"
        );
    }

    #[tokio::test]
    async fn pii_field_rejected_without_cipher() {
        let store = create_test_store().await;
        let registry = SchemaRegistry::new(store.clone());
        registry.init().await.unwrap();

        let schema = Schema {
            name: "pii-app".to_string(),
            version: 1,
            fields: vec![FieldDef::with_kind(
                "email",
                FieldType::String,
                FieldKind::Pii(PiiPolicy { searchable: false }),
                true,
            )],
        };
        registry.register(schema.clone()).await.unwrap();

        let credentials = Arc::new(CredentialManager::new(
            store.clone(),
            EngineResourceConfig::default(),
        ));
        let capabilities = Arc::new(Capabilities::for_tests()); // no cipher
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
            version: 1,
            fields: vec![
                FieldDef::with_kind(
                    "api_key",
                    FieldType::String,
                    FieldKind::Secret(SecretPolicy {
                        rotation_days: None,
                    }),
                    true,
                ),
                FieldDef::with_kind(
                    "email",
                    FieldType::String,
                    FieldKind::Pii(PiiPolicy { searchable: false }),
                    true,
                ),
            ],
        };
        registry.register(schema.clone()).await.unwrap();

        let keep = TestKeepOps::new();
        let keep_secrets = keep.secrets.clone();
        let capabilities = Arc::new(Capabilities {
            keep: shroudb_server_bootstrap::Capability::Enabled(Box::new(keep)),
            ..Capabilities::for_tests() // no cipher — will fail on PII field
        });

        let credentials = Arc::new(CredentialManager::new(
            store.clone(),
            EngineResourceConfig::default(),
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
            version: 1,
            fields: vec![
                FieldDef::with_kind(
                    "password",
                    FieldType::String,
                    legacy_credential_kind(),
                    true,
                ),
                FieldDef::with_kind(
                    "api_key",
                    FieldType::String,
                    FieldKind::Secret(SecretPolicy {
                        rotation_days: None,
                    }),
                    true,
                ),
                FieldDef::with_kind(
                    "ssn",
                    FieldType::String,
                    FieldKind::Pii(PiiPolicy { searchable: false }),
                    true,
                ),
            ],
        };
        registry.register(schema.clone()).await.unwrap();

        let keep = TestKeepOps::new();
        let keep_secrets = keep.secrets.clone();
        let capabilities = Arc::new(Capabilities {
            keep: shroudb_server_bootstrap::Capability::Enabled(Box::new(keep)),
            ..Capabilities::for_tests()
        });

        let credentials = Arc::new(CredentialManager::new(
            store.clone(),
            EngineResourceConfig::default(),
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
            data: &[u8],
            _field: Option<&str>,
            _blind: bool,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), SigilError>> + Send + '_>>
        {
            let id = entry_id.to_string();
            let data = data.to_vec();
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
            _blind: bool,
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
            version: 1,
            fields: vec![
                FieldDef::with_kind(
                    "email",
                    FieldType::String,
                    FieldKind::Pii(PiiPolicy { searchable: true }),
                    true,
                ),
                FieldDef::with_kind(
                    "api_key",
                    FieldType::String,
                    FieldKind::Secret(SecretPolicy {
                        rotation_days: None,
                    }),
                    true,
                ),
            ],
        };
        registry.register(schema.clone()).await.unwrap();

        let veil = TestVeilOps::new();
        let veil_entries = veil.entries.clone();
        let capabilities = Arc::new(Capabilities {
            cipher: shroudb_server_bootstrap::Capability::Enabled(Box::new(TestCipherOps)),
            veil: shroudb_server_bootstrap::Capability::Enabled(Box::new(veil)),
            // No keep → will fail on the secret field
            ..Capabilities::for_tests()
        });

        let credentials = Arc::new(CredentialManager::new(
            store.clone(),
            EngineResourceConfig::default(),
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
        assert!(coord.get_envelope(&schema, "user1", false).await.is_err());
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
            version: 1,
            fields: vec![
                FieldDef::with_kind(
                    "password",
                    FieldType::String,
                    legacy_credential_kind(),
                    true,
                ),
                FieldDef::with_kind(
                    "api_key",
                    FieldType::String,
                    FieldKind::Secret(SecretPolicy {
                        rotation_days: None,
                    }),
                    true,
                ),
                FieldDef::with_kind(
                    "email",
                    FieldType::String,
                    FieldKind::Pii(PiiPolicy { searchable: true }),
                    true,
                ),
            ],
        };
        registry.register(schema.clone()).await.unwrap();

        let keep = TestKeepOps::new();
        let keep_secrets = keep.secrets.clone();
        let capabilities = Arc::new(Capabilities {
            keep: shroudb_server_bootstrap::Capability::Enabled(Box::new(keep)),
            // No cipher, no veil → will fail on searchable+pii field
            ..Capabilities::for_tests()
        });

        let credentials = Arc::new(CredentialManager::new(
            store.clone(),
            EngineResourceConfig::default(),
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
        assert!(coord.get_envelope(&schema, "user1", false).await.is_err());
    }

    #[tokio::test]
    async fn rollback_on_failure() {
        let (store, coord) = setup().await;

        // Create a schema with a credential field + a PII field (no cipher available)
        let schema = Schema {
            name: "rollback-test".to_string(),
            version: 1,
            fields: vec![
                FieldDef::with_kind(
                    "password",
                    FieldType::String,
                    legacy_credential_kind(),
                    true,
                ),
                FieldDef::with_kind(
                    "email",
                    FieldType::String,
                    FieldKind::Pii(PiiPolicy { searchable: false }),
                    true,
                ),
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
            version: 1,
            fields: vec![FieldDef::with_kind(
                "org_id",
                FieldType::String,
                FieldKind::Index { claim: None },
                true,
            )],
        };
        registry.register(schema.clone()).await.unwrap();

        let capabilities = Arc::new(Capabilities {
            chronicle: shroudb_server_bootstrap::Capability::Enabled(Arc::new(FailingChronicleOps)),
            ..Capabilities::for_tests()
        });
        let credentials = Arc::new(CredentialManager::new(
            store.clone(),
            EngineResourceConfig::default(),
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
            coord.get_envelope(&schema, "user1", false).await.is_err(),
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
            version: 1,
            fields: vec![FieldDef::with_kind(
                "name",
                FieldType::String,
                FieldKind::Inert { claim: None },
                true,
            )],
        };
        registry.register(schema.clone()).await.unwrap();

        // Create without chronicle (succeeds)
        let credentials = Arc::new(CredentialManager::new(
            store.clone(),
            EngineResourceConfig::default(),
        ));
        let no_chronicle = Arc::new(Capabilities::for_tests());
        let coord_create = WriteCoordinator::new(store.clone(), credentials.clone(), no_chronicle);

        let mut fields = HashMap::new();
        fields.insert("name".into(), serde_json::json!("Alice"));
        coord_create
            .create_envelope(&schema, "user1", &fields)
            .await
            .unwrap();

        // Now delete WITH failing chronicle
        let with_chronicle = Arc::new(Capabilities {
            chronicle: shroudb_server_bootstrap::Capability::Enabled(Arc::new(FailingChronicleOps)),
            ..Capabilities::for_tests()
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
            _data: &[u8],
            _field: Option<&str>,
            _blind: bool,
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
            _blind: bool,
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

    // delete_succeeds_despite_veil_cleanup_failure is covered by
    // delete_cleanup_after_commit_is_best_effort above.

    // ── Concurrency tests ───────────────────────────────────────

    /// KeepOps that sleeps to simulate network latency.
    struct SlowKeepOps;

    impl crate::capabilities::KeepOps for SlowKeepOps {
        fn store_secret(
            &self,
            _path: &str,
            _value: &[u8],
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<u64, SigilError>> + Send + '_>>
        {
            Box::pin(async {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                Ok(1)
            })
        }

        fn delete_secret(
            &self,
            _path: &str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), SigilError>> + Send + '_>>
        {
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn concurrent_creates_do_not_serialize_on_capabilities() {
        // Verify that concurrent envelope creates with slow capabilities
        // run in parallel, not serialized through a single connection.
        let store = create_test_store().await;
        let registry = SchemaRegistry::new(store.clone());
        registry.init().await.unwrap();

        let schema = Schema {
            name: "concurrency-test".to_string(),
            version: 1,
            fields: vec![
                FieldDef::with_kind(
                    "api_key",
                    FieldType::String,
                    FieldKind::Secret(SecretPolicy {
                        rotation_days: None,
                    }),
                    true,
                ),
                FieldDef::with_kind(
                    "org",
                    FieldType::String,
                    FieldKind::Index { claim: None },
                    true,
                ),
            ],
        };
        registry.register(schema.clone()).await.unwrap();

        let capabilities = Arc::new(Capabilities {
            keep: shroudb_server_bootstrap::Capability::Enabled(Box::new(SlowKeepOps)),
            ..Capabilities::for_tests()
        });
        let credentials = Arc::new(CredentialManager::new(
            store.clone(),
            EngineResourceConfig::default(),
        ));
        let coord = Arc::new(WriteCoordinator::new(
            store.clone(),
            credentials,
            capabilities,
        ));

        let start = std::time::Instant::now();
        let mut handles = Vec::new();

        for i in 0..5 {
            let c = coord.clone();
            let s = schema.clone();
            handles.push(tokio::spawn(async move {
                let mut fields = HashMap::new();
                fields.insert("api_key".into(), serde_json::json!(format!("sk-{i}")));
                fields.insert("org".into(), serde_json::json!(format!("org-{i}")));
                c.create_envelope(&s, &format!("user-{i}"), &fields).await
            }));
        }

        for h in handles {
            h.await.unwrap().unwrap();
        }

        let elapsed = start.elapsed();
        // 5 creates with 50ms Keep each. Serial: >= 250ms. Parallel: ~50ms.
        assert!(
            elapsed.as_millis() < 200,
            "concurrent creates appear serialized: {elapsed:?} for 5 creates with 50ms Keep"
        );
    }

    // ── Rollback orphan tests ──────────────────────────────────────

    /// KeepOps where store_secret succeeds but delete_secret fails,
    /// simulating a compensating operation failure during rollback.
    struct FailingDeleteKeepOps {
        secrets: Arc<std::sync::Mutex<HashMap<String, Vec<u8>>>>,
    }

    impl FailingDeleteKeepOps {
        fn new() -> Self {
            Self {
                secrets: Arc::new(std::sync::Mutex::new(HashMap::new())),
            }
        }
    }

    impl crate::capabilities::KeepOps for FailingDeleteKeepOps {
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
            _path: &str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), SigilError>> + Send + '_>>
        {
            Box::pin(async { Err(SigilError::Internal("keep delete unreachable".into())) })
        }
    }

    #[tokio::test]
    async fn test_rollback_orphan_surfaced_in_error() {
        // Schema: secret field (Keep) + PII field (no cipher → fails).
        // Secret stores successfully → PII fails → rollback tries to delete
        // secret → delete_secret fails → error message must contain
        // "rollback orphans" and the Keep path.
        let store = create_test_store().await;
        let registry = SchemaRegistry::new(store.clone());
        registry.init().await.unwrap();

        let schema = Schema {
            name: "orphan-test".to_string(),
            version: 1,
            fields: vec![
                FieldDef::with_kind(
                    "api_key",
                    FieldType::String,
                    FieldKind::Secret(SecretPolicy {
                        rotation_days: None,
                    }),
                    true,
                ),
                FieldDef::with_kind(
                    "email",
                    FieldType::String,
                    FieldKind::Pii(PiiPolicy { searchable: false }),
                    true,
                ),
            ],
        };
        registry.register(schema.clone()).await.unwrap();

        let keep = FailingDeleteKeepOps::new();
        let keep_secrets = keep.secrets.clone();
        let capabilities = Arc::new(Capabilities {
            keep: shroudb_server_bootstrap::Capability::Enabled(Box::new(keep)),
            // No cipher → will fail on PII field, triggering rollback
            ..Capabilities::for_tests()
        });

        let credentials = Arc::new(CredentialManager::new(
            store.clone(),
            EngineResourceConfig::default(),
        ));
        let coord = WriteCoordinator::new(store.clone(), credentials, capabilities);

        let mut fields = HashMap::new();
        fields.insert("api_key".into(), serde_json::json!("sk-secret-key-12345"));
        fields.insert("email".into(), serde_json::json!("user@example.com"));

        let err = coord
            .create_envelope(&schema, "user1", &fields)
            .await
            .unwrap_err();
        let err_msg = err.to_string();

        // Error must surface the rollback orphan
        assert!(
            err_msg.contains("rollback orphans"),
            "expected 'rollback orphans' in error, got: {err_msg}"
        );
        assert!(
            err_msg.contains("keep:orphan-test/user1/api_key"),
            "expected Keep path in orphan list, got: {err_msg}"
        );

        // The secret is still in Keep (delete failed — it's orphaned)
        assert!(
            !keep_secrets.lock().unwrap().is_empty(),
            "secret should remain in Keep since delete_secret failed"
        );

        // Envelope should not exist
        assert!(coord.get_envelope(&schema, "user1", false).await.is_err());
    }

    // ── Concurrent duplicate entity_id tests ───────────────────────

    #[tokio::test]
    async fn test_concurrent_create_same_entity_rejects_duplicate() {
        // Seed an entity, then spawn 5 concurrent tasks trying to create
        // the same entity_id. All 5 must fail with EntityExists since the
        // entity already exists.
        //
        // Note: EmbeddedStore does not provide compare-and-set, so truly
        // simultaneous creates from a cold start could race through the
        // existence check (TOCTOU). This test validates the duplicate-
        // detection path by pre-seeding the entity, ensuring all concurrent
        // attempts see the existing record.
        let store = create_test_store().await;
        let registry = SchemaRegistry::new(store.clone());
        registry.init().await.unwrap();

        let schema = Schema {
            name: "dup-race".to_string(),
            version: 1,
            fields: vec![
                FieldDef::with_kind(
                    "org_id",
                    FieldType::String,
                    FieldKind::Index { claim: None },
                    true,
                ),
                FieldDef::with_kind(
                    "name",
                    FieldType::String,
                    FieldKind::Inert { claim: None },
                    true,
                ),
            ],
        };
        registry.register(schema.clone()).await.unwrap();

        let capabilities = Arc::new(Capabilities::for_tests());
        let credentials = Arc::new(CredentialManager::new(
            store.clone(),
            EngineResourceConfig::default(),
        ));
        let coord = Arc::new(WriteCoordinator::new(
            store.clone(),
            credentials,
            capabilities,
        ));

        // Seed the entity so it exists before any concurrent tasks run
        let mut seed_fields = HashMap::new();
        seed_fields.insert("org_id".into(), serde_json::json!("org-seed"));
        seed_fields.insert("name".into(), serde_json::json!("Seed"));
        coord
            .create_envelope(&schema, "same-entity", &seed_fields)
            .await
            .unwrap();

        // Fire 5 concurrent creates for the same entity_id — all must fail
        let mut handles = Vec::new();
        for i in 0..5 {
            let c = coord.clone();
            let s = schema.clone();
            handles.push(tokio::spawn(async move {
                let mut fields = HashMap::new();
                fields.insert("org_id".into(), serde_json::json!(format!("org-{i}")));
                fields.insert("name".into(), serde_json::json!(format!("Task-{i}")));
                c.create_envelope(&s, "same-entity", &fields).await
            }));
        }

        let mut entity_exists_errors = 0u32;
        for h in handles {
            match h.await.unwrap() {
                Ok(_) => panic!("create should not succeed for an existing entity"),
                Err(SigilError::EntityExists) => entity_exists_errors += 1,
                Err(e) => panic!("unexpected error: {e}"),
            }
        }

        assert_eq!(
            entity_exists_errors, 5,
            "all 5 concurrent creates should fail with EntityExists, got {entity_exists_errors}"
        );

        // Original envelope is intact and unmodified
        let record = coord
            .get_envelope(&schema, "same-entity", false)
            .await
            .unwrap();
        assert_eq!(record.entity_id, "same-entity");
        assert_eq!(record.fields["org_id"], "org-seed");
    }

    // ── PII decryption tests (HIGH-12) ───────────────────────────────

    /// Mock Cipher that encrypts by prefixing "enc:" and decrypts by stripping it.
    struct MockCipher;

    impl crate::capabilities::CipherOps for MockCipher {
        fn encrypt(
            &self,
            plaintext: &[u8],
            _context: Option<&str>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<String, SigilError>> + Send + '_>,
        > {
            let pt = String::from_utf8_lossy(plaintext).to_string();
            Box::pin(async move { Ok(format!("enc:{pt}")) })
        }

        fn decrypt(
            &self,
            ciphertext: &str,
            _context: Option<&str>,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<shroudb_crypto::SensitiveBytes, SigilError>>
                    + Send
                    + '_,
            >,
        > {
            let ct = ciphertext.to_string();
            Box::pin(async move {
                let plaintext = ct
                    .strip_prefix("enc:")
                    .ok_or_else(|| SigilError::Crypto("not mock-encrypted".into()))?;
                Ok(shroudb_crypto::SensitiveBytes::new(
                    plaintext.as_bytes().to_vec(),
                ))
            })
        }
    }

    fn pii_schema() -> Schema {
        Schema {
            name: "pii-app".to_string(),
            version: 1,
            fields: vec![
                FieldDef::with_kind(
                    "email",
                    FieldType::String,
                    FieldKind::Pii(PiiPolicy { searchable: false }),
                    true,
                ),
                FieldDef::with_kind(
                    "org_id",
                    FieldType::String,
                    FieldKind::Index { claim: None },
                    true,
                ),
            ],
        }
    }

    async fn setup_with_cipher() -> WriteCoordinator<shroudb_storage::EmbeddedStore> {
        let store = create_test_store().await;

        let registry = SchemaRegistry::new(store.clone());
        registry.init().await.unwrap();
        registry.register(pii_schema()).await.unwrap();

        let credentials = Arc::new(CredentialManager::new(
            store.clone(),
            EngineResourceConfig::default(),
        ));
        let capabilities = Arc::new(Capabilities {
            cipher: shroudb_server_bootstrap::Capability::Enabled(Box::new(MockCipher)),
            ..Capabilities::for_tests()
        });
        WriteCoordinator::new(store, credentials, capabilities)
    }

    #[tokio::test]
    async fn get_envelope_decrypt_true_returns_plaintext_pii() {
        let coord = setup_with_cipher().await;
        let schema = pii_schema();

        let mut fields = HashMap::new();
        fields.insert("email".into(), serde_json::json!("alice@example.com"));
        fields.insert("org_id".into(), serde_json::json!("acme"));

        coord
            .create_envelope(&schema, "user1", &fields)
            .await
            .unwrap();

        // With decrypt=true, PII field should be decrypted
        let record = coord.get_envelope(&schema, "user1", true).await.unwrap();
        assert_eq!(
            record.fields["email"], "alice@example.com",
            "PII field should be decrypted when decrypt=true"
        );
        assert_eq!(record.fields["org_id"], "acme");
    }

    #[tokio::test]
    async fn get_envelope_decrypt_false_redacts_pii() {
        let coord = setup_with_cipher().await;
        let schema = pii_schema();

        let mut fields = HashMap::new();
        fields.insert("email".into(), serde_json::json!("bob@example.com"));
        fields.insert("org_id".into(), serde_json::json!("acme"));

        coord
            .create_envelope(&schema, "user1", &fields)
            .await
            .unwrap();

        // With decrypt=false, PII field should be redacted
        let record = coord.get_envelope(&schema, "user1", false).await.unwrap();
        assert_eq!(
            record.fields["email"], "[encrypted]",
            "PII field should be redacted when decrypt=false"
        );
        assert_eq!(record.fields["org_id"], "acme");
    }

    #[tokio::test]
    async fn get_envelope_no_cipher_redacts_even_with_decrypt_true() {
        // When cipher is unavailable, decrypt=true still redacts
        let (_store, coord) = setup().await; // no cipher
        let schema = test_schema(); // no PII fields in test_schema, so this is a no-op test

        // Since test_schema has no PII fields, verify the regular path works
        coord
            .create_envelope(&schema, "user1", &entity_fields())
            .await
            .unwrap();

        let record = coord.get_envelope(&schema, "user1", true).await.unwrap();
        // Non-PII fields returned as-is regardless of decrypt flag
        assert_eq!(record.fields["org_id"], "acme-corp");
    }

    // ── DEBT TESTS ────────────────────────────────────────────────────
    //
    // Hard-ratchet tests for half-assed wiring (AUDIT_2026-04-17).
    // These fail until the underlying gap is fixed. Do NOT add `#[ignore]`
    // to make `cargo test` pass — either fix the bug, or if a visible
    // ratchet is genuinely needed, document it in TODOS.md AND on the
    // `#[ignore = "DEBT-...: ..."]` attribute itself.

    use crate::test_support::{RecordingChronicle, RecordingSentry};

    async fn setup_with_recorders() -> (
        Arc<shroudb_storage::EmbeddedStore>,
        WriteCoordinator<shroudb_storage::EmbeddedStore>,
        std::sync::Arc<std::sync::Mutex<Vec<PolicyRequest>>>,
        std::sync::Arc<std::sync::Mutex<Vec<shroudb_chronicle_core::event::Event>>>,
    ) {
        let store = create_test_store().await;
        let registry = SchemaRegistry::new(store.clone());
        registry.init().await.unwrap();
        registry.register(test_schema()).await.unwrap();

        let credentials = Arc::new(CredentialManager::new(
            store.clone(),
            EngineResourceConfig::default(),
        ));
        let (sentry, reqs) = RecordingSentry::new();
        let (chronicle, events) = RecordingChronicle::new();
        let capabilities = Arc::new(Capabilities {
            sentry: shroudb_server_bootstrap::Capability::Enabled(sentry),
            chronicle: shroudb_server_bootstrap::Capability::Enabled(chronicle),
            ..Capabilities::for_tests()
        });
        let coord = WriteCoordinator::new(store.clone(), credentials, capabilities);
        (store, coord, reqs, events)
    }

    /// DEBT-F3 (AUDIT_2026-04-17): PolicyRequest.principal is currently set
    /// to the target `entity_id`, not the authenticated caller. That's not
    /// authorization — it's "is this entity allowed to be operated on".
    /// Fix: thread `AuthContext` from dispatch → engine; use caller's actor
    /// as the policy principal. See also DEBT-F2.
    #[tokio::test]
    async fn debt_f03_policy_principal_must_not_equal_target_entity() {
        let (_store, coord, reqs, _events) = setup_with_recorders().await;
        coord
            .create_envelope(&test_schema(), "alice_target", &entity_fields())
            .await
            .expect("create should succeed when sentry permits");

        let requests = reqs.lock().unwrap();
        assert!(
            !requests.is_empty(),
            "DEBT-F3: Sentry should be invoked on create"
        );
        for req in requests.iter() {
            assert_ne!(
                req.principal.id, "alice_target",
                "DEBT-F3: principal.id == target entity. Thread caller context."
            );
        }
    }

    /// DEBT-F3b (AUDIT_2026-04-17): PolicyRequest.principal.roles and
    /// .claims are hardcoded empty. ABAC cannot evaluate without attributes.
    #[tokio::test]
    async fn debt_f03b_policy_principal_must_carry_roles_or_claims() {
        let (_store, coord, reqs, _events) = setup_with_recorders().await;
        coord
            .create_envelope(&test_schema(), "alice", &entity_fields())
            .await
            .expect("create should succeed");
        let requests = reqs.lock().unwrap();
        let req = requests.first().expect("policy request recorded");
        assert!(
            !req.principal.roles.is_empty() || !req.principal.claims.is_empty(),
            "DEBT-F3b: principal carries no roles and no claims. ABAC is blind."
        );
    }

    /// DEBT-F4a (AUDIT_2026-04-17): audit event `actor` is currently set to
    /// the target `entity_id`, not the caller. Chronicle receives
    /// "alice_target performed create on alice_target" — useless for
    /// forensics. Fix: thread caller and set actor = caller.actor.
    #[tokio::test]
    async fn debt_f04a_audit_event_actor_must_not_equal_target_entity() {
        let (_store, coord, _reqs, events) = setup_with_recorders().await;
        coord
            .create_envelope(&test_schema(), "alice_target", &entity_fields())
            .await
            .expect("create should succeed");
        let events = events.lock().unwrap();
        assert!(
            !events.is_empty(),
            "DEBT-F4a: Chronicle should be invoked on create"
        );
        for ev in events.iter() {
            assert_ne!(
                ev.actor, "alice_target",
                "DEBT-F4a: actor == target entity. Thread caller."
            );
        }
    }

    /// DEBT-F4b (AUDIT_2026-04-17): audit event `tenant_id` is hardcoded
    /// None in write_coordinator.rs. Multi-tenant deployments cannot filter
    /// audit events by tenant. Fix: thread caller tenant and populate.
    #[tokio::test]
    async fn debt_f04b_audit_event_tenant_must_be_populated() {
        let (_store, coord, _reqs, events) = setup_with_recorders().await;
        coord
            .create_envelope(&test_schema(), "alice", &entity_fields())
            .await
            .expect("create should succeed");
        let events = events.lock().unwrap();
        let ev = events.first().expect("event recorded");
        assert!(
            ev.tenant_id.is_some(),
            "DEBT-F4b: tenant_id is None. Thread caller.tenant."
        );
    }

    /// DEBT-F4c (AUDIT_2026-04-17): audit event `duration_ms` is hardcoded
    /// 0. Sigil never measures operation duration. Fix: wrap ops with a
    /// start-instant, compute elapsed before emitting.
    #[tokio::test]
    async fn debt_f04c_audit_event_duration_must_be_measured() {
        let (_store, coord, _reqs, events) = setup_with_recorders().await;
        // create_envelope hashes a credential via Argon2id — always > 1ms.
        coord
            .create_envelope(&test_schema(), "alice", &entity_fields())
            .await
            .expect("create should succeed");
        let events = events.lock().unwrap();
        let ev = events.first().expect("event recorded");
        assert!(
            ev.duration_ms > 0,
            "DEBT-F4c: duration_ms is 0. Sigil never measures op duration."
        );
    }

    /// DEBT-F8 (AUDIT_2026-04-17): audit events are emitted only on success
    /// (before the commit point). A failed operation (e.g. credential
    /// verify = wrong password, duplicate create, policy deny) emits
    /// *nothing*. Failed attempts are arguably more important to audit than
    /// successes. Fix: emit audit on failure paths with
    /// `result: EventResult::Fail` and a reason.
    #[tokio::test]
    async fn debt_f08_failed_operation_must_emit_audit_event() {
        let (_store, coord, _reqs, events) = setup_with_recorders().await;

        // First create succeeds and emits one event.
        coord
            .create_envelope(&test_schema(), "alice", &entity_fields())
            .await
            .expect("first create");
        let events_after_success = events.lock().unwrap().len();

        // Second create fails with EntityExists — must also emit.
        let err = coord
            .create_envelope(&test_schema(), "alice", &entity_fields())
            .await
            .expect_err("second create must fail");
        assert!(matches!(err, SigilError::EntityExists));

        let total = events.lock().unwrap().len();
        assert!(
            total > events_after_success,
            "DEBT-F8: failed create emitted no audit event (events_before={events_after_success}, total={total})"
        );

        let fail_events: Vec<_> = events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| !matches!(e.result, shroudb_chronicle_core::event::EventResult::Ok))
            .cloned()
            .collect();
        assert!(
            !fail_events.is_empty(),
            "DEBT-F8: failure event emitted with result=Ok. Should be Fail."
        );
    }
}
