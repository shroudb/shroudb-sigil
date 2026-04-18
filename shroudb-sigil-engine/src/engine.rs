use std::sync::Arc;

use shroudb_crypto::JwtAlgorithm;

use shroudb_sigil_core::credential::EngineResourceConfig;
use shroudb_sigil_core::error::SigilError;
use shroudb_sigil_core::field_kind::CredentialPolicy;
use shroudb_sigil_core::record::EnvelopeRecord;
use shroudb_sigil_core::schema::{FieldDef, Schema};
use shroudb_sigil_core::session::TokenPair;
use shroudb_store::Store;

use crate::caller::CallerContext;
use crate::capabilities::Capabilities;
use crate::credential::CredentialManager;
use crate::jwt::JwtManager;
use crate::schema_registry::SchemaRegistry;
use crate::session::SessionManager;
use crate::write_coordinator::WriteCoordinator;

/// Configuration for the Sigil engine.
///
/// Only process-scoped resource limits live here in v2.0. Per-field credential
/// properties (algorithm, length bounds, lockout) come from each schema's
/// `CredentialPolicy`, resolved per operation.
pub struct SigilConfig {
    pub engine_resources: EngineResourceConfig,
    pub jwt_algorithm: JwtAlgorithm,
    pub access_ttl_secs: u64,
    pub refresh_ttl_secs: u64,
}

impl Default for SigilConfig {
    fn default() -> Self {
        Self {
            engine_resources: EngineResourceConfig::default(),
            jwt_algorithm: JwtAlgorithm::ES256,
            access_ttl_secs: 900,        // 15 minutes
            refresh_ttl_secs: 2_592_000, // 30 days
        }
    }
}

/// The unified Sigil engine. Single entry point for all operations.
///
/// Generic over `S: Store` — works identically with `EmbeddedStore`
/// (in-process ShrouDB) or `RemoteStore` (TCP to ShrouDB server).
pub struct SigilEngine<S: Store> {
    pub(crate) schemas: SchemaRegistry<S>,
    pub(crate) credentials: Arc<CredentialManager<S>>,
    /// JWT manager — public for token verification in tests and downstream crates.
    pub jwt: Arc<JwtManager<S>>,
    pub(crate) sessions: SessionManager<S>,
    pub(crate) coordinator: WriteCoordinator<S>,
}

impl<S: Store> SigilEngine<S> {
    /// Create a new Sigil engine for production use.
    ///
    /// Rejects capability slots that are `DisabledForTests` — Sigil is
    /// security infrastructure, and deploying without Sentry (policy) or
    /// Chronicle (audit) means running without authorization enforcement
    /// or audit trail. Operators that need to opt a slot out explicitly
    /// must use `Capability::DisabledWithJustification { reason }` so the
    /// decision is visible and reviewable.
    ///
    /// Tests that need a permissive config should call `new_permissive`.
    pub async fn new(
        store: Arc<S>,
        config: SigilConfig,
        capabilities: Capabilities,
    ) -> Result<Self, SigilError> {
        Self::validate_production_capabilities(&capabilities)?;
        Self::construct(store, config, capabilities).await
    }

    /// Create a new Sigil engine without production capability checks.
    ///
    /// Intended for unit tests and in-process test harnesses where
    /// `Capabilities::for_tests()` is used to disable every slot. Never
    /// use in a production binary — `new` is the production entry point.
    pub async fn new_permissive(
        store: Arc<S>,
        config: SigilConfig,
        capabilities: Capabilities,
    ) -> Result<Self, SigilError> {
        Self::construct(store, config, capabilities).await
    }

    fn validate_production_capabilities(capabilities: &Capabilities) -> Result<(), SigilError> {
        use shroudb_server_bootstrap::Capability;
        fn check<T>(slot: &Capability<T>, name: &str) -> Result<(), SigilError> {
            match slot {
                Capability::DisabledForTests => Err(SigilError::CapabilityMissing(format!(
                    "{name} is DisabledForTests; production construction rejects test-only \
                     capabilities. Use `Capability::DisabledWithJustification` with an \
                     explicit reason, or call `SigilEngine::new_permissive` in tests."
                ))),
                Capability::Enabled(_) | Capability::DisabledWithJustification(_) => Ok(()),
            }
        }
        check(&capabilities.sentry, "sentry")?;
        check(&capabilities.chronicle, "chronicle")?;
        Ok(())
    }

    async fn construct(
        store: Arc<S>,
        config: SigilConfig,
        capabilities: Capabilities,
    ) -> Result<Self, SigilError> {
        let schemas = SchemaRegistry::new(store.clone());
        schemas.init().await?;

        let credentials = Arc::new(CredentialManager::new(
            store.clone(),
            config.engine_resources,
        ));

        let jwt = Arc::new(JwtManager::new(
            store.clone(),
            config.jwt_algorithm,
            config.access_ttl_secs,
        ));

        let sessions = SessionManager::new(
            store.clone(),
            jwt.clone(),
            config.access_ttl_secs,
            config.refresh_ttl_secs,
        );

        let coordinator =
            WriteCoordinator::new(store.clone(), credentials.clone(), Arc::new(capabilities));

        Ok(Self {
            schemas,
            credentials,
            jwt,
            sessions,
            coordinator,
        })
    }

    // ── Schema operations ───────────────────────────────────────────

    pub async fn schema_register(&self, schema: Schema) -> Result<u64, SigilError> {
        let started_at = std::time::Instant::now();
        let caller = CallerContext::internal("schema-register");
        let schema_name = schema.name.clone();
        let version = self.schemas.register(schema).await?;
        self.coordinator
            .emit_audit_event(
                &caller,
                "schema.register",
                &schema_name,
                &schema_name,
                started_at,
            )
            .await?;
        Ok(version)
    }

    pub async fn schema_get(&self, name: &str) -> Result<Schema, SigilError> {
        self.schemas.get(name).await
    }

    pub async fn schema_list(&self) -> Result<Vec<String>, SigilError> {
        self.schemas.list().await
    }

    pub async fn schema_alter(
        &self,
        name: &str,
        add_fields: Vec<FieldDef>,
        remove_fields: Vec<String>,
    ) -> Result<Schema, SigilError> {
        let started_at = std::time::Instant::now();
        let caller = CallerContext::internal("schema-alter");
        let schema = self.schemas.alter(name, add_fields, remove_fields).await?;
        self.coordinator
            .emit_audit_event(&caller, "schema.alter", name, name, started_at)
            .await?;
        Ok(schema)
    }

    // ── Generic envelope operations ─────────────────────────────────

    pub async fn envelope_create(
        &self,
        schema_name: &str,
        entity_id: &str,
        fields: &std::collections::HashMap<String, serde_json::Value>,
    ) -> Result<EnvelopeRecord, SigilError> {
        let schema = self.schemas.get(schema_name).await?;
        self.coordinator
            .create_envelope(&schema, entity_id, fields)
            .await
    }

    pub async fn envelope_import(
        &self,
        schema_name: &str,
        entity_id: &str,
        fields: &std::collections::HashMap<String, serde_json::Value>,
    ) -> Result<EnvelopeRecord, SigilError> {
        let schema = self.schemas.get(schema_name).await?;
        self.coordinator
            .import_envelope(&schema, entity_id, fields)
            .await
    }

    pub async fn envelope_get(
        &self,
        schema_name: &str,
        entity_id: &str,
        decrypt: bool,
    ) -> Result<EnvelopeRecord, SigilError> {
        let started_at = std::time::Instant::now();
        let caller = CallerContext::internal("envelope-get");
        let schema = self.schemas.get(schema_name).await?;
        self.coordinator
            .check_policy(&caller, entity_id, schema_name, "read")
            .await?;
        let record = self
            .coordinator
            .get_envelope(&schema, entity_id, decrypt)
            .await?;
        self.coordinator
            .emit_audit_event(
                &caller,
                "read",
                &format!("{schema_name}/{entity_id}"),
                entity_id,
                started_at,
            )
            .await?;
        Ok(record)
    }

    pub async fn envelope_update(
        &self,
        schema_name: &str,
        entity_id: &str,
        fields: &std::collections::HashMap<String, serde_json::Value>,
    ) -> Result<EnvelopeRecord, SigilError> {
        let schema = self.schemas.get(schema_name).await?;
        self.coordinator
            .update_envelope(&schema, entity_id, fields)
            .await
    }

    pub async fn envelope_delete(
        &self,
        schema_name: &str,
        entity_id: &str,
    ) -> Result<(), SigilError> {
        let schema = self.schemas.get(schema_name).await?;
        self.coordinator.delete_envelope(&schema, entity_id).await
    }

    /// Verify a specific credential field on an envelope.
    pub async fn envelope_verify(
        &self,
        schema_name: &str,
        entity_id: &str,
        field_name: &str,
        value: &str,
    ) -> Result<bool, SigilError> {
        let started_at = std::time::Instant::now();
        let caller = CallerContext::internal("envelope-verify");
        let schema = self.schemas.get(schema_name).await?;
        let policy = resolve_credential_policy(&schema, field_name)?;
        self.coordinator
            .check_policy(&caller, entity_id, schema_name, "verify")
            .await?;
        let ok = self
            .credentials
            .verify(schema_name, entity_id, field_name, value, &policy)
            .await?;
        self.coordinator
            .emit_audit_event(
                &caller,
                "verify",
                &format!("{schema_name}/{entity_id}/{field_name}"),
                entity_id,
                started_at,
            )
            .await?;
        Ok(ok)
    }

    /// Look up an entity by a searchable field value via Veil.
    /// Returns the entity_id if found.
    pub async fn envelope_lookup(
        &self,
        schema_name: &str,
        field_name: &str,
        field_value: &str,
    ) -> Result<String, SigilError> {
        let started_at = std::time::Instant::now();
        let caller = CallerContext::internal("envelope-lookup");
        self.coordinator
            .check_policy(&caller, "", schema_name, "lookup")
            .await?;
        let entity_id = self
            .coordinator
            .lookup_by_field(field_name, field_value)
            .await?;
        self.coordinator
            .emit_audit_event(
                &caller,
                "lookup",
                &format!("{schema_name}/{field_name}"),
                &entity_id,
                started_at,
            )
            .await?;
        Ok(entity_id)
    }

    // ── User sugar (delegates to envelope_*) ────────────────────────
    // These infer the credential field from the schema.

    pub async fn user_create(
        &self,
        schema_name: &str,
        user_id: &str,
        fields: &std::collections::HashMap<String, serde_json::Value>,
    ) -> Result<EnvelopeRecord, SigilError> {
        self.envelope_create(schema_name, user_id, fields).await
    }

    pub async fn user_import(
        &self,
        schema_name: &str,
        user_id: &str,
        fields: &std::collections::HashMap<String, serde_json::Value>,
    ) -> Result<EnvelopeRecord, SigilError> {
        self.envelope_import(schema_name, user_id, fields).await
    }

    pub async fn user_get(
        &self,
        schema_name: &str,
        user_id: &str,
        decrypt: bool,
    ) -> Result<EnvelopeRecord, SigilError> {
        self.envelope_get(schema_name, user_id, decrypt).await
    }

    pub async fn user_update(
        &self,
        schema_name: &str,
        user_id: &str,
        fields: &std::collections::HashMap<String, serde_json::Value>,
    ) -> Result<EnvelopeRecord, SigilError> {
        self.envelope_update(schema_name, user_id, fields).await
    }

    pub async fn user_delete(&self, schema_name: &str, user_id: &str) -> Result<(), SigilError> {
        self.envelope_delete(schema_name, user_id).await
    }

    /// Verify user credentials. Infers the credential field from the schema.
    pub async fn user_verify(
        &self,
        schema_name: &str,
        user_id: &str,
        password: &str,
    ) -> Result<bool, SigilError> {
        let schema = self.schemas.get(schema_name).await?;
        let cred_field = schema.credential_field_name()?;
        self.envelope_verify(schema_name, user_id, cred_field, password)
            .await
    }

    pub async fn user_lookup(
        &self,
        schema_name: &str,
        field_name: &str,
        field_value: &str,
    ) -> Result<String, SigilError> {
        self.envelope_lookup(schema_name, field_name, field_value)
            .await
    }

    // ── Session operations ──────────────────────────────────────────

    /// Login by searchable field (e.g., email) instead of entity_id.
    /// Resolves the entity via Veil blind search, then verifies credentials.
    pub async fn session_create_by_field(
        &self,
        schema_name: &str,
        field_name: &str,
        field_value: &str,
        password: &str,
        extra_claims: Option<&serde_json::Value>,
    ) -> Result<TokenPair, SigilError> {
        let entity_id = self
            .envelope_lookup(schema_name, field_name, field_value)
            .await?;

        self.session_create(schema_name, &entity_id, password, extra_claims)
            .await
    }

    pub async fn session_create(
        &self,
        schema_name: &str,
        entity_id: &str,
        password: &str,
        extra_claims: Option<&serde_json::Value>,
    ) -> Result<TokenPair, SigilError> {
        let started_at = std::time::Instant::now();
        let caller = CallerContext::internal("session-create");
        // Verify credentials first (infers credential field from schema)
        let schema = self.schemas.get(schema_name).await?;
        let cred_field = schema.credential_field_name()?;
        let policy = resolve_credential_policy(&schema, cred_field)?;
        self.coordinator
            .check_policy(&caller, entity_id, schema_name, "session.create")
            .await?;
        self.credentials
            .verify(schema_name, entity_id, cred_field, password, &policy)
            .await?;

        let merged = self
            .build_enriched_claims(&schema, entity_id, extra_claims)
            .await?;

        let pair = self
            .sessions
            .create_session(schema_name, entity_id, merged.as_ref())
            .await?;
        self.coordinator
            .emit_audit_event(
                &caller,
                "session.create",
                &format!("{schema_name}/{entity_id}"),
                entity_id,
                started_at,
            )
            .await?;
        Ok(pair)
    }

    pub async fn session_refresh(
        &self,
        schema_name: &str,
        token: &str,
    ) -> Result<TokenPair, SigilError> {
        let started_at = std::time::Instant::now();
        let caller = CallerContext::internal("session-refresh");
        let schema = self.schemas.get(schema_name).await?;
        let claim_fields = schema.claim_fields();

        let entity_id = self.sessions.peek_entity_id(schema_name, token).await?;
        self.coordinator
            .check_policy(&caller, &entity_id, schema_name, "session.refresh")
            .await?;

        let enrichment = if !claim_fields.is_empty() {
            self.build_enriched_claims(&schema, &entity_id, None)
                .await?
        } else {
            None
        };

        let pair = self
            .sessions
            .refresh(schema_name, token, enrichment.as_ref())
            .await?;
        self.coordinator
            .emit_audit_event(
                &caller,
                "session.refresh",
                &format!("{schema_name}/{entity_id}"),
                &entity_id,
                started_at,
            )
            .await?;
        Ok(pair)
    }

    pub async fn session_revoke(&self, schema_name: &str, token: &str) -> Result<(), SigilError> {
        let started_at = std::time::Instant::now();
        let caller = CallerContext::internal("session-revoke");
        let entity_id = self.sessions.peek_entity_id(schema_name, token).await?;
        self.coordinator
            .check_policy(&caller, &entity_id, schema_name, "session.revoke")
            .await?;
        self.sessions.revoke(schema_name, token).await?;
        self.coordinator
            .emit_audit_event(
                &caller,
                "session.revoke",
                &format!("{schema_name}/{entity_id}"),
                &entity_id,
                started_at,
            )
            .await
    }

    pub async fn session_revoke_all(
        &self,
        schema_name: &str,
        entity_id: &str,
    ) -> Result<u64, SigilError> {
        let started_at = std::time::Instant::now();
        let caller = CallerContext::internal("session-revoke-all");
        self.coordinator
            .check_policy(&caller, entity_id, schema_name, "session.revoke_all")
            .await?;
        let count = self.sessions.revoke_all(schema_name, entity_id).await?;
        self.coordinator
            .emit_audit_event(
                &caller,
                "session.revoke_all",
                &format!("{schema_name}/{entity_id}"),
                entity_id,
                started_at,
            )
            .await?;
        Ok(count)
    }

    pub async fn session_list(
        &self,
        schema_name: &str,
        entity_id: &str,
    ) -> Result<Vec<shroudb_sigil_core::session::RefreshTokenRecord>, SigilError> {
        let started_at = std::time::Instant::now();
        let caller = CallerContext::internal("session-list");
        self.coordinator
            .check_policy(&caller, entity_id, schema_name, "session.list")
            .await?;
        let records = self.sessions.list_sessions(schema_name, entity_id).await?;
        self.coordinator
            .emit_audit_event(
                &caller,
                "session.list",
                &format!("{schema_name}/{entity_id}"),
                entity_id,
                started_at,
            )
            .await?;
        Ok(records)
    }

    // ── Credential operations ───────────────────────────────────────
    // Generic credential operations with explicit field name.

    pub async fn credential_change(
        &self,
        schema_name: &str,
        entity_id: &str,
        field_name: &str,
        old_value: &str,
        new_value: &str,
    ) -> Result<(), SigilError> {
        let started_at = std::time::Instant::now();
        let caller = CallerContext::internal("credential-change");
        let schema = self.schemas.get(schema_name).await?;
        let policy = resolve_credential_policy(&schema, field_name)?;
        self.coordinator
            .check_policy(&caller, entity_id, schema_name, "credential.change")
            .await?;
        self.credentials
            .change_credential(
                schema_name,
                entity_id,
                field_name,
                old_value,
                new_value,
                &policy,
            )
            .await?;
        self.coordinator
            .emit_audit_event(
                &caller,
                "credential.change",
                &format!("{schema_name}/{entity_id}/{field_name}"),
                entity_id,
                started_at,
            )
            .await
    }

    pub async fn credential_reset(
        &self,
        schema_name: &str,
        entity_id: &str,
        field_name: &str,
        new_value: &str,
    ) -> Result<(), SigilError> {
        let started_at = std::time::Instant::now();
        let caller = CallerContext::internal("credential-reset");
        let schema = self.schemas.get(schema_name).await?;
        let policy = resolve_credential_policy(&schema, field_name)?;
        self.coordinator
            .check_policy(&caller, entity_id, schema_name, "credential.reset")
            .await?;
        self.credentials
            .reset_credential(schema_name, entity_id, field_name, new_value, &policy)
            .await?;
        self.coordinator
            .emit_audit_event(
                &caller,
                "credential.reset",
                &format!("{schema_name}/{entity_id}/{field_name}"),
                entity_id,
                started_at,
            )
            .await
    }

    pub async fn credential_import(
        &self,
        schema_name: &str,
        entity_id: &str,
        field_name: &str,
        hash: &str,
    ) -> Result<shroudb_sigil_core::credential::PasswordAlgorithm, SigilError> {
        let started_at = std::time::Instant::now();
        let caller = CallerContext::internal("credential-import");
        let schema = self.schemas.get(schema_name).await?;
        let policy = resolve_credential_policy(&schema, field_name)?;
        self.coordinator
            .check_policy(&caller, entity_id, schema_name, "credential.import")
            .await?;
        let algo = self
            .credentials
            .import_credential(schema_name, entity_id, field_name, hash, &policy)
            .await?;
        self.coordinator
            .emit_audit_event(
                &caller,
                "credential.import",
                &format!("{schema_name}/{entity_id}/{field_name}"),
                entity_id,
                started_at,
            )
            .await?;
        Ok(algo)
    }

    // ── Password sugar (infers credential field from schema) ────────

    pub async fn password_change(
        &self,
        schema_name: &str,
        user_id: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), SigilError> {
        let schema = self.schemas.get(schema_name).await?;
        let cred_field = schema.credential_field_name()?;
        self.credential_change(schema_name, user_id, cred_field, old_password, new_password)
            .await
    }

    pub async fn password_reset(
        &self,
        schema_name: &str,
        user_id: &str,
        new_password: &str,
    ) -> Result<(), SigilError> {
        let schema = self.schemas.get(schema_name).await?;
        let cred_field = schema.credential_field_name()?;
        self.credential_reset(schema_name, user_id, cred_field, new_password)
            .await
    }

    pub async fn password_import(
        &self,
        schema_name: &str,
        user_id: &str,
        hash: &str,
    ) -> Result<shroudb_sigil_core::credential::PasswordAlgorithm, SigilError> {
        let schema = self.schemas.get(schema_name).await?;
        let cred_field = schema.credential_field_name()?;
        self.credential_import(schema_name, user_id, cred_field, hash)
            .await
    }

    // ── Claim enrichment ─────────────────────────────────────────────

    /// Build enriched claims by merging caller-provided extra_claims with
    /// schema-level claim fields read from the entity's envelope.
    ///
    /// Enriched fields (from envelope) always override caller-provided claims
    /// for the same key, ensuring authoritative values (like roles) come from
    /// the envelope, not the client.
    async fn build_enriched_claims(
        &self,
        schema: &Schema,
        entity_id: &str,
        extra_claims: Option<&serde_json::Value>,
    ) -> Result<Option<serde_json::Value>, SigilError> {
        let claim_fields = schema.claim_fields();

        // Start with caller-provided claims
        let mut merged = serde_json::Map::new();
        if let Some(extra) = extra_claims
            && let Some(obj) = extra.as_object()
        {
            for (k, v) in obj {
                merged.insert(k.clone(), v.clone());
            }
        }

        // Enrich from envelope if schema has claim-annotated fields
        if !claim_fields.is_empty() {
            // Read envelope without decryption — claim fields are index/inert
            // so their values are plaintext in the record
            if let Ok(envelope) = self
                .coordinator
                .get_envelope(schema, entity_id, false)
                .await
            {
                for field_name in &claim_fields {
                    if let Some(value) = envelope.fields.get(*field_name) {
                        // Enriched fields always override caller claims
                        merged.insert(field_name.to_string(), value.clone());
                    }
                }
            }
        }

        if merged.is_empty() {
            Ok(None)
        } else {
            Ok(Some(serde_json::Value::Object(merged)))
        }
    }

    // ── JWT operations ──────────────────────────────────────────────

    pub async fn jwks(&self, schema_name: &str) -> Result<serde_json::Value, SigilError> {
        self.jwt.jwks(schema_name).await
    }
}

/// Resolve the `CredentialPolicy` for a field on a schema, or error if the
/// field does not exist or is not a credential. Clones the policy so call
/// sites can pass it by reference without holding a borrow on the schema.
fn resolve_credential_policy(
    schema: &Schema,
    field_name: &str,
) -> Result<CredentialPolicy, SigilError> {
    schema
        .credential_policy(field_name)
        .cloned()
        .ok_or_else(|| {
            SigilError::SchemaValidation(format!(
                "field '{field_name}' is not a credential field on schema '{}'",
                schema.name
            ))
        })
}

#[cfg(test)]
mod debt_tests {
    //! Engine-level debt tests (AUDIT_2026-04-17). Hard ratchet.

    use super::*;
    use crate::schema_registry::tests::create_test_store;
    use crate::test_support::{RecordingChronicle, RecordingSentry};
    use shroudb_sigil_core::credential::PasswordAlgorithm;
    use shroudb_sigil_core::field_kind::{CredentialPolicy, FieldKind, LockoutPolicy};
    use shroudb_sigil_core::schema::{FieldDef, FieldType};

    fn debt_schema() -> Schema {
        Schema {
            name: "debt_app".to_string(),
            version: 1,
            fields: vec![FieldDef::with_kind(
                "password",
                FieldType::String,
                FieldKind::Credential(CredentialPolicy {
                    algorithm: PasswordAlgorithm::Argon2id,
                    min_length: None,
                    max_length: None,
                    lockout: Some(LockoutPolicy {
                        max_attempts: 5,
                        duration_secs: 900,
                    }),
                }),
                true,
            )],
        }
    }

    async fn engine_with_recorders() -> (
        Arc<SigilEngine<shroudb_storage::EmbeddedStore>>,
        std::sync::Arc<std::sync::Mutex<Vec<shroudb_acl::PolicyRequest>>>,
        std::sync::Arc<std::sync::Mutex<Vec<shroudb_chronicle_core::event::Event>>>,
    ) {
        let store = create_test_store().await;
        let (sentry, reqs) = RecordingSentry::new();
        let (chronicle, events) = RecordingChronicle::new();
        let caps = Capabilities {
            sentry: shroudb_server_bootstrap::Capability::Enabled(sentry),
            chronicle: shroudb_server_bootstrap::Capability::Enabled(chronicle),
            ..Capabilities::for_tests()
        };
        let engine = Arc::new(
            SigilEngine::new_permissive(store, SigilConfig::default(), caps)
                .await
                .expect("engine init"),
        );
        (engine, reqs, events)
    }

    /// DEBT-F5 (AUDIT_2026-04-17): `schema_register` and `schema_alter`
    /// emit audit events with `actor: "system"` hardcoded. Administrative
    /// schema mutations are audited as from nobody. Fix: thread
    /// AuthContext.actor through to schema ops.
    #[tokio::test]
    async fn debt_f05_schema_ops_audit_actor_must_not_be_literal_system() {
        let (engine, _reqs, events) = engine_with_recorders().await;
        engine
            .schema_register(debt_schema())
            .await
            .expect("register");

        let events = events.lock().unwrap();
        let schema_events: Vec<_> = events
            .iter()
            .filter(|e| e.operation.starts_with("schema."))
            .collect();
        assert!(
            !schema_events.is_empty(),
            "DEBT-F5: no schema.* audit event emitted"
        );
        for ev in schema_events {
            assert_ne!(
                ev.actor, "system",
                "DEBT-F5: schema op actor is literal 'system'. Thread caller."
            );
        }
    }

    /// DEBT-F6 (AUDIT_2026-04-17): `envelope_lookup` calls
    /// `check_policy("", schema_name, "lookup")` with an empty principal
    /// because the engine doesn't know the caller. Fix: thread caller so
    /// lookup policy evaluates against a real principal.
    #[tokio::test]
    async fn debt_f06_lookup_policy_principal_must_not_be_empty() {
        // Trigger the lookup path by registering schema + calling
        // envelope_lookup (which will fail EntityNotFound but still emits
        // policy check first).
        let (engine, reqs, _events) = engine_with_recorders().await;
        engine
            .schema_register(debt_schema())
            .await
            .expect("register");

        // lookup will fail (no veil capability in this test), but
        // `check_policy` runs before the veil call in engine.rs — so the
        // policy request is still recorded.
        let _ = engine.envelope_lookup("debt_app", "email", "alice@x").await;

        let requests = reqs.lock().unwrap();
        let lookup_reqs: Vec<_> = requests.iter().filter(|r| r.action == "lookup").collect();
        assert!(
            !lookup_reqs.is_empty(),
            "DEBT-F6: lookup did not invoke policy check"
        );
        for req in lookup_reqs {
            assert!(
                !req.principal.id.is_empty(),
                "DEBT-F6: lookup principal is empty. Thread caller."
            );
        }
    }

    /// DEBT-F10 (AUDIT_2026-04-17): `SigilEngine::new` accepts empty
    /// `Capabilities`. A production deployment missing Sentry or Chronicle
    /// runs without authorization enforcement and without audit — and
    /// nobody is informed. Fix: add strict-mode construction that errors
    /// when required capabilities are absent, OR log a loud warning
    /// (tracing::warn! at minimum) on startup when they are None.
    #[tokio::test]
    async fn debt_f10_production_construction_must_reject_empty_capabilities() {
        let store = create_test_store().await;
        // Currently succeeds — the bug.
        let result =
            SigilEngine::new(store, SigilConfig::default(), Capabilities::for_tests()).await;
        assert!(
            result.is_err(),
            "DEBT-F10: SigilEngine::new(.., Capabilities::for_tests()) succeeds silently. \
             Production can deploy without Sentry/Chronicle. \
             Fix: require them by default, add an opt-in `permissive` mode for tests."
        );
    }
}
