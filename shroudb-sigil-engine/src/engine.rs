use std::sync::Arc;

use shroudb_crypto::JwtAlgorithm;

use shroudb_sigil_core::credential::PasswordPolicy;
use shroudb_sigil_core::error::SigilError;
use shroudb_sigil_core::record::EnvelopeRecord;
use shroudb_sigil_core::schema::{FieldDef, Schema};
use shroudb_sigil_core::session::TokenPair;
use shroudb_store::Store;

use crate::capabilities::Capabilities;
use crate::credential::CredentialManager;
use crate::jwt::JwtManager;
use crate::schema_registry::SchemaRegistry;
use crate::session::SessionManager;
use crate::write_coordinator::WriteCoordinator;

/// Configuration for the Sigil engine.
pub struct SigilConfig {
    pub password_policy: PasswordPolicy,
    pub jwt_algorithm: JwtAlgorithm,
    pub access_ttl_secs: u64,
    pub refresh_ttl_secs: u64,
}

impl Default for SigilConfig {
    fn default() -> Self {
        Self {
            password_policy: PasswordPolicy::default(),
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
    /// Create a new Sigil engine.
    pub async fn new(
        store: Arc<S>,
        config: SigilConfig,
        capabilities: Capabilities,
    ) -> Result<Self, SigilError> {
        let schemas = SchemaRegistry::new(store.clone());
        schemas.init().await?;

        let credentials = Arc::new(CredentialManager::new(
            store.clone(),
            config.password_policy,
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
        self.schemas.register(schema).await
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
        self.schemas.alter(name, add_fields, remove_fields).await
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
        let schema = self.schemas.get(schema_name).await?;
        self.coordinator
            .get_envelope(&schema, entity_id, decrypt)
            .await
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
        let schema = self.schemas.get(schema_name).await?;
        let enforce_lockout = schema.field_lockout(field_name);
        self.credentials
            .verify(schema_name, entity_id, field_name, value, enforce_lockout)
            .await
    }

    /// Look up an entity by a searchable field value via Veil.
    /// Returns the entity_id if found.
    pub async fn envelope_lookup(
        &self,
        _schema_name: &str,
        field_name: &str,
        field_value: &str,
    ) -> Result<String, SigilError> {
        self.coordinator
            .lookup_by_field(field_name, field_value)
            .await
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
        // Verify credentials first (infers credential field from schema)
        let schema = self.schemas.get(schema_name).await?;
        let cred_field = schema.credential_field_name()?;
        let enforce_lockout = schema.field_lockout(cred_field);
        self.credentials
            .verify(
                schema_name,
                entity_id,
                cred_field,
                password,
                enforce_lockout,
            )
            .await?;

        let merged = self
            .build_enriched_claims(&schema, entity_id, extra_claims)
            .await?;

        self.sessions
            .create_session(schema_name, entity_id, merged.as_ref())
            .await
    }

    pub async fn session_refresh(
        &self,
        schema_name: &str,
        token: &str,
    ) -> Result<TokenPair, SigilError> {
        let schema = self.schemas.get(schema_name).await?;
        let claim_fields = schema.claim_fields();

        let enrichment = if !claim_fields.is_empty() {
            let entity_id = self.sessions.peek_entity_id(schema_name, token).await?;
            self.build_enriched_claims(&schema, &entity_id, None)
                .await?
        } else {
            None
        };

        self.sessions
            .refresh(schema_name, token, enrichment.as_ref())
            .await
    }

    pub async fn session_revoke(&self, schema_name: &str, token: &str) -> Result<(), SigilError> {
        self.sessions.revoke(schema_name, token).await
    }

    pub async fn session_revoke_all(
        &self,
        schema_name: &str,
        entity_id: &str,
    ) -> Result<u64, SigilError> {
        self.sessions.revoke_all(schema_name, entity_id).await
    }

    pub async fn session_list(
        &self,
        schema_name: &str,
        entity_id: &str,
    ) -> Result<Vec<shroudb_sigil_core::session::RefreshTokenRecord>, SigilError> {
        self.sessions.list_sessions(schema_name, entity_id).await
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
        let schema = self.schemas.get(schema_name).await?;
        let enforce_lockout = schema.field_lockout(field_name);
        self.credentials
            .change_credential(
                schema_name,
                entity_id,
                field_name,
                old_value,
                new_value,
                enforce_lockout,
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
        self.credentials
            .reset_credential(schema_name, entity_id, field_name, new_value)
            .await
    }

    pub async fn credential_import(
        &self,
        schema_name: &str,
        entity_id: &str,
        field_name: &str,
        hash: &str,
    ) -> Result<shroudb_sigil_core::credential::PasswordAlgorithm, SigilError> {
        self.credentials
            .import_credential(schema_name, entity_id, field_name, hash)
            .await
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
