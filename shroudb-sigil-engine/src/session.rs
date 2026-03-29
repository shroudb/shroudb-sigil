use std::sync::Arc;

use shroudb_sigil_core::error::SigilError;
use shroudb_sigil_core::session::{RefreshTokenRecord, TokenPair, TokenState};
use shroudb_store::Store;

use crate::jwt::JwtManager;

/// Manages sessions: access tokens (JWT) + refresh tokens (family-based rotation).
///
/// Session lifecycle:
/// 1. `create_session` — verify credentials externally, then call this to issue tokens
/// 2. `refresh` — rotate the refresh token, issue new access token
/// 3. `revoke` — logout a single session (single refresh token)
/// 4. `revoke_all` — logout all sessions for a user
/// 5. `list_sessions` — list active sessions for a user
///
/// Reuse detection: if a rotated (already-used) refresh token is presented,
/// the entire family is revoked. This indicates token theft.
pub struct SessionManager<S: Store> {
    store: Arc<S>,
    jwt: Arc<JwtManager<S>>,
    access_ttl_secs: u64,
    refresh_ttl_secs: u64,
}

impl<S: Store> SessionManager<S> {
    pub fn new(
        store: Arc<S>,
        jwt: Arc<JwtManager<S>>,
        access_ttl_secs: u64,
        refresh_ttl_secs: u64,
    ) -> Self {
        Self {
            store,
            jwt,
            access_ttl_secs,
            refresh_ttl_secs,
        }
    }

    /// Create a new session: issue access + refresh tokens.
    /// The caller is responsible for verifying credentials before calling this.
    pub async fn create_session(
        &self,
        schema: &str,
        user_id: &str,
        extra_claims: Option<&serde_json::Value>,
    ) -> Result<TokenPair, SigilError> {
        self.jwt.ensure_active_key(schema).await?;

        let family_id = uuid::Uuid::new_v4().to_string();
        let refresh_token = generate_opaque_token();

        // Store refresh token record
        let record = RefreshTokenRecord {
            token_id: uuid::Uuid::new_v4().to_string(),
            family_id,
            user_id: user_id.to_string(),
            generation: 0,
            state: TokenState::Active,
            created_at: now(),
            expires_at: now() + self.refresh_ttl_secs,
        };

        let ns = sessions_namespace(schema);
        let value = serde_json::to_vec(&record).map_err(|e| SigilError::Internal(e.to_string()))?;
        self.store
            .put(&ns, refresh_token.as_bytes(), &value, None)
            .await
            .map_err(|e| SigilError::Store(e.to_string()))?;

        // Sign access token
        let mut claims = serde_json::json!({
            "sub": user_id,
        });
        if let Some(extra) = extra_claims
            && let Some(obj) = extra.as_object()
        {
            for (k, v) in obj {
                claims[k] = v.clone();
            }
        }

        let access_token = self.jwt.sign(schema, &claims).await?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            expires_in: self.access_ttl_secs,
        })
    }

    /// Refresh: rotate the refresh token and issue a new access token.
    ///
    /// If the presented token has already been rotated (reuse detection),
    /// the entire family is revoked and `TokenReuse` is returned.
    pub async fn refresh(&self, schema: &str, token: &str) -> Result<TokenPair, SigilError> {
        let ns = sessions_namespace(schema);
        let entry = self
            .store
            .get(&ns, token.as_bytes(), None)
            .await
            .map_err(|_| SigilError::InvalidToken)?;

        let record: RefreshTokenRecord = serde_json::from_slice(&entry.value)
            .map_err(|e| SigilError::Internal(e.to_string()))?;

        // Reuse detection
        if record.state == TokenState::Rotated {
            self.revoke_family(schema, &record.family_id).await?;
            return Err(SigilError::TokenReuse);
        }

        if record.state == TokenState::Revoked {
            return Err(SigilError::InvalidToken);
        }

        if now() > record.expires_at {
            return Err(SigilError::TokenExpired);
        }

        // Mark old token as rotated
        let mut old = record.clone();
        old.state = TokenState::Rotated;
        let old_value =
            serde_json::to_vec(&old).map_err(|e| SigilError::Internal(e.to_string()))?;
        self.store
            .put(&ns, token.as_bytes(), &old_value, None)
            .await
            .map_err(|e| SigilError::Store(e.to_string()))?;

        // Issue new refresh token in same family
        let new_refresh = generate_opaque_token();
        let new_record = RefreshTokenRecord {
            token_id: uuid::Uuid::new_v4().to_string(),
            family_id: record.family_id,
            user_id: record.user_id.clone(),
            generation: record.generation + 1,
            state: TokenState::Active,
            created_at: now(),
            expires_at: now() + self.refresh_ttl_secs,
        };
        let new_value =
            serde_json::to_vec(&new_record).map_err(|e| SigilError::Internal(e.to_string()))?;
        self.store
            .put(&ns, new_refresh.as_bytes(), &new_value, None)
            .await
            .map_err(|e| SigilError::Store(e.to_string()))?;

        // Sign new access token
        let claims = serde_json::json!({ "sub": record.user_id });
        let access_token = self.jwt.sign(schema, &claims).await?;

        Ok(TokenPair {
            access_token,
            refresh_token: new_refresh,
            expires_in: self.access_ttl_secs,
        })
    }

    /// Revoke a single refresh token (logout one session).
    pub async fn revoke(&self, schema: &str, token: &str) -> Result<(), SigilError> {
        let ns = sessions_namespace(schema);
        let entry = self
            .store
            .get(&ns, token.as_bytes(), None)
            .await
            .map_err(|_| SigilError::InvalidToken)?;

        let mut record: RefreshTokenRecord = serde_json::from_slice(&entry.value)
            .map_err(|e| SigilError::Internal(e.to_string()))?;

        record.state = TokenState::Revoked;
        let value = serde_json::to_vec(&record).map_err(|e| SigilError::Internal(e.to_string()))?;
        self.store
            .put(&ns, token.as_bytes(), &value, None)
            .await
            .map_err(|e| SigilError::Store(e.to_string()))?;

        Ok(())
    }

    /// Revoke all sessions for a user (logout everywhere).
    pub async fn revoke_all(&self, schema: &str, user_id: &str) -> Result<u64, SigilError> {
        let ns = sessions_namespace(schema);
        let page = self
            .store
            .list(&ns, None, None, 10_000)
            .await
            .map_err(|e| SigilError::Store(e.to_string()))?;

        let mut revoked = 0u64;
        for key in &page.keys {
            if let Ok(entry) = self.store.get(&ns, key, None).await
                && let Ok(mut record) = serde_json::from_slice::<RefreshTokenRecord>(&entry.value)
                && record.user_id == user_id
                && record.state == TokenState::Active
            {
                record.state = TokenState::Revoked;
                if let Ok(value) = serde_json::to_vec(&record) {
                    let _ = self.store.put(&ns, key, &value, None).await;
                    revoked += 1;
                }
            }
        }

        Ok(revoked)
    }

    /// List active sessions for a user.
    pub async fn list_sessions(
        &self,
        schema: &str,
        user_id: &str,
    ) -> Result<Vec<RefreshTokenRecord>, SigilError> {
        let ns = sessions_namespace(schema);
        let page = self
            .store
            .list(&ns, None, None, 10_000)
            .await
            .map_err(|e| SigilError::Store(e.to_string()))?;

        let mut sessions = Vec::new();
        for key in &page.keys {
            if let Ok(entry) = self.store.get(&ns, key, None).await
                && let Ok(record) = serde_json::from_slice::<RefreshTokenRecord>(&entry.value)
                && record.user_id == user_id
                && record.state == TokenState::Active
                && now() <= record.expires_at
            {
                sessions.push(record);
            }
        }

        Ok(sessions)
    }

    /// Revoke all tokens in a family (used by reuse detection).
    async fn revoke_family(&self, schema: &str, family_id: &str) -> Result<(), SigilError> {
        let ns = sessions_namespace(schema);
        let page = self
            .store
            .list(&ns, None, None, 10_000)
            .await
            .map_err(|e| SigilError::Store(e.to_string()))?;

        for key in &page.keys {
            if let Ok(entry) = self.store.get(&ns, key, None).await
                && let Ok(mut record) = serde_json::from_slice::<RefreshTokenRecord>(&entry.value)
                && record.family_id == family_id
            {
                record.state = TokenState::Revoked;
                if let Ok(value) = serde_json::to_vec(&record) {
                    let _ = self.store.put(&ns, key, &value, None).await;
                }
            }
        }

        Ok(())
    }
}

fn sessions_namespace(schema: &str) -> String {
    format!("sigil.{schema}.sessions")
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Generate a cryptographically random opaque token.
fn generate_opaque_token() -> String {
    let mut bytes = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .expect("system random failed");
    hex::encode(bytes)
}

use ring::rand::SecureRandom;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::JwtManager;
    use crate::schema_registry::SchemaRegistry;
    use crate::schema_registry::tests::create_test_store;
    use shroudb_crypto::JwtAlgorithm;
    use shroudb_sigil_core::schema::{FieldAnnotations, FieldDef, FieldType, Schema};

    async fn setup() -> (
        Arc<shroudb_storage::EmbeddedStore>,
        SessionManager<shroudb_storage::EmbeddedStore>,
    ) {
        let store = create_test_store().await;
        let registry = SchemaRegistry::new(store.clone());
        registry.init().await.unwrap();
        registry
            .register(Schema {
                name: "myapp".to_string(),
                fields: vec![FieldDef {
                    name: "password".to_string(),
                    field_type: FieldType::String,
                    annotations: FieldAnnotations {
                        credential: true,
                        ..Default::default()
                    },
                }],
            })
            .await
            .unwrap();

        let jwt = Arc::new(JwtManager::new(store.clone(), JwtAlgorithm::ES256, 900));
        let session = SessionManager::new(store.clone(), jwt, 900, 2_592_000);
        (store, session)
    }

    #[tokio::test]
    async fn create_session_returns_tokens() {
        let (_store, sm) = setup().await;
        let pair = sm.create_session("myapp", "user1", None).await.unwrap();
        assert!(!pair.access_token.is_empty());
        assert!(!pair.refresh_token.is_empty());
        assert_eq!(pair.expires_in, 900);
    }

    #[tokio::test]
    async fn refresh_rotates_token() {
        let (_store, sm) = setup().await;
        let pair1 = sm.create_session("myapp", "user1", None).await.unwrap();
        let pair2 = sm.refresh("myapp", &pair1.refresh_token).await.unwrap();

        // New tokens issued
        assert_ne!(pair1.refresh_token, pair2.refresh_token);
        assert_ne!(pair1.access_token, pair2.access_token);
    }

    #[tokio::test]
    async fn reuse_detection_revokes_family() {
        let (_store, sm) = setup().await;
        let pair1 = sm.create_session("myapp", "user1", None).await.unwrap();

        // First refresh succeeds
        let pair2 = sm.refresh("myapp", &pair1.refresh_token).await.unwrap();

        // Reusing the old token triggers family revocation
        let err = sm.refresh("myapp", &pair1.refresh_token).await.unwrap_err();
        assert!(err.to_string().contains("reuse"));

        // The new token from pair2 should also be revoked (family killed)
        let err = sm.refresh("myapp", &pair2.refresh_token).await.unwrap_err();
        assert!(
            err.to_string().contains("invalid") || err.to_string().contains("Revoked"),
            "expected revoked token error, got: {err}"
        );
    }

    #[tokio::test]
    async fn revoke_single_session() {
        let (_store, sm) = setup().await;
        let pair = sm.create_session("myapp", "user1", None).await.unwrap();

        sm.revoke("myapp", &pair.refresh_token).await.unwrap();

        let err = sm.refresh("myapp", &pair.refresh_token).await.unwrap_err();
        assert!(err.to_string().contains("invalid"));
    }

    #[tokio::test]
    async fn revoke_all_sessions() {
        let (_store, sm) = setup().await;

        // Create multiple sessions
        let pair1 = sm.create_session("myapp", "user1", None).await.unwrap();
        let pair2 = sm.create_session("myapp", "user1", None).await.unwrap();
        let _pair3 = sm.create_session("myapp", "user2", None).await.unwrap();

        let revoked = sm.revoke_all("myapp", "user1").await.unwrap();
        assert_eq!(revoked, 2);

        // user1 sessions revoked
        assert!(sm.refresh("myapp", &pair1.refresh_token).await.is_err());
        assert!(sm.refresh("myapp", &pair2.refresh_token).await.is_err());

        // user2 unaffected
        let sessions = sm.list_sessions("myapp", "user2").await.unwrap();
        assert_eq!(sessions.len(), 1);
    }

    #[tokio::test]
    async fn list_sessions_returns_active_only() {
        let (_store, sm) = setup().await;

        sm.create_session("myapp", "user1", None).await.unwrap();
        sm.create_session("myapp", "user1", None).await.unwrap();
        let pair3 = sm.create_session("myapp", "user1", None).await.unwrap();

        // Revoke one
        sm.revoke("myapp", &pair3.refresh_token).await.unwrap();

        let sessions = sm.list_sessions("myapp", "user1").await.unwrap();
        assert_eq!(sessions.len(), 2);
    }

    #[tokio::test]
    async fn extra_claims_merged_into_access_token() {
        let (_store, sm) = setup().await;
        let extra = serde_json::json!({"role": "admin", "org": "acme"});
        let pair = sm
            .create_session("myapp", "user1", Some(&extra))
            .await
            .unwrap();

        // Verify the access token contains the extra claims
        let jwt = JwtManager::new(sm.store.clone(), JwtAlgorithm::ES256, 900);
        let claims = jwt.verify("myapp", &pair.access_token).await.unwrap();
        assert_eq!(claims["sub"], "user1");
        assert_eq!(claims["role"], "admin");
        assert_eq!(claims["org"], "acme");
    }
}
