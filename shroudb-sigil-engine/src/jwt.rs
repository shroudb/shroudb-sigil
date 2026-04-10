use std::sync::Arc;

use shroudb_crypto::{JwtAlgorithm, generate_signing_key, public_key_to_jwk, sign_jwt, verify_jwt};
use zeroize::Zeroize;

use shroudb_sigil_core::error::SigilError;
use shroudb_store::Store;

/// Key state in the rotation lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyState {
    /// Currently signing new tokens.
    Active,
    /// No longer signing, but still verifying (drain period).
    Draining,
    /// Fully retired — no signing or verifying.
    Retired,
}

/// A signing key record stored in `sigil.{schema}.keys`.
/// Private key material is zeroed on drop.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SigningKeyRecord {
    pub key_id: String,
    pub algorithm: JwtAlgorithm,
    pub state: KeyState,
    pub private_key_pkcs8: Vec<u8>,
    pub public_key_der: Vec<u8>,
    pub created_at: u64,
}

impl Drop for SigningKeyRecord {
    fn drop(&mut self) {
        self.private_key_pkcs8.zeroize();
    }
}

/// Manages JWT signing keys and token operations.
///
/// Uses `shroudb-crypto` for key generation, signing, and verification.
/// Keys are stored in `sigil.{schema}.keys` via the Store trait —
/// the Store's at-rest encryption protects the private key material.
pub struct JwtManager<S: Store> {
    store: Arc<S>,
    algorithm: JwtAlgorithm,
    default_ttl_secs: u64,
    leeway_secs: u64,
}

impl<S: Store> JwtManager<S> {
    pub fn new(store: Arc<S>, algorithm: JwtAlgorithm, default_ttl_secs: u64) -> Self {
        Self {
            store,
            algorithm,
            default_ttl_secs,
            leeway_secs: 30,
        }
    }

    /// Generate and store a new signing key. Returns the key ID.
    pub async fn create_key(&self, schema: &str) -> Result<String, SigilError> {
        let kp =
            generate_signing_key(self.algorithm).map_err(|e| SigilError::Crypto(e.to_string()))?;

        let key_id = uuid::Uuid::new_v4().to_string();
        let record = SigningKeyRecord {
            key_id: key_id.clone(),
            algorithm: kp.algorithm,
            state: KeyState::Active,
            private_key_pkcs8: kp.private_key_pkcs8.as_bytes().to_vec(),
            public_key_der: kp.public_key_der,
            created_at: now(),
        };

        let ns = keys_namespace(schema);
        let value = serde_json::to_vec(&record).map_err(|e| SigilError::Internal(e.to_string()))?;
        self.store
            .put(&ns, key_id.as_bytes(), &value, None)
            .await
            .map_err(|e| SigilError::Store(e.to_string()))?;

        Ok(key_id)
    }

    /// Ensure at least one active key exists. Creates one if needed.
    pub async fn ensure_active_key(&self, schema: &str) -> Result<String, SigilError> {
        if let Ok(key) = self.get_active_key(schema).await {
            return Ok(key.key_id.clone());
        }
        self.create_key(schema).await
    }

    /// Sign claims into a JWT using the active key.
    pub async fn sign(
        &self,
        schema: &str,
        claims: &serde_json::Value,
    ) -> Result<String, SigilError> {
        let key = self.get_active_key(schema).await?;

        let mut full_claims = claims.clone();
        let now = now();
        if let Some(obj) = full_claims.as_object_mut() {
            obj.entry("iat").or_insert(serde_json::json!(now));
            obj.entry("exp")
                .or_insert(serde_json::json!(now + self.default_ttl_secs));
        }

        let token = sign_jwt(
            &key.private_key_pkcs8,
            key.algorithm,
            &full_claims,
            &key.key_id,
        )
        .map_err(|e| SigilError::Crypto(e.to_string()))?;

        Ok(token)
    }

    /// Verify a JWT against all non-retired keys. Returns the claims on success.
    pub async fn verify(&self, schema: &str, token: &str) -> Result<serde_json::Value, SigilError> {
        let keys = self.list_verifiable_keys(schema).await?;

        for key in &keys {
            if let Ok(claims) =
                verify_jwt(&key.public_key_der, key.algorithm, token, self.leeway_secs)
            {
                return Ok(claims);
            }
        }

        Err(SigilError::InvalidToken)
    }

    /// Generate JWKS (JSON Web Key Set) for external verification.
    pub async fn jwks(&self, schema: &str) -> Result<serde_json::Value, SigilError> {
        let keys = self.list_verifiable_keys(schema).await?;

        let jwks: Vec<serde_json::Value> = keys
            .iter()
            .filter_map(|k| public_key_to_jwk(k.algorithm, &k.public_key_der, &k.key_id).ok())
            .collect();

        Ok(serde_json::json!({ "keys": jwks }))
    }

    /// Rotate: retire the active key and create a new one.
    pub async fn rotate(&self, schema: &str) -> Result<String, SigilError> {
        // Drain the current active key
        if let Ok(active) = self.get_active_key(schema).await {
            let mut updated = active;
            updated.state = KeyState::Draining;
            let ns = keys_namespace(schema);
            let value =
                serde_json::to_vec(&updated).map_err(|e| SigilError::Internal(e.to_string()))?;
            self.store
                .put(&ns, updated.key_id.as_bytes(), &value, None)
                .await
                .map_err(|e| SigilError::Store(e.to_string()))?;
        }

        // Create a new active key
        self.create_key(schema).await
    }

    async fn get_active_key(&self, schema: &str) -> Result<SigningKeyRecord, SigilError> {
        let keys = self.list_all_keys(schema).await?;
        keys.into_iter()
            .find(|k| k.state == KeyState::Active)
            .ok_or_else(|| SigilError::Internal("no active signing key".into()))
    }

    async fn list_verifiable_keys(
        &self,
        schema: &str,
    ) -> Result<Vec<SigningKeyRecord>, SigilError> {
        let keys = self.list_all_keys(schema).await?;
        Ok(keys
            .into_iter()
            .filter(|k| k.state == KeyState::Active || k.state == KeyState::Draining)
            .collect())
    }

    async fn list_all_keys(&self, schema: &str) -> Result<Vec<SigningKeyRecord>, SigilError> {
        let ns = keys_namespace(schema);
        let page = self
            .store
            .list(&ns, None, None, 1000)
            .await
            .map_err(|e| SigilError::Store(e.to_string()))?;

        let mut keys = Vec::new();
        for key_bytes in &page.keys {
            let entry = self
                .store
                .get(&ns, key_bytes, None)
                .await
                .map_err(|e| SigilError::Store(e.to_string()))?;
            let record: SigningKeyRecord = serde_json::from_slice(&entry.value)
                .map_err(|e| SigilError::Internal(e.to_string()))?;
            keys.push(record);
        }

        Ok(keys)
    }
}

fn keys_namespace(schema: &str) -> String {
    format!("sigil.{schema}.keys")
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema_registry::SchemaRegistry;
    use crate::schema_registry::tests::create_test_store;
    use shroudb_sigil_core::schema::{FieldAnnotations, FieldDef, FieldType, Schema};

    async fn setup() -> (
        Arc<shroudb_storage::EmbeddedStore>,
        JwtManager<shroudb_storage::EmbeddedStore>,
    ) {
        let store = create_test_store().await;
        let registry = SchemaRegistry::new(store.clone());
        registry.init().await.unwrap();
        registry
            .register(Schema {
                name: "myapp".to_string(),
                version: 1,
                fields: vec![FieldDef {
                    name: "password".to_string(),
                    field_type: FieldType::String,
                    annotations: FieldAnnotations {
                        credential: true,
                        ..Default::default()
                    },
                    required: true,
                }],
            })
            .await
            .unwrap();

        let jwt = JwtManager::new(store.clone(), JwtAlgorithm::ES256, 900);
        (store, jwt)
    }

    #[tokio::test]
    async fn create_key_and_sign_verify() {
        let (_store, jwt) = setup().await;

        jwt.ensure_active_key("myapp").await.unwrap();

        let claims = serde_json::json!({ "sub": "user1" });
        let token = jwt.sign("myapp", &claims).await.unwrap();

        let verified = jwt.verify("myapp", &token).await.unwrap();
        assert_eq!(verified["sub"], "user1");
    }

    #[tokio::test]
    async fn verify_rejects_tampered_token() {
        let (_store, jwt) = setup().await;
        jwt.ensure_active_key("myapp").await.unwrap();

        let token = jwt
            .sign("myapp", &serde_json::json!({"sub": "user1"}))
            .await
            .unwrap();

        let mut tampered = token.clone();
        tampered.push('x');

        assert!(jwt.verify("myapp", &tampered).await.is_err());
    }

    #[tokio::test]
    async fn jwks_returns_public_keys() {
        let (_store, jwt) = setup().await;
        jwt.ensure_active_key("myapp").await.unwrap();

        let jwks = jwt.jwks("myapp").await.unwrap();
        let keys = jwks["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kty"], "EC");
        assert_eq!(keys[0]["alg"], "ES256");
    }

    #[tokio::test]
    async fn rotate_creates_new_key_drains_old() {
        let (_store, jwt) = setup().await;
        let kid1 = jwt.ensure_active_key("myapp").await.unwrap();

        let kid2 = jwt.rotate("myapp").await.unwrap();
        assert_ne!(kid1, kid2);

        // Old key still verifies (draining)
        let token = jwt
            .sign("myapp", &serde_json::json!({"sub": "user1"}))
            .await
            .unwrap();
        let claims = jwt.verify("myapp", &token).await.unwrap();
        assert_eq!(claims["sub"], "user1");

        // JWKS has both keys
        let jwks = jwt.jwks("myapp").await.unwrap();
        assert_eq!(jwks["keys"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn sign_auto_adds_iat_exp() {
        let (_store, jwt) = setup().await;
        jwt.ensure_active_key("myapp").await.unwrap();

        let token = jwt
            .sign("myapp", &serde_json::json!({"sub": "user1"}))
            .await
            .unwrap();
        let claims = jwt.verify("myapp", &token).await.unwrap();

        assert!(claims["iat"].is_number());
        assert!(claims["exp"].is_number());
        let exp = claims["exp"].as_u64().unwrap();
        let iat = claims["iat"].as_u64().unwrap();
        assert_eq!(exp - iat, 900); // default TTL
    }
}
