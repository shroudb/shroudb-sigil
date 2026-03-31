use std::sync::Arc;

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use zeroize::Zeroize;

use shroudb_sigil_core::credential::{CredentialRecord, PasswordAlgorithm, PasswordPolicy};
use shroudb_sigil_core::error::SigilError;
use shroudb_store::Store;

use crate::write_coordinator::credential_store_key;

/// Manages credential fields via the Store trait.
///
/// Sigil owns password hashing directly — the Store just sees opaque bytes.
/// This is the clean break from v0.1 where ShrouDB-the-credential-store
/// owned hashing because it *was* the credential engine.
///
/// Credentials are keyed by `{entity_id}/{field_name}`, supporting
/// multiple credential fields per schema (e.g., password + recovery_key).
pub struct CredentialManager<S: Store> {
    store: Arc<S>,
    policy: PasswordPolicy,
}

impl<S: Store> CredentialManager<S> {
    pub fn new(store: Arc<S>, policy: PasswordPolicy) -> Self {
        Self { store, policy }
    }

    /// Hash a new credential and store the credential record.
    pub async fn set_credential(
        &self,
        schema: &str,
        entity_id: &str,
        field_name: &str,
        plaintext: &str,
    ) -> Result<(), SigilError> {
        self.validate_password_length(plaintext)?;

        let ns = credentials_namespace(schema);
        let store_key = credential_store_key(entity_id, field_name);

        // Check for existing credential
        if self
            .store
            .get(&ns, store_key.as_bytes(), None)
            .await
            .is_ok()
        {
            return Err(SigilError::EntityExists);
        }

        let hash = hash_argon2id(plaintext)?;
        let record = CredentialRecord {
            entity_id: entity_id.to_string(),
            hash,
            algorithm: PasswordAlgorithm::Argon2id,
            failed_attempts: 0,
            locked_until: None,
            created_at: now(),
            updated_at: now(),
        };

        let value = serde_json::to_vec(&record).map_err(|e| SigilError::Internal(e.to_string()))?;
        self.store
            .put(&ns, store_key.as_bytes(), &value, None)
            .await
            .map_err(|e| SigilError::Store(e.to_string()))?;

        Ok(())
    }

    /// Import a pre-hashed credential. Validates the hash format and detects
    /// the algorithm. On next verify, non-Argon2id hashes are transparently
    /// rehashed.
    pub async fn import_credential(
        &self,
        schema: &str,
        entity_id: &str,
        field_name: &str,
        hash: &str,
    ) -> Result<PasswordAlgorithm, SigilError> {
        let ns = credentials_namespace(schema);
        let store_key = credential_store_key(entity_id, field_name);

        if self
            .store
            .get(&ns, store_key.as_bytes(), None)
            .await
            .is_ok()
        {
            return Err(SigilError::EntityExists);
        }

        let algorithm = detect_algorithm(hash)?;
        validate_hash_format(hash)?;

        let record = CredentialRecord {
            entity_id: entity_id.to_string(),
            hash: hash.to_string(),
            algorithm,
            failed_attempts: 0,
            locked_until: None,
            created_at: now(),
            updated_at: now(),
        };

        let value = serde_json::to_vec(&record).map_err(|e| SigilError::Internal(e.to_string()))?;
        self.store
            .put(&ns, store_key.as_bytes(), &value, None)
            .await
            .map_err(|e| SigilError::Store(e.to_string()))?;

        Ok(algorithm)
    }

    /// Verify a credential. Handles lockout and transparent rehash.
    ///
    /// Returns `Ok(true)` on success, `Err(AccountLocked)` if locked,
    /// `Err(VerificationFailed)` on wrong password.
    pub async fn verify(
        &self,
        schema: &str,
        entity_id: &str,
        field_name: &str,
        plaintext: &str,
    ) -> Result<bool, SigilError> {
        let ns = credentials_namespace(schema);
        let store_key = credential_store_key(entity_id, field_name);

        let entry = self
            .store
            .get(&ns, store_key.as_bytes(), None)
            .await
            .map_err(|_| SigilError::EntityNotFound)?;

        let mut record: CredentialRecord = serde_json::from_slice(&entry.value)
            .map_err(|e| SigilError::Internal(e.to_string()))?;

        // Check lockout
        if let Some(locked_until) = record.locked_until {
            let current = now();
            if current < locked_until {
                return Err(SigilError::AccountLocked {
                    retry_after_secs: locked_until - current,
                });
            }
            record.locked_until = None;
            record.failed_attempts = 0;
        }

        // Verify credential against stored hash (any algorithm)
        let valid = verify_password(plaintext, &record.hash)?;

        if valid {
            record.failed_attempts = 0;
            record.locked_until = None;

            // Transparent rehash: if not Argon2id, rehash on successful verify
            if record.algorithm != PasswordAlgorithm::Argon2id {
                let new_hash = hash_argon2id(plaintext)?;
                record.hash = new_hash;
                record.algorithm = PasswordAlgorithm::Argon2id;
                tracing::info!(entity_id, field_name, "transparent rehash to argon2id");
            }
        } else {
            record.failed_attempts += 1;
            if record.failed_attempts >= self.policy.max_failed_attempts {
                record.locked_until = Some(now() + self.policy.lockout_duration_secs);
            }
        }

        // Update record
        record.updated_at = now();
        let value = serde_json::to_vec(&record).map_err(|e| SigilError::Internal(e.to_string()))?;
        self.store
            .put(&ns, store_key.as_bytes(), &value, None)
            .await
            .map_err(|e| SigilError::Store(e.to_string()))?;

        if valid {
            Ok(true)
        } else {
            Err(SigilError::VerificationFailed)
        }
    }

    /// Change credential (requires old value verification).
    pub async fn change_credential(
        &self,
        schema: &str,
        entity_id: &str,
        field_name: &str,
        old_plaintext: &str,
        new_plaintext: &str,
    ) -> Result<(), SigilError> {
        self.validate_password_length(new_plaintext)?;

        // Verify old credential (this also handles lockout)
        self.verify(schema, entity_id, field_name, old_plaintext)
            .await?;

        // Hash new credential
        let new_hash = hash_argon2id(new_plaintext)?;

        let ns = credentials_namespace(schema);
        let store_key = credential_store_key(entity_id, field_name);

        let entry = self
            .store
            .get(&ns, store_key.as_bytes(), None)
            .await
            .map_err(|_| SigilError::EntityNotFound)?;

        let mut record: CredentialRecord = serde_json::from_slice(&entry.value)
            .map_err(|e| SigilError::Internal(e.to_string()))?;

        record.hash = new_hash;
        record.algorithm = PasswordAlgorithm::Argon2id;
        record.failed_attempts = 0;
        record.locked_until = None;
        record.updated_at = now();

        let value = serde_json::to_vec(&record).map_err(|e| SigilError::Internal(e.to_string()))?;
        self.store
            .put(&ns, store_key.as_bytes(), &value, None)
            .await
            .map_err(|e| SigilError::Store(e.to_string()))?;

        Ok(())
    }

    /// Force-reset a credential without requiring the old one.
    /// Clears lockout state.
    pub async fn reset_credential(
        &self,
        schema: &str,
        entity_id: &str,
        field_name: &str,
        new_plaintext: &str,
    ) -> Result<(), SigilError> {
        self.validate_password_length(new_plaintext)?;

        let new_hash = hash_argon2id(new_plaintext)?;

        let ns = credentials_namespace(schema);
        let store_key = credential_store_key(entity_id, field_name);

        let entry = self
            .store
            .get(&ns, store_key.as_bytes(), None)
            .await
            .map_err(|_| SigilError::EntityNotFound)?;

        let mut record: CredentialRecord = serde_json::from_slice(&entry.value)
            .map_err(|e| SigilError::Internal(e.to_string()))?;

        record.hash = new_hash;
        record.algorithm = PasswordAlgorithm::Argon2id;
        record.failed_attempts = 0;
        record.locked_until = None;
        record.updated_at = now();

        let value = serde_json::to_vec(&record).map_err(|e| SigilError::Internal(e.to_string()))?;
        self.store
            .put(&ns, store_key.as_bytes(), &value, None)
            .await
            .map_err(|e| SigilError::Store(e.to_string()))?;

        Ok(())
    }

    fn validate_password_length(&self, plaintext: &str) -> Result<(), SigilError> {
        if plaintext.len() < self.policy.min_length {
            return Err(SigilError::InvalidField {
                field: "credential".into(),
                reason: format!("must be at least {} characters", self.policy.min_length),
            });
        }
        if plaintext.len() > self.policy.max_length {
            return Err(SigilError::InvalidField {
                field: "credential".into(),
                reason: format!("must be at most {} characters", self.policy.max_length),
            });
        }
        Ok(())
    }
}

fn credentials_namespace(schema: &str) -> String {
    format!("sigil.{schema}.credentials")
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Hash a password with Argon2id using default parameters.
/// The plaintext copy is zeroed after hashing.
fn hash_argon2id(plaintext: &str) -> Result<String, SigilError> {
    let mut pw_bytes = plaintext.as_bytes().to_vec();
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let result = Argon2::default()
        .hash_password(&pw_bytes, &salt)
        .map_err(|e| SigilError::Crypto(e.to_string()));
    pw_bytes.zeroize();
    Ok(result?.to_string())
}

/// Verify a password against any supported hash format.
/// The plaintext copy is zeroed after verification.
fn verify_password(plaintext: &str, hash: &str) -> Result<bool, SigilError> {
    let mut pw_bytes = plaintext.as_bytes().to_vec();
    let result = verify_password_inner(&pw_bytes, hash);
    pw_bytes.zeroize();
    result
}

fn verify_password_inner(pw_bytes: &[u8], hash: &str) -> Result<bool, SigilError> {
    if hash.starts_with("$argon2") || hash.starts_with("$scrypt$") {
        let parsed = PasswordHash::new(hash).map_err(|e| SigilError::Crypto(e.to_string()))?;
        Ok(Argon2::default().verify_password(pw_bytes, &parsed).is_ok())
    } else if hash.starts_with("$2b$") || hash.starts_with("$2a$") || hash.starts_with("$2y$") {
        Ok(shroudb_crypto::password_verify(pw_bytes, hash.as_bytes())
            .map_err(|e| SigilError::Crypto(e.to_string()))?)
    } else {
        Err(SigilError::Crypto(format!(
            "unrecognized hash format: {}",
            &hash[..hash.len().min(10)]
        )))
    }
}

/// Detect the password algorithm from a hash string.
fn detect_algorithm(hash: &str) -> Result<PasswordAlgorithm, SigilError> {
    if hash.starts_with("$argon2id$") {
        Ok(PasswordAlgorithm::Argon2id)
    } else if hash.starts_with("$argon2i$") {
        Ok(PasswordAlgorithm::Argon2i)
    } else if hash.starts_with("$argon2d$") {
        Ok(PasswordAlgorithm::Argon2d)
    } else if hash.starts_with("$2b$") || hash.starts_with("$2a$") || hash.starts_with("$2y$") {
        Ok(PasswordAlgorithm::Bcrypt)
    } else if hash.starts_with("$scrypt$") {
        Ok(PasswordAlgorithm::Scrypt)
    } else {
        Err(SigilError::ImportFailed(
            "unrecognized hash algorithm".into(),
        ))
    }
}

/// Validate that a hash string is well-formed.
fn validate_hash_format(hash: &str) -> Result<(), SigilError> {
    if hash.starts_with("$2b$") || hash.starts_with("$2a$") || hash.starts_with("$2y$") {
        if hash.len() != 60 {
            return Err(SigilError::ImportFailed(
                "invalid bcrypt hash length (expected 60)".into(),
            ));
        }
    } else if hash.starts_with("$argon2") || hash.starts_with("$scrypt$") {
        // Validate by parsing — PHC string format
        PasswordHash::new(hash)
            .map_err(|e| SigilError::ImportFailed(format!("invalid PHC hash: {e}")))?;
    } else {
        return Err(SigilError::ImportFailed("unrecognized hash format".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use shroudb_store::Store as _;

    use super::*;
    use crate::schema_registry::tests::create_test_store;

    async fn setup() -> (
        Arc<shroudb_storage::EmbeddedStore>,
        CredentialManager<shroudb_storage::EmbeddedStore>,
    ) {
        let store = create_test_store().await;
        // Create the credentials namespace
        store
            .namespace_create(
                "sigil.myapp.credentials",
                shroudb_store::NamespaceConfig::default(),
            )
            .await
            .unwrap();
        let mgr = CredentialManager::new(store.clone(), PasswordPolicy::default());
        (store, mgr)
    }

    #[tokio::test]
    async fn set_and_verify_credential() {
        let (_store, mgr) = setup().await;
        mgr.set_credential("myapp", "user1", "password", "correcthorse")
            .await
            .unwrap();
        let valid = mgr
            .verify("myapp", "user1", "password", "correcthorse")
            .await
            .unwrap();
        assert!(valid);
    }

    #[tokio::test]
    async fn wrong_credential_fails() {
        let (_store, mgr) = setup().await;
        mgr.set_credential("myapp", "user1", "password", "correcthorse")
            .await
            .unwrap();
        let err = mgr
            .verify("myapp", "user1", "password", "wrongpassword")
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn duplicate_set_rejected() {
        let (_store, mgr) = setup().await;
        mgr.set_credential("myapp", "user1", "password", "password1")
            .await
            .unwrap();
        let err = mgr
            .set_credential("myapp", "user1", "password", "password2")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[tokio::test]
    async fn lockout_after_failed_attempts() {
        let (_store, mgr) = setup().await;
        mgr.set_credential("myapp", "user1", "password", "correcthorse")
            .await
            .unwrap();

        // Exhaust attempts (default: 5)
        for _ in 0..5 {
            let _ = mgr.verify("myapp", "user1", "password", "wrong").await;
        }

        // Next attempt should be locked
        let err = mgr
            .verify("myapp", "user1", "password", "correcthorse")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("locked"));
    }

    #[tokio::test]
    async fn change_credential() {
        let (_store, mgr) = setup().await;
        mgr.set_credential("myapp", "user1", "password", "oldpassword")
            .await
            .unwrap();
        mgr.change_credential("myapp", "user1", "password", "oldpassword", "newpassword")
            .await
            .unwrap();

        // Old credential fails
        assert!(
            mgr.verify("myapp", "user1", "password", "oldpassword")
                .await
                .is_err()
        );
        // New credential works
        assert!(
            mgr.verify("myapp", "user1", "password", "newpassword")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn reset_credential_clears_lockout() {
        let (_store, mgr) = setup().await;
        mgr.set_credential("myapp", "user1", "password", "original")
            .await
            .unwrap();

        // Lock the account
        for _ in 0..5 {
            let _ = mgr.verify("myapp", "user1", "password", "wrong").await;
        }
        assert!(
            mgr.verify("myapp", "user1", "password", "original")
                .await
                .is_err()
        );

        // Reset
        mgr.reset_credential("myapp", "user1", "password", "newpassword")
            .await
            .unwrap();

        // Should work now (lockout cleared)
        assert!(
            mgr.verify("myapp", "user1", "password", "newpassword")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn import_argon2id_hash() {
        let (_store, mgr) = setup().await;

        // Generate a real argon2id hash
        let hash = hash_argon2id("imported_pw").unwrap();
        let algo = mgr
            .import_credential("myapp", "user1", "password", &hash)
            .await
            .unwrap();
        assert_eq!(algo, PasswordAlgorithm::Argon2id);

        // Verify works
        assert!(
            mgr.verify("myapp", "user1", "password", "imported_pw")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn credential_too_short_rejected() {
        let (_store, mgr) = setup().await;
        let err = mgr
            .set_credential("myapp", "user1", "password", "short")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("at least"));
    }

    #[tokio::test]
    async fn verify_nonexistent_entity() {
        let (_store, mgr) = setup().await;
        let err = mgr
            .verify("myapp", "nope", "password", "password")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[tokio::test]
    async fn multi_credential_fields() {
        let (_store, mgr) = setup().await;
        mgr.set_credential("myapp", "user1", "password", "correcthorse")
            .await
            .unwrap();
        mgr.set_credential("myapp", "user1", "recovery_key", "my-recovery-key-123")
            .await
            .unwrap();

        // Each verifies independently
        assert!(
            mgr.verify("myapp", "user1", "password", "correcthorse")
                .await
                .is_ok()
        );
        assert!(
            mgr.verify("myapp", "user1", "recovery_key", "my-recovery-key-123")
                .await
                .is_ok()
        );

        // Cross-verify fails
        assert!(
            mgr.verify("myapp", "user1", "password", "my-recovery-key-123")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn detect_algorithm_from_hash() {
        assert_eq!(
            detect_algorithm("$argon2id$v=19$m=65536,t=3,p=4$salt$hash").unwrap(),
            PasswordAlgorithm::Argon2id
        );
        assert_eq!(
            detect_algorithm("$2b$12$saltsaltsaltsaltsaltsOhash").unwrap(),
            PasswordAlgorithm::Bcrypt
        );
        assert_eq!(
            detect_algorithm("$scrypt$ln=15,r=8,p=1$salt$hash").unwrap(),
            PasswordAlgorithm::Scrypt
        );
        assert!(detect_algorithm("notahash").is_err());
    }
}
