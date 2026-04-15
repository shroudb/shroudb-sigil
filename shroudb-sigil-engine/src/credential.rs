use std::sync::Arc;

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use tokio::sync::Semaphore;
use zeroize::Zeroize;

use shroudb_sigil_core::credential::{CredentialRecord, EngineResourceConfig, PasswordAlgorithm};
use shroudb_sigil_core::error::SigilError;
use shroudb_sigil_core::field_kind::CredentialPolicy;
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
///
/// Per-call `CredentialPolicy` drives algorithm, length bounds, and lockout —
/// the manager itself only holds process-scoped resource limits
/// (`hash_semaphore`). Each Argon2id hash uses ~64 MiB (m_cost=65536) ×
/// p_cost=4, so the semaphore bounds peak memory under load.
pub struct CredentialManager<S: Store> {
    store: Arc<S>,
    hash_semaphore: Arc<Semaphore>,
}

impl<S: Store> CredentialManager<S> {
    pub fn new(store: Arc<S>, config: EngineResourceConfig) -> Self {
        let permits = if config.max_concurrent_hashes == 0 {
            Semaphore::MAX_PERMITS
        } else {
            config.max_concurrent_hashes as usize
        };
        Self {
            store,
            hash_semaphore: Arc::new(Semaphore::new(permits)),
        }
    }

    /// Hash a new credential and store the credential record.
    ///
    /// The algorithm is taken from `policy.algorithm`. Currently supported for
    /// new credentials: `Argon2id` (human-auth) and `Sha256` (high-entropy
    /// machine credentials — the 32-byte floor is enforced by schema validation).
    pub async fn set_credential(
        &self,
        schema: &str,
        entity_id: &str,
        field_name: &str,
        plaintext: &str,
        policy: &CredentialPolicy,
    ) -> Result<(), SigilError> {
        validate_credential_length(policy, plaintext)?;

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

        let (hash, algorithm) = {
            // Argon2id holds the semaphore; Sha256 is cheap and does not.
            if matches!(policy.algorithm, PasswordAlgorithm::Sha256) {
                (hash_sha256_hex(plaintext), PasswordAlgorithm::Sha256)
            } else {
                let _permit = self
                    .hash_semaphore
                    .acquire()
                    .await
                    .map_err(|_| SigilError::Internal("hash semaphore closed".into()))?;
                (
                    hash_for_new_credential(policy, plaintext)?,
                    PasswordAlgorithm::Argon2id,
                )
            }
        };
        let record = CredentialRecord {
            entity_id: entity_id.to_string(),
            hash,
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

        Ok(())
    }

    /// Import a pre-hashed credential. Validates the hash format against the
    /// schema's declared algorithm. Non-Argon2id legacy hashes are transparently
    /// rehashed to Argon2id on the next successful verify, when the policy
    /// targets Argon2id.
    pub async fn import_credential(
        &self,
        schema: &str,
        entity_id: &str,
        field_name: &str,
        hash: &str,
        policy: &CredentialPolicy,
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

        let algorithm = validate_imported_hash(hash, policy)?;

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
    /// Lockout enforcement is driven by `policy.lockout`: presence of a
    /// `LockoutPolicy` enables it (human-auth), `None` disables it (machine-auth
    /// credentials where lockout is a denial-of-service vector).
    ///
    /// The stored record carries its own algorithm — a password set under
    /// Argon2id remains verifiable even if the schema is later changed to
    /// Sha256. Transparent rehash runs when the stored algorithm is a legacy
    /// format and the policy targets Argon2id (upgrade path); other
    /// transitions require an explicit reset.
    ///
    /// Returns `Ok(true)` on success, `Err(AccountLocked)` if locked,
    /// `Err(VerificationFailed)` on wrong credential.
    pub async fn verify(
        &self,
        schema: &str,
        entity_id: &str,
        field_name: &str,
        plaintext: &str,
        policy: &CredentialPolicy,
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

        // Check lockout (only when enabled on the policy — disabling unlocks
        // immediately, which matters when a schema is switched to `lockout:
        // None` after a prior lock).
        if policy.lockout.is_some()
            && let Some(locked_until) = record.locked_until
        {
            let current = now();
            if current < locked_until {
                return Err(SigilError::AccountLocked {
                    retry_after_secs: locked_until - current,
                });
            }
            record.locked_until = None;
            record.failed_attempts = 0;
        }

        // Verify credential against stored hash (dispatched on stored algorithm).
        // Argon2/legacy hashes hold the semaphore; Sha256 is cheap and skips it.
        let valid = if record.algorithm == PasswordAlgorithm::Sha256 {
            verify_sha256_hex(plaintext, &record.hash)?
        } else {
            let _permit = self
                .hash_semaphore
                .acquire()
                .await
                .map_err(|_| SigilError::Internal("hash semaphore closed".into()))?;
            verify_password(plaintext, &record.hash)?
        };

        if valid {
            record.failed_attempts = 0;
            record.locked_until = None;

            // Transparent rehash: upgrade legacy formats to Argon2id when
            // the policy targets Argon2id. Never auto-migrate across families
            // (no Argon2id → Sha256 downgrade; no Sha256 → Argon2id when the
            // stored record is already a SHA-256 tag with no salt).
            if policy.algorithm == PasswordAlgorithm::Argon2id
                && record.algorithm != PasswordAlgorithm::Argon2id
                && record.algorithm != PasswordAlgorithm::Sha256
            {
                let new_hash = hash_argon2id(plaintext)?;
                record.hash = new_hash;
                record.algorithm = PasswordAlgorithm::Argon2id;
                tracing::info!(entity_id, field_name, "transparent rehash to argon2id");
            }
        } else if let Some(lockout) = &policy.lockout {
            record.failed_attempts += 1;
            if record.failed_attempts >= lockout.max_attempts {
                record.locked_until = Some(now() + lockout.duration_secs);
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
    ///
    /// The policy drives lockout enforcement on the verify step and algorithm
    /// choice for the new hash.
    pub async fn change_credential(
        &self,
        schema: &str,
        entity_id: &str,
        field_name: &str,
        old_plaintext: &str,
        new_plaintext: &str,
        policy: &CredentialPolicy,
    ) -> Result<(), SigilError> {
        validate_credential_length(policy, new_plaintext)?;

        // Verify old credential (this also handles lockout)
        self.verify(schema, entity_id, field_name, old_plaintext, policy)
            .await?;

        let (new_hash, new_algorithm) = if matches!(policy.algorithm, PasswordAlgorithm::Sha256) {
            (hash_sha256_hex(new_plaintext), PasswordAlgorithm::Sha256)
        } else {
            let _permit = self
                .hash_semaphore
                .acquire()
                .await
                .map_err(|_| SigilError::Internal("hash semaphore closed".into()))?;
            (
                hash_for_new_credential(policy, new_plaintext)?,
                PasswordAlgorithm::Argon2id,
            )
        };

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
        record.algorithm = new_algorithm;
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
        policy: &CredentialPolicy,
    ) -> Result<(), SigilError> {
        validate_credential_length(policy, new_plaintext)?;

        let (new_hash, new_algorithm) = if matches!(policy.algorithm, PasswordAlgorithm::Sha256) {
            (hash_sha256_hex(new_plaintext), PasswordAlgorithm::Sha256)
        } else {
            let _permit = self
                .hash_semaphore
                .acquire()
                .await
                .map_err(|_| SigilError::Internal("hash semaphore closed".into()))?;
            (
                hash_for_new_credential(policy, new_plaintext)?,
                PasswordAlgorithm::Argon2id,
            )
        };

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
        record.algorithm = new_algorithm;
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
}

/// Validate plaintext against the policy's resolved length bounds.
fn validate_credential_length(
    policy: &CredentialPolicy,
    plaintext: &str,
) -> Result<(), SigilError> {
    let min = policy.resolved_min_length();
    let max = policy.resolved_max_length();
    if plaintext.len() < min {
        return Err(SigilError::InvalidField {
            field: "credential".into(),
            reason: format!("must be at least {min} characters"),
        });
    }
    if plaintext.len() > max {
        return Err(SigilError::InvalidField {
            field: "credential".into(),
            reason: format!("must be at most {max} characters"),
        });
    }
    Ok(())
}

/// Hash a plaintext for a new credential under an Argon2-family policy.
/// Sha256 is handled by `hash_sha256_hex` — this path is Argon2id-only; legacy
/// algorithms (bcrypt/scrypt) are import-only and never produced by Sigil.
fn hash_for_new_credential(
    policy: &CredentialPolicy,
    plaintext: &str,
) -> Result<String, SigilError> {
    match policy.algorithm {
        PasswordAlgorithm::Argon2id | PasswordAlgorithm::Argon2i | PasswordAlgorithm::Argon2d => {
            hash_argon2id(plaintext)
        }
        PasswordAlgorithm::Bcrypt | PasswordAlgorithm::Scrypt => Err(SigilError::InvalidField {
            field: "credential".into(),
            reason: format!(
                "algorithm {:?} is import-only; use Argon2id for new credentials",
                policy.algorithm
            ),
        }),
        PasswordAlgorithm::Sha256 => {
            // Caller dispatches Sha256 separately; reaching this arm is a bug.
            Err(SigilError::Internal(
                "Sha256 cannot be hashed via Argon2id path".into(),
            ))
        }
    }
}

/// Compute SHA-256 over plaintext and return the lowercase hex representation.
/// Used for high-entropy machine credentials (API keys). Safe because the
/// schema validator requires `min_length >= 32` on `Sha256` fields.
fn hash_sha256_hex(plaintext: &str) -> String {
    let digest = shroudb_crypto::sha256(plaintext.as_bytes());
    hex::encode(digest)
}

/// Constant-time comparison of SHA-256(plaintext) against a hex-encoded tag.
fn verify_sha256_hex(plaintext: &str, stored_hex: &str) -> Result<bool, SigilError> {
    let computed = shroudb_crypto::sha256(plaintext.as_bytes());
    let stored = hex::decode(stored_hex)
        .map_err(|e| SigilError::Crypto(format!("invalid sha256 hex: {e}")))?;
    if stored.len() != computed.len() {
        return Ok(false);
    }
    Ok(shroudb_crypto::constant_time_eq(&computed, &stored))
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

/// Detect the password algorithm from a hash string format (PHC prefix,
/// bcrypt modular crypt). Does not handle `Sha256`, which is indistinguishable
/// from arbitrary hex and must be declared by the policy.
fn detect_legacy_algorithm(hash: &str) -> Result<PasswordAlgorithm, SigilError> {
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

/// Validate an imported hash against the schema's declared algorithm and
/// return the algorithm actually detected.
///
/// For Sha256 the hash must be 64 lowercase hex characters (32 bytes).
/// For Argon2-family, bcrypt, and scrypt the hash format is auto-detected
/// via PHC/bcrypt prefix; any legacy format is acceptable on an Argon2id
/// policy (transparent rehash on next verify). Explicit Sha256 policy
/// rejects PHC hashes and vice versa — a schema switch cannot be smuggled
/// in via `PASSWORD IMPORT`.
fn validate_imported_hash(
    hash: &str,
    policy: &CredentialPolicy,
) -> Result<PasswordAlgorithm, SigilError> {
    if policy.algorithm == PasswordAlgorithm::Sha256 {
        if hash.len() != 64 {
            return Err(SigilError::ImportFailed(format!(
                "sha256 hash must be 64 hex characters, got {}",
                hash.len()
            )));
        }
        hex::decode(hash)
            .map_err(|e| SigilError::ImportFailed(format!("invalid sha256 hex: {e}")))?;
        return Ok(PasswordAlgorithm::Sha256);
    }

    let detected = detect_legacy_algorithm(hash)?;
    if hash.starts_with("$2b$") || hash.starts_with("$2a$") || hash.starts_with("$2y$") {
        if hash.len() != 60 {
            return Err(SigilError::ImportFailed(
                "invalid bcrypt hash length (expected 60)".into(),
            ));
        }
    } else {
        PasswordHash::new(hash)
            .map_err(|e| SigilError::ImportFailed(format!("invalid PHC hash: {e}")))?;
    }
    Ok(detected)
}

#[cfg(test)]
mod tests {
    use shroudb_sigil_core::field_kind::LockoutPolicy;
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
        let mgr = CredentialManager::new(store.clone(), EngineResourceConfig::default());
        (store, mgr)
    }

    /// Policy matching the pre-v2 engine defaults — Argon2id with lockout
    /// enabled (5 attempts / 15 minutes). Used to preserve the behavior
    /// asserted by existing tests.
    fn legacy_policy() -> CredentialPolicy {
        CredentialPolicy {
            algorithm: PasswordAlgorithm::Argon2id,
            min_length: Some(8),
            max_length: Some(128),
            lockout: Some(LockoutPolicy {
                max_attempts: 5,
                duration_secs: 900,
            }),
        }
    }

    /// Policy for API-key-style credentials: SHA-256, 32-char floor, no lockout.
    fn api_key_policy() -> CredentialPolicy {
        CredentialPolicy {
            algorithm: PasswordAlgorithm::Sha256,
            min_length: Some(32),
            max_length: Some(128),
            lockout: None,
        }
    }

    /// Argon2id policy with lockout disabled. Used to assert the path that
    /// previously took `enforce_lockout=false`.
    fn no_lockout_policy() -> CredentialPolicy {
        CredentialPolicy {
            algorithm: PasswordAlgorithm::Argon2id,
            min_length: Some(8),
            max_length: Some(128),
            lockout: None,
        }
    }

    #[tokio::test]
    async fn set_and_verify_credential() {
        let (_store, mgr) = setup().await;
        let p = legacy_policy();
        mgr.set_credential("myapp", "user1", "password", "correcthorse", &p)
            .await
            .unwrap();
        let valid = mgr
            .verify("myapp", "user1", "password", "correcthorse", &p)
            .await
            .unwrap();
        assert!(valid);
    }

    #[tokio::test]
    async fn wrong_credential_fails() {
        let (_store, mgr) = setup().await;
        let p = legacy_policy();
        mgr.set_credential("myapp", "user1", "password", "correcthorse", &p)
            .await
            .unwrap();
        let err = mgr
            .verify("myapp", "user1", "password", "wrongpassword", &p)
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn duplicate_set_rejected() {
        let (_store, mgr) = setup().await;
        let p = legacy_policy();
        mgr.set_credential("myapp", "user1", "password", "password1", &p)
            .await
            .unwrap();
        let err = mgr
            .set_credential("myapp", "user1", "password", "password2", &p)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[tokio::test]
    async fn lockout_after_failed_attempts() {
        let (_store, mgr) = setup().await;
        let p = legacy_policy();
        mgr.set_credential("myapp", "user1", "password", "correcthorse", &p)
            .await
            .unwrap();

        // Exhaust attempts (legacy default: 5)
        for _ in 0..5 {
            let _ = mgr.verify("myapp", "user1", "password", "wrong", &p).await;
        }

        // Next attempt should be locked
        let err = mgr
            .verify("myapp", "user1", "password", "correcthorse", &p)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("locked"));
    }

    #[tokio::test]
    async fn no_lockout_when_policy_lockout_is_none() {
        let (_store, mgr) = setup().await;
        let p = no_lockout_policy();
        mgr.set_credential("myapp", "key_42", "key_secret", "correcthorse", &p)
            .await
            .unwrap();

        // Far exceed the default attempt threshold — must never lock.
        for _ in 0..20 {
            let err = mgr
                .verify("myapp", "key_42", "key_secret", "wrong", &p)
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains("verification failed"),
                "expected verification failure, got: {err}"
            );
        }

        // Correct secret still verifies — no lock ever tripped.
        assert!(
            mgr.verify("myapp", "key_42", "key_secret", "correcthorse", &p)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn lockout_none_unlocks_existing_lock() {
        // A record locked under a policy with lockout enabled should be
        // reachable once the schema is switched to `lockout: None`.
        let (_store, mgr) = setup().await;
        let locked = legacy_policy();
        mgr.set_credential("myapp", "user1", "password", "correcthorse", &locked)
            .await
            .unwrap();
        for _ in 0..5 {
            let _ = mgr
                .verify("myapp", "user1", "password", "wrong", &locked)
                .await;
        }
        assert!(
            mgr.verify("myapp", "user1", "password", "correcthorse", &locked)
                .await
                .is_err()
        );

        // Switch policy — the prior lockout state is ignored.
        let unlocked = no_lockout_policy();
        assert!(
            mgr.verify("myapp", "user1", "password", "correcthorse", &unlocked)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn change_credential() {
        let (_store, mgr) = setup().await;
        let p = legacy_policy();
        mgr.set_credential("myapp", "user1", "password", "oldpassword", &p)
            .await
            .unwrap();
        mgr.change_credential(
            "myapp",
            "user1",
            "password",
            "oldpassword",
            "newpassword",
            &p,
        )
        .await
        .unwrap();

        // Old credential fails
        assert!(
            mgr.verify("myapp", "user1", "password", "oldpassword", &p)
                .await
                .is_err()
        );
        // New credential works
        assert!(
            mgr.verify("myapp", "user1", "password", "newpassword", &p)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn reset_credential_clears_lockout() {
        let (_store, mgr) = setup().await;
        let p = legacy_policy();
        mgr.set_credential("myapp", "user1", "password", "original", &p)
            .await
            .unwrap();

        // Lock the account
        for _ in 0..5 {
            let _ = mgr.verify("myapp", "user1", "password", "wrong", &p).await;
        }
        assert!(
            mgr.verify("myapp", "user1", "password", "original", &p)
                .await
                .is_err()
        );

        // Reset
        mgr.reset_credential("myapp", "user1", "password", "newpassword", &p)
            .await
            .unwrap();

        // Should work now (lockout cleared)
        assert!(
            mgr.verify("myapp", "user1", "password", "newpassword", &p)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn import_argon2id_hash() {
        let (_store, mgr) = setup().await;
        let p = legacy_policy();

        // Generate a real argon2id hash
        let hash = hash_argon2id("imported_pw").unwrap();
        let algo = mgr
            .import_credential("myapp", "user1", "password", &hash, &p)
            .await
            .unwrap();
        assert_eq!(algo, PasswordAlgorithm::Argon2id);

        // Verify works
        assert!(
            mgr.verify("myapp", "user1", "password", "imported_pw", &p)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn credential_too_short_rejected() {
        let (_store, mgr) = setup().await;
        let p = legacy_policy();
        let err = mgr
            .set_credential("myapp", "user1", "password", "short", &p)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("at least"));
    }

    #[tokio::test]
    async fn verify_nonexistent_entity() {
        let (_store, mgr) = setup().await;
        let p = legacy_policy();
        let err = mgr
            .verify("myapp", "nope", "password", "password", &p)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[tokio::test]
    async fn multi_credential_fields() {
        let (_store, mgr) = setup().await;
        let p = legacy_policy();
        mgr.set_credential("myapp", "user1", "password", "correcthorse", &p)
            .await
            .unwrap();
        mgr.set_credential("myapp", "user1", "recovery_key", "my-recovery-key-123", &p)
            .await
            .unwrap();

        // Each verifies independently
        assert!(
            mgr.verify("myapp", "user1", "password", "correcthorse", &p)
                .await
                .is_ok()
        );
        assert!(
            mgr.verify("myapp", "user1", "recovery_key", "my-recovery-key-123", &p,)
                .await
                .is_ok()
        );

        // Cross-verify fails
        assert!(
            mgr.verify("myapp", "user1", "password", "my-recovery-key-123", &p)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn detect_legacy_algorithm_from_hash() {
        assert_eq!(
            detect_legacy_algorithm("$argon2id$v=19$m=65536,t=3,p=4$salt$hash").unwrap(),
            PasswordAlgorithm::Argon2id
        );
        assert_eq!(
            detect_legacy_algorithm("$2b$12$saltsaltsaltsaltsaltsOhash").unwrap(),
            PasswordAlgorithm::Bcrypt
        );
        assert_eq!(
            detect_legacy_algorithm("$scrypt$ln=15,r=8,p=1$salt$hash").unwrap(),
            PasswordAlgorithm::Scrypt
        );
        assert!(detect_legacy_algorithm("notahash").is_err());
    }

    // --- Phase 3: Sha256 + per-field policy ---

    #[tokio::test]
    async fn sha256_set_and_verify() {
        let (_store, mgr) = setup().await;
        let p = api_key_policy();
        let secret = "a".repeat(32); // meets SHA256_MIN_LENGTH
        mgr.set_credential("myapp", "svc1", "key_secret", &secret, &p)
            .await
            .unwrap();
        assert!(
            mgr.verify("myapp", "svc1", "key_secret", &secret, &p)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn sha256_wrong_value_fails() {
        let (_store, mgr) = setup().await;
        let p = api_key_policy();
        let secret = "a".repeat(32);
        let wrong = "b".repeat(32);
        mgr.set_credential("myapp", "svc1", "key_secret", &secret, &p)
            .await
            .unwrap();
        assert!(
            mgr.verify("myapp", "svc1", "key_secret", &wrong, &p)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn sha256_stores_raw_hex_hash() {
        let (_store, mgr) = setup().await;
        let p = api_key_policy();
        let secret = "a".repeat(32);
        mgr.set_credential("myapp", "svc1", "key_secret", &secret, &p)
            .await
            .unwrap();

        // Reach into the store and confirm the stored hash is 64 hex chars
        // (raw SHA-256 output), not a PHC-format Argon2id string.
        let entry = _store
            .get(
                "sigil.myapp.credentials",
                credential_store_key("svc1", "key_secret").as_bytes(),
                None,
            )
            .await
            .unwrap();
        let record: CredentialRecord = serde_json::from_slice(&entry.value).unwrap();
        assert_eq!(record.algorithm, PasswordAlgorithm::Sha256);
        assert_eq!(record.hash.len(), 64);
        assert!(record.hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!record.hash.starts_with('$'));
    }

    #[tokio::test]
    async fn sha256_import_raw_hex() {
        let (_store, mgr) = setup().await;
        let p = api_key_policy();
        // Pre-compute a SHA-256 hash of a known secret
        let secret = "a".repeat(32);
        let hash = hex::encode(shroudb_crypto::sha256(secret.as_bytes()));
        let algo = mgr
            .import_credential("myapp", "svc1", "key_secret", &hash, &p)
            .await
            .unwrap();
        assert_eq!(algo, PasswordAlgorithm::Sha256);

        // Verify works
        assert!(
            mgr.verify("myapp", "svc1", "key_secret", &secret, &p)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn sha256_import_rejects_phc_hash() {
        let (_store, mgr) = setup().await;
        let p = api_key_policy();
        // An Argon2id PHC hash is not valid for an Sha256-declared field.
        let argon2 = hash_argon2id("whatever").unwrap();
        let err = mgr
            .import_credential("myapp", "svc1", "key_secret", &argon2, &p)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("sha256"));
    }

    #[tokio::test]
    async fn argon2_import_rejects_sha256_hex() {
        let (_store, mgr) = setup().await;
        let p = legacy_policy();
        let hex_digest = hex::encode(shroudb_crypto::sha256(b"pw"));
        let err = mgr
            .import_credential("myapp", "user1", "password", &hex_digest, &p)
            .await
            .unwrap_err();
        // Hex digest has no `$` prefix, so legacy detection rejects it.
        assert!(err.to_string().contains("unrecognized"));
    }

    #[tokio::test]
    async fn sha256_never_locks_out_regardless_of_failures() {
        // API-key policy has `lockout: None`. Even 50 failures must not lock.
        let (_store, mgr) = setup().await;
        let p = api_key_policy();
        let secret = "a".repeat(32);
        mgr.set_credential("myapp", "svc1", "key_secret", &secret, &p)
            .await
            .unwrap();
        let wrong = "b".repeat(32);
        for _ in 0..50 {
            let _ = mgr.verify("myapp", "svc1", "key_secret", &wrong, &p).await;
        }
        // Still verifiable.
        assert!(
            mgr.verify("myapp", "svc1", "key_secret", &secret, &p)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn per_field_lockout_threshold_is_honored() {
        let (_store, mgr) = setup().await;
        // Tight threshold: lock after 2 failures.
        let tight = CredentialPolicy {
            algorithm: PasswordAlgorithm::Argon2id,
            min_length: Some(8),
            max_length: Some(128),
            lockout: Some(LockoutPolicy {
                max_attempts: 2,
                duration_secs: 600,
            }),
        };
        mgr.set_credential("myapp", "user1", "password", "correcthorse", &tight)
            .await
            .unwrap();

        let _ = mgr
            .verify("myapp", "user1", "password", "wrong", &tight)
            .await;
        let _ = mgr
            .verify("myapp", "user1", "password", "wrong", &tight)
            .await;
        // 3rd attempt: locked.
        let err = mgr
            .verify("myapp", "user1", "password", "correcthorse", &tight)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("locked"));
    }

    #[tokio::test]
    async fn per_field_length_bounds_are_independent() {
        // Different fields can enforce different length floors.
        let (_store, mgr) = setup().await;
        let short_ok = CredentialPolicy {
            algorithm: PasswordAlgorithm::Argon2id,
            min_length: Some(4),
            max_length: Some(128),
            lockout: None,
        };
        let long_required = CredentialPolicy {
            algorithm: PasswordAlgorithm::Argon2id,
            min_length: Some(16),
            max_length: Some(128),
            lockout: None,
        };

        // Same value (6 chars) accepted on short policy, rejected on long.
        mgr.set_credential("myapp", "u1", "pin", "abcdef", &short_ok)
            .await
            .unwrap();
        let err = mgr
            .set_credential("myapp", "u1", "password", "abcdef", &long_required)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("at least 16"));
    }

    #[tokio::test]
    async fn mixed_policy_credentials_coexist() {
        // One manager serves both Argon2id and Sha256 credentials without
        // cross-contamination.
        let (_store, mgr) = setup().await;
        let pw_policy = legacy_policy();
        let key_policy = api_key_policy();

        mgr.set_credential("myapp", "user1", "password", "humanpass!", &pw_policy)
            .await
            .unwrap();
        let api_secret = "a".repeat(32);
        mgr.set_credential("myapp", "svc1", "key_secret", &api_secret, &key_policy)
            .await
            .unwrap();

        // Argon2id verify under pw_policy works.
        assert!(
            mgr.verify("myapp", "user1", "password", "humanpass!", &pw_policy)
                .await
                .unwrap()
        );
        // Sha256 verify under key_policy works.
        assert!(
            mgr.verify("myapp", "svc1", "key_secret", &api_secret, &key_policy)
                .await
                .unwrap()
        );
    }
}
