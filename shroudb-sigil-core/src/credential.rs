use serde::{Deserialize, Serialize};

/// Credential hashing algorithm.
///
/// Sigil defaults to Argon2id for human-auth credentials (passwords). Bcrypt,
/// Scrypt, and the Argon2 variants are supported for import (`PASSWORD IMPORT`)
/// — imported hashes are transparently rehashed to Argon2id on the next
/// successful verify.
///
/// `Sha256` is an unkeyed SHA-256 with constant-time comparison, intended for
/// high-entropy machine credentials (256-bit random API keys from
/// `shroudb_crypto::generate_api_key`). It is deliberately not HMAC: for
/// 2^256 input spaces the entropy alone defeats offline brute-force, and an
/// HMAC key would require Sigil to either break the `KeepOps` one-way
/// doctrine or hold key material from engine-startup config — both violate
/// the schema-driven thesis. Use of `Sha256` is gated by a schema validation
/// rule (`min_length >= 32`) that refuses low-entropy inputs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PasswordAlgorithm {
    #[default]
    Argon2id,
    Argon2i,
    Argon2d,
    Bcrypt,
    Scrypt,
    Sha256,
}

/// Process-scoped resource limits for the credential engine.
///
/// Only process-scoped knobs live here — anything that is a credential
/// *property* (algorithm, length bounds, lockout) is per-field on
/// `CredentialPolicy` inside `FieldKind`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineResourceConfig {
    /// Maximum concurrent Argon2id hash/verify operations (0 = unlimited).
    /// Each Argon2id hash uses ~64 MiB memory (m_cost=65536) × p_cost=4
    /// parallelism lanes. Bounding concurrency prevents OOM under load.
    pub max_concurrent_hashes: u32,
}

impl Default for EngineResourceConfig {
    fn default() -> Self {
        Self {
            max_concurrent_hashes: 4,
        }
    }
}

/// Stored credential record (hash + lockout state).
///
/// The hash is stored in one of:
/// - PHC string format (argon2, scrypt): `$argon2id$...`, `$scrypt$...`
/// - Bcrypt modular crypt format: `$2b$...`
/// - Raw 64-char lowercase hex (Sha256 algorithm)
///
/// On verify, a legacy-format hash (bcrypt/scrypt/argon2i/argon2d) is
/// transparently rehashed to Argon2id when the per-field policy targets
/// Argon2id. Sha256 records are never auto-rehashed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRecord {
    pub entity_id: String,
    /// Hash in PHC string, bcrypt, or raw hex form.
    pub hash: String,
    /// Algorithm used to produce `hash` (drives verify dispatch and rehash).
    pub algorithm: PasswordAlgorithm,
    pub failed_attempts: u32,
    pub locked_until: Option<u64>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_algorithm_default_is_argon2id() {
        assert_eq!(PasswordAlgorithm::default(), PasswordAlgorithm::Argon2id);
    }

    #[test]
    fn password_algorithm_sha256_serde() {
        let algo = PasswordAlgorithm::Sha256;
        let json = serde_json::to_string(&algo).unwrap();
        assert_eq!(json, "\"sha256\"");
        let parsed: PasswordAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, PasswordAlgorithm::Sha256);
    }

    #[test]
    fn engine_resource_config_default() {
        let cfg = EngineResourceConfig::default();
        assert_eq!(cfg.max_concurrent_hashes, 4);
    }

    #[test]
    fn engine_resource_config_json_roundtrip() {
        let cfg = EngineResourceConfig {
            max_concurrent_hashes: 16,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: EngineResourceConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.max_concurrent_hashes, 16);
    }

    #[test]
    fn credential_record_json_roundtrip() {
        let record = CredentialRecord {
            entity_id: "user:alice".to_string(),
            hash: "$argon2id$v=19$m=65536,t=3,p=4$abc$xyz".to_string(),
            algorithm: PasswordAlgorithm::Argon2id,
            failed_attempts: 2,
            locked_until: Some(1700000000),
            created_at: 1690000000,
            updated_at: 1695000000,
        };
        let json = serde_json::to_string(&record).unwrap();
        let parsed: CredentialRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.entity_id, "user:alice");
        assert_eq!(parsed.algorithm, PasswordAlgorithm::Argon2id);
        assert_eq!(parsed.failed_attempts, 2);
        assert_eq!(parsed.locked_until, Some(1700000000));
    }
}
