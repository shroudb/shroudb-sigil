use serde::{Deserialize, Serialize};

/// Password hashing algorithm.
/// Password hashing algorithm.
///
/// Sigil defaults to Argon2id for new passwords. Other algorithms are
/// supported for import (`PASSWORD IMPORT`) — imported hashes are
/// transparently rehashed to Argon2id on the next successful verify.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PasswordAlgorithm {
    #[default]
    Argon2id,
    Argon2i,
    Argon2d,
    Bcrypt,
    Scrypt,
}

/// Policy for credential (password) fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub algorithm: PasswordAlgorithm,
    pub max_failed_attempts: u32,
    pub lockout_duration_secs: u64,
    pub min_length: usize,
    pub max_length: usize,
    /// Maximum concurrent Argon2id hash/verify operations (0 = unlimited).
    /// Each Argon2id hash uses ~64 MiB memory (m_cost=65536) × p_cost=4
    /// parallelism lanes. Bounding concurrency prevents OOM under load.
    pub max_concurrent_hashes: u32,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            algorithm: PasswordAlgorithm::default(),
            max_failed_attempts: 5,
            lockout_duration_secs: 900, // 15 minutes
            min_length: 8,
            max_length: 128,
            max_concurrent_hashes: 4,
        }
    }
}

/// Stored credential record (password hash + lockout state).
///
/// The hash is stored in PHC string format (argon2, scrypt) or standard
/// bcrypt format (`$2b$...`). On verify, if the algorithm is not the
/// configured default (Argon2id), the hash is transparently upgraded
/// after successful verification — the user never knows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRecord {
    pub entity_id: String,
    /// Hash in PHC string format or bcrypt format.
    pub hash: String,
    /// Algorithm detected from the hash (for rehash decisions).
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
    fn default_password_policy_values() {
        let policy = PasswordPolicy::default();
        assert_eq!(policy.algorithm, PasswordAlgorithm::Argon2id);
        assert_eq!(policy.max_failed_attempts, 5);
        assert_eq!(policy.lockout_duration_secs, 900);
        assert_eq!(policy.min_length, 8);
        assert_eq!(policy.max_length, 128);
    }

    #[test]
    fn password_policy_json_roundtrip() {
        let policy = PasswordPolicy {
            algorithm: PasswordAlgorithm::Bcrypt,
            max_failed_attempts: 10,
            lockout_duration_secs: 1800,
            min_length: 12,
            max_length: 256,
            ..Default::default()
        };
        let json = serde_json::to_string(&policy).unwrap();
        let parsed: PasswordPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.algorithm, PasswordAlgorithm::Bcrypt);
        assert_eq!(parsed.max_failed_attempts, 10);
        assert_eq!(parsed.lockout_duration_secs, 1800);
        assert_eq!(parsed.min_length, 12);
        assert_eq!(parsed.max_length, 256);
    }

    #[test]
    fn password_algorithm_default_is_argon2id() {
        assert_eq!(PasswordAlgorithm::default(), PasswordAlgorithm::Argon2id);
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
