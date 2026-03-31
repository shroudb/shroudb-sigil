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
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            algorithm: PasswordAlgorithm::default(),
            max_failed_attempts: 5,
            lockout_duration_secs: 900, // 15 minutes
            min_length: 8,
            max_length: 128,
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
