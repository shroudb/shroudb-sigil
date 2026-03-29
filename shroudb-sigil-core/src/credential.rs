use serde::{Deserialize, Serialize};

/// Password hashing algorithm.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PasswordAlgorithm {
    #[default]
    Argon2id,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRecord {
    pub user_id: String,
    pub hash: String,
    pub failed_attempts: u32,
    pub locked_until: Option<u64>,
    pub created_at: u64,
    pub updated_at: u64,
}
