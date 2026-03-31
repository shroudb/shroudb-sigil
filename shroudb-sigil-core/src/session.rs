use serde::{Deserialize, Serialize};

/// A pair of access + refresh tokens returned on login/refresh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

/// State of a refresh token in its family chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenState {
    Active,
    Rotated,
    Revoked,
}

/// Stored refresh token record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenRecord {
    pub token_id: String,
    pub family_id: String,
    pub entity_id: String,
    pub generation: u32,
    pub state: TokenState,
    pub created_at: u64,
    pub expires_at: u64,
}
