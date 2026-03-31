/// Errors produced by the Sigil engine.
#[derive(Debug, thiserror::Error)]
pub enum SigilError {
    #[error("schema validation failed: {0}")]
    SchemaValidation(String),

    #[error("schema not found: {0}")]
    SchemaNotFound(String),

    #[error("schema already exists: {0}")]
    SchemaExists(String),

    #[error("entity not found")]
    EntityNotFound,

    #[error("entity already exists")]
    EntityExists,

    #[error("missing required field: {0}")]
    MissingField(String),

    #[error("invalid field value for {field}: {reason}")]
    InvalidField { field: String, reason: String },

    #[error("credential verification failed")]
    VerificationFailed,

    #[error("account locked until {retry_after_secs}s from now")]
    AccountLocked { retry_after_secs: u64 },

    #[error("invalid token")]
    InvalidToken,

    #[error("token expired")]
    TokenExpired,

    #[error("token reuse detected — family revoked")]
    TokenReuse,

    #[error("capability not available: {0}")]
    CapabilityMissing(String),

    #[error("password import failed: {0}")]
    ImportFailed(String),

    #[error("store error: {0}")]
    Store(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("internal error: {0}")]
    Internal(String),
}
