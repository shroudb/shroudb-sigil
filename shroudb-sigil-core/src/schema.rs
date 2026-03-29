use serde::{Deserialize, Serialize};

/// A registered credential envelope schema.
///
/// Defines the shape of a credential record and the cryptographic treatment
/// applied to each field based on its annotations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schema {
    /// Schema name (used as namespace prefix: `sigil.{name}.*`).
    pub name: String,
    /// Field definitions with type and annotation metadata.
    pub fields: Vec<FieldDef>,
}

/// A single field in a credential schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDef {
    /// Field name (must be a valid identifier: alphanumeric + underscores).
    pub name: String,
    /// Data type of the field.
    pub field_type: FieldType,
    /// Cryptographic treatment annotations.
    #[serde(default)]
    pub annotations: FieldAnnotations,
}

/// Supported field data types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    String,
    Integer,
    Boolean,
    Bytes,
}

/// Annotations that determine how a field's value is processed.
///
/// These drive the field routing: each annotation maps to a specific
/// cryptographic treatment and potentially a specific engine.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FieldAnnotations {
    /// Hash with Argon2id. Supports verify, change, lockout.
    /// At most one credential field per schema.
    #[serde(default)]
    pub credential: bool,

    /// Encrypt at rest via Cipher. Requires Cipher capability.
    #[serde(default)]
    pub pii: bool,

    /// Create a blind index for encrypted search via Veil.
    /// Requires `pii: true` and Cipher + Veil capabilities.
    #[serde(default)]
    pub searchable: bool,

    /// Store as a versioned secret via Keep. Requires Keep capability.
    #[serde(default)]
    pub secret: bool,

    /// Create a plaintext index for direct lookups.
    #[serde(default)]
    pub index: bool,
}
