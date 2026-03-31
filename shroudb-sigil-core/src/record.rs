use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A stored envelope record.
///
/// Contains non-sensitive field values and metadata. This is the
/// "commit point" written to `sigil.{schema}.envelopes` after all
/// field-level operations (hashing, encryption, secret storage) succeed.
#[derive(Debug, Serialize, Deserialize)]
pub struct EnvelopeRecord {
    pub entity_id: String,
    /// Non-sensitive field values (index, inert fields).
    pub fields: HashMap<String, serde_json::Value>,
    pub created_at: u64,
    pub updated_at: u64,
}
