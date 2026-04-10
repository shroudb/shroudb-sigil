use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

fn default_version() -> u32 {
    1
}

/// A stored envelope record.
///
/// Contains non-sensitive field values and metadata. This is the
/// "commit point" written to `sigil.{schema}.envelopes` after all
/// field-level operations (hashing, encryption, secret storage) succeed.
#[derive(Debug, Serialize, Deserialize)]
pub struct EnvelopeRecord {
    pub entity_id: String,
    /// Schema version used when this envelope was created or last updated.
    #[serde(default = "default_version")]
    pub schema_version: u32,
    /// Non-sensitive field values (index, inert fields).
    pub fields: HashMap<String, serde_json::Value>,
    pub created_at: u64,
    pub updated_at: u64,
    /// Fields encrypted client-side (blind mode). These cannot be decrypted
    /// by the server — they are always redacted on read.
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub blind_fields: HashSet<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_record_json_roundtrip() {
        let mut fields = HashMap::new();
        fields.insert(
            "org_id".to_string(),
            serde_json::Value::String("acme".to_string()),
        );
        fields.insert("active".to_string(), serde_json::Value::Bool(true));
        fields.insert("login_count".to_string(), serde_json::json!(42));

        let record = EnvelopeRecord {
            entity_id: "user:bob".to_string(),
            schema_version: 1,
            fields,
            created_at: 1690000000,
            updated_at: 1695000000,
            blind_fields: HashSet::new(),
        };

        let json = serde_json::to_string(&record).unwrap();
        let parsed: EnvelopeRecord = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.entity_id, "user:bob");
        assert_eq!(parsed.created_at, 1690000000);
        assert_eq!(parsed.updated_at, 1695000000);
        assert_eq!(parsed.fields.len(), 3);
        assert_eq!(
            parsed.fields.get("org_id").unwrap(),
            &serde_json::Value::String("acme".to_string())
        );
        assert_eq!(
            parsed.fields.get("active").unwrap(),
            &serde_json::Value::Bool(true)
        );
        assert_eq!(
            parsed.fields.get("login_count").unwrap(),
            &serde_json::json!(42)
        );
    }

    #[test]
    fn envelope_record_empty_fields_roundtrip() {
        let record = EnvelopeRecord {
            entity_id: "device:sensor-1".to_string(),
            schema_version: 1,
            fields: HashMap::new(),
            created_at: 1700000000,
            updated_at: 1700000000,
            blind_fields: HashSet::new(),
        };

        let json = serde_json::to_string(&record).unwrap();
        let parsed: EnvelopeRecord = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.entity_id, "device:sensor-1");
        assert!(parsed.fields.is_empty());
    }

    #[test]
    fn schema_version_defaults_on_deserialize() {
        // Simulate a record stored before schema evolution (no schema_version field)
        let json = r#"{"entity_id":"user:old","fields":{},"created_at":1690000000,"updated_at":1690000000}"#;
        let parsed: EnvelopeRecord = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.schema_version, 1);
    }
}
