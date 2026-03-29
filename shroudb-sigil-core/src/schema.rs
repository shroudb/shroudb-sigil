use serde::{Deserialize, Serialize};

use crate::error::SigilError;

/// A registered credential envelope schema.
///
/// Defines the shape of a credential record and the cryptographic treatment
/// applied to each field based on its annotations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schema {
    /// Schema name (used as namespace prefix: `sigil.{name}.*`).
    #[serde(default)]
    pub name: String,
    /// Field definitions with type and annotation metadata.
    pub fields: Vec<FieldDef>,
}

impl Schema {
    /// Validate schema rules. Returns `Ok(())` if the schema is well-formed.
    pub fn validate(&self) -> Result<(), SigilError> {
        if self.name.is_empty() {
            return Err(SigilError::SchemaValidation(
                "schema name must not be empty".into(),
            ));
        }

        if !self
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(SigilError::SchemaValidation(
                "schema name must contain only alphanumeric characters, underscores, or hyphens"
                    .into(),
            ));
        }

        if self.fields.is_empty() {
            return Err(SigilError::SchemaValidation(
                "schema must have at least one field".into(),
            ));
        }

        // Validate individual fields
        let mut credential_count = 0;
        let mut seen_names = std::collections::HashSet::new();

        for field in &self.fields {
            field.validate()?;

            if !seen_names.insert(&field.name) {
                return Err(SigilError::SchemaValidation(format!(
                    "duplicate field name: {}",
                    field.name
                )));
            }

            if field.annotations.credential {
                credential_count += 1;
            }
        }

        if credential_count > 1 {
            return Err(SigilError::SchemaValidation(
                "at most one credential field per schema".into(),
            ));
        }

        Ok(())
    }
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

impl FieldDef {
    /// Validate field-level rules.
    pub fn validate(&self) -> Result<(), SigilError> {
        if self.name.is_empty() {
            return Err(SigilError::SchemaValidation(
                "field name must not be empty".into(),
            ));
        }

        if !self
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(SigilError::SchemaValidation(format!(
                "field name '{}' must contain only alphanumeric characters and underscores",
                self.name
            )));
        }

        self.annotations.validate(&self.name)
    }
}

impl FieldAnnotations {
    /// Validate annotation combinations.
    fn validate(&self, field_name: &str) -> Result<(), SigilError> {
        if self.credential && self.pii {
            return Err(SigilError::SchemaValidation(format!(
                "field '{field_name}': credential and pii are mutually exclusive (credentials are hashed, not encrypted)"
            )));
        }

        if self.credential && self.secret {
            return Err(SigilError::SchemaValidation(format!(
                "field '{field_name}': credential and secret are mutually exclusive"
            )));
        }

        if self.searchable && !self.pii {
            return Err(SigilError::SchemaValidation(format!(
                "field '{field_name}': searchable requires pii"
            )));
        }

        Ok(())
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn field(name: &str, f: impl FnOnce(&mut FieldAnnotations)) -> FieldDef {
        let mut annotations = FieldAnnotations::default();
        f(&mut annotations);
        FieldDef {
            name: name.to_string(),
            field_type: FieldType::String,
            annotations,
        }
    }

    fn schema(name: &str, fields: Vec<FieldDef>) -> Schema {
        Schema {
            name: name.to_string(),
            fields,
        }
    }

    #[test]
    fn valid_schema() {
        let s = schema(
            "myapp",
            vec![
                field("email", |a| a.pii = true),
                field("password", |a| a.credential = true),
                field("org_id", |a| a.index = true),
            ],
        );
        assert!(s.validate().is_ok());
    }

    #[test]
    fn empty_name_rejected() {
        let s = schema("", vec![field("f", |_| {})]);
        assert!(s.validate().is_err());
    }

    #[test]
    fn invalid_name_chars() {
        let s = schema("my app!", vec![field("f", |_| {})]);
        assert!(s.validate().is_err());
    }

    #[test]
    fn no_fields_rejected() {
        let s = schema("myapp", vec![]);
        assert!(s.validate().is_err());
    }

    #[test]
    fn duplicate_field_names_rejected() {
        let s = schema(
            "myapp",
            vec![field("email", |_| {}), field("email", |_| {})],
        );
        assert!(s.validate().is_err());
    }

    #[test]
    fn multiple_credential_fields_rejected() {
        let s = schema(
            "myapp",
            vec![
                field("password", |a| a.credential = true),
                field("pin", |a| a.credential = true),
            ],
        );
        let err = s.validate().unwrap_err();
        assert!(err.to_string().contains("at most one credential"));
    }

    #[test]
    fn credential_and_pii_mutually_exclusive() {
        let s = schema(
            "myapp",
            vec![field("password", |a| {
                a.credential = true;
                a.pii = true;
            })],
        );
        let err = s.validate().unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn credential_and_secret_mutually_exclusive() {
        let s = schema(
            "myapp",
            vec![field("password", |a| {
                a.credential = true;
                a.secret = true;
            })],
        );
        assert!(s.validate().is_err());
    }

    #[test]
    fn searchable_requires_pii() {
        let s = schema("myapp", vec![field("email", |a| a.searchable = true)]);
        let err = s.validate().unwrap_err();
        assert!(err.to_string().contains("searchable requires pii"));
    }

    #[test]
    fn searchable_with_pii_valid() {
        let s = schema(
            "myapp",
            vec![field("email", |a| {
                a.pii = true;
                a.searchable = true;
            })],
        );
        assert!(s.validate().is_ok());
    }

    #[test]
    fn schema_json_roundtrip() {
        let s = schema(
            "myapp",
            vec![
                field("email", |a| {
                    a.pii = true;
                    a.searchable = true;
                }),
                field("password", |a| a.credential = true),
            ],
        );
        let json = serde_json::to_string(&s).unwrap();
        let parsed: Schema = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "myapp");
        assert_eq!(parsed.fields.len(), 2);
        assert!(parsed.fields[0].annotations.searchable);
        assert!(parsed.fields[1].annotations.credential);
    }
}
