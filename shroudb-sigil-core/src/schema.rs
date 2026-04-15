use serde::{Deserialize, Serialize};

use crate::error::SigilError;

fn default_version() -> u32 {
    1
}

fn default_true() -> bool {
    true
}

/// A registered credential envelope schema.
///
/// Defines the shape of a credential record and the cryptographic treatment
/// applied to each field based on its annotations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schema {
    /// Schema name (used as namespace prefix: `sigil.{name}.*`).
    #[serde(default)]
    pub name: String,
    /// Schema version. Starts at 1, increments on each ALTER.
    #[serde(default = "default_version")]
    pub version: u32,
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
        let mut seen_names = std::collections::HashSet::new();

        for field in &self.fields {
            field.validate()?;

            if !seen_names.insert(&field.name) {
                return Err(SigilError::SchemaValidation(format!(
                    "duplicate field name: {}",
                    field.name
                )));
            }
        }

        Ok(())
    }

    /// Returns the names of all credential-annotated fields.
    pub fn credential_fields(&self) -> Vec<&str> {
        self.fields
            .iter()
            .filter(|f| f.annotations.credential)
            .map(|f| f.name.as_str())
            .collect()
    }

    /// Returns the names of all claim-annotated fields.
    /// These fields have their envelope values auto-included in JWT claims.
    pub fn claim_fields(&self) -> Vec<&str> {
        self.fields
            .iter()
            .filter(|f| f.annotations.claim)
            .map(|f| f.name.as_str())
            .collect()
    }

    /// Returns whether lockout enforcement is enabled for the named field.
    /// Returns `true` (the safe default) if the field is not found or is not a
    /// credential field — non-credential fields cannot be verified, so the
    /// answer is irrelevant.
    pub fn field_lockout(&self, field_name: &str) -> bool {
        self.fields
            .iter()
            .find(|f| f.name == field_name)
            .map(|f| f.annotations.lockout)
            .unwrap_or(true)
    }

    /// Returns the single credential field name, or an error if zero or
    /// multiple credential fields exist. Used by the `USER` command sugar
    /// where the credential field is inferred from the schema.
    pub fn credential_field_name(&self) -> Result<&str, SigilError> {
        let creds = self.credential_fields();
        match creds.len() {
            0 => Err(SigilError::SchemaValidation(
                "schema has no credential field".into(),
            )),
            1 => Ok(creds[0]),
            _ => Err(SigilError::SchemaValidation(
                "schema has multiple credential fields; use ENVELOPE VERIFY with explicit field name".into(),
            )),
        }
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
    /// Whether this field is required on envelope creation. Fields added via
    /// ALTER are optional (required=false). Defaults to true for backward
    /// compatibility with schemas registered before schema evolution.
    #[serde(default = "default_true")]
    pub required: bool,
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

        if self.claim && self.credential {
            return Err(SigilError::SchemaValidation(format!(
                "field '{field_name}': claim and credential are mutually exclusive"
            )));
        }

        if self.claim && self.pii {
            return Err(SigilError::SchemaValidation(format!(
                "field '{field_name}': claim and pii are mutually exclusive (encrypted values cannot be included in JWT claims)"
            )));
        }

        if self.claim && self.secret {
            return Err(SigilError::SchemaValidation(format!(
                "field '{field_name}': claim and secret are mutually exclusive"
            )));
        }

        if !self.lockout && !self.credential {
            return Err(SigilError::SchemaValidation(format!(
                "field '{field_name}': lockout=false is only valid on credential fields"
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    /// Include this field's value in JWT claims on session creation and refresh.
    /// Only valid on non-credential, non-pii, non-secret fields (index or inert).
    /// Enriched claim values always come from the envelope, overriding any
    /// caller-provided extra_claims for the same key.
    #[serde(default)]
    pub claim: bool,

    /// Enforce lockout on repeated verify failures for this credential field.
    ///
    /// Default `true`. Only meaningful when `credential = true`. Set to `false`
    /// for machine-auth schemas (API keys, service tokens) where lockout would
    /// let an attacker who guesses a valid `entity_id` deny service to a tenant
    /// by hammering bad secrets. Leave `true` for human-auth schemas (passwords)
    /// where brute-force mitigation is the goal.
    #[serde(default = "default_true")]
    pub lockout: bool,
}

impl Default for FieldAnnotations {
    fn default() -> Self {
        Self {
            credential: false,
            pii: false,
            searchable: false,
            secret: false,
            index: false,
            claim: false,
            lockout: true,
        }
    }
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
            required: true,
        }
    }

    fn schema(name: &str, fields: Vec<FieldDef>) -> Schema {
        Schema {
            name: name.to_string(),
            version: 1,
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
    fn multiple_credential_fields_allowed() {
        let s = schema(
            "myapp",
            vec![
                field("password", |a| a.credential = true),
                field("pin", |a| a.credential = true),
            ],
        );
        assert!(s.validate().is_ok());
        assert_eq!(s.credential_fields().len(), 2);
        assert!(s.credential_field_name().is_err());
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
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.fields.len(), 2);
        assert!(parsed.fields[0].annotations.searchable);
        assert!(parsed.fields[0].required);
        assert!(parsed.fields[1].annotations.credential);
    }

    #[test]
    fn schema_version_defaults_on_deserialize() {
        // Simulate a schema stored before schema evolution (no version field)
        let json = r#"{"name":"legacy","fields":[{"name":"f","field_type":"string"}]}"#;
        let parsed: Schema = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.version, 1);
        assert!(parsed.fields[0].required);
    }

    #[test]
    fn optional_field_valid() {
        let mut s = schema("myapp", vec![field("email", |a| a.pii = true)]);
        s.fields.push(FieldDef {
            name: "phone".to_string(),
            field_type: FieldType::String,
            annotations: FieldAnnotations {
                pii: true,
                ..Default::default()
            },
            required: false,
        });
        assert!(s.validate().is_ok());
    }

    #[test]
    fn claim_on_index_field_valid() {
        let s = schema(
            "myapp",
            vec![
                field("password", |a| a.credential = true),
                field("role", |a| {
                    a.index = true;
                    a.claim = true;
                }),
            ],
        );
        assert!(s.validate().is_ok());
        assert_eq!(s.claim_fields(), vec!["role"]);
    }

    #[test]
    fn claim_on_inert_field_valid() {
        let s = schema(
            "myapp",
            vec![
                field("password", |a| a.credential = true),
                field("display_name", |a| a.claim = true),
            ],
        );
        assert!(s.validate().is_ok());
        assert_eq!(s.claim_fields(), vec!["display_name"]);
    }

    #[test]
    fn claim_and_credential_mutually_exclusive() {
        let s = schema(
            "myapp",
            vec![field("password", |a| {
                a.credential = true;
                a.claim = true;
            })],
        );
        let err = s.validate().unwrap_err();
        assert!(err.to_string().contains("claim and credential"));
    }

    #[test]
    fn claim_and_pii_mutually_exclusive() {
        let s = schema(
            "myapp",
            vec![field("email", |a| {
                a.pii = true;
                a.claim = true;
            })],
        );
        let err = s.validate().unwrap_err();
        assert!(err.to_string().contains("claim and pii"));
    }

    #[test]
    fn claim_and_secret_mutually_exclusive() {
        let s = schema(
            "myapp",
            vec![field("api_key", |a| {
                a.secret = true;
                a.claim = true;
            })],
        );
        let err = s.validate().unwrap_err();
        assert!(err.to_string().contains("claim and secret"));
    }

    #[test]
    fn no_claim_fields_returns_empty() {
        let s = schema(
            "myapp",
            vec![
                field("password", |a| a.credential = true),
                field("org", |a| a.index = true),
            ],
        );
        assert!(s.claim_fields().is_empty());
    }

    #[test]
    fn claim_field_defaults_false_on_deserialize() {
        // Simulate a schema stored before claim annotation existed
        let json = r#"{"name":"legacy","fields":[{"name":"role","field_type":"string","annotations":{"index":true}}]}"#;
        let parsed: Schema = serde_json::from_str(json).unwrap();
        assert!(!parsed.fields[0].annotations.claim);
        assert!(parsed.claim_fields().is_empty());
    }

    #[test]
    fn lockout_defaults_true() {
        let a = FieldAnnotations::default();
        assert!(a.lockout);
    }

    #[test]
    fn lockout_off_on_credential_valid() {
        let s = schema(
            "api_keys",
            vec![field("key_secret", |a| {
                a.credential = true;
                a.lockout = false;
            })],
        );
        assert!(s.validate().is_ok());
    }

    #[test]
    fn lockout_off_on_non_credential_rejected() {
        let s = schema(
            "myapp",
            vec![
                field("password", |a| a.credential = true),
                field("role", |a| {
                    a.index = true;
                    a.lockout = false;
                }),
            ],
        );
        let err = s.validate().unwrap_err();
        assert!(err.to_string().contains("lockout=false"));
    }

    #[test]
    fn lockout_defaults_true_on_deserialize() {
        // Simulate a schema stored before the lockout annotation existed
        let json = r#"{"name":"legacy","fields":[{"name":"password","field_type":"string","annotations":{"credential":true}}]}"#;
        let parsed: Schema = serde_json::from_str(json).unwrap();
        assert!(parsed.fields[0].annotations.lockout);
    }
}
