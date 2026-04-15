use serde::{Deserialize, Serialize};

use crate::error::SigilError;
use crate::field_kind::{CredentialPolicy, FieldKind};

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
            .filter(|f| f.kind.is_credential())
            .map(|f| f.name.as_str())
            .collect()
    }

    /// Returns the names of all claim-annotated fields.
    /// These fields have their envelope values auto-included in JWT claims.
    pub fn claim_fields(&self) -> Vec<&str> {
        self.fields
            .iter()
            .filter(|f| f.kind.claim().is_some())
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
            .and_then(|f| f.kind.credential_policy())
            .map(|p| p.lockout.is_some())
            .unwrap_or(true)
    }

    /// Returns the resolved credential policy for the named field, or `None`
    /// if the field does not exist or is not a credential. The engine uses
    /// this on every credential operation (verify, set, change) to apply
    /// per-field algorithm, length bounds, and lockout thresholds.
    pub fn credential_policy(&self, field_name: &str) -> Option<&CredentialPolicy> {
        self.fields
            .iter()
            .find(|f| f.name == field_name)
            .and_then(|f| f.kind.credential_policy())
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
///
/// v2.0 shape: `kind` carries the field's cryptographic treatment as a tagged
/// enum, making mutex rules structural. Deserialization rejects the legacy v1
/// `annotations` key with a pointer to the migration tool.
#[derive(Debug, Clone, Serialize)]
pub struct FieldDef {
    /// Field name (must be a valid identifier: alphanumeric + underscores).
    pub name: String,
    /// Data type of the field.
    pub field_type: FieldType,
    /// Per-field cryptographic treatment.
    pub kind: FieldKind,
    /// Whether this field is required on envelope creation. Fields added via
    /// ALTER are optional (required=false). Defaults to true for backward
    /// compatibility with schemas registered before schema evolution.
    pub required: bool,
}

impl<'de> Deserialize<'de> for FieldDef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Raw {
            name: String,
            field_type: FieldType,
            /// Present on v1 schemas. Rejected — run `SCHEMA MIGRATE` to upgrade.
            #[serde(default)]
            annotations: Option<serde_json::Value>,
            #[serde(default)]
            kind: Option<FieldKind>,
            #[serde(default = "default_true")]
            required: bool,
        }

        let raw = Raw::deserialize(deserializer)?;
        if raw.annotations.is_some() {
            return Err(serde::de::Error::custom(format!(
                "field '{}': legacy `annotations` key is not supported in v2.0 — \
                 run `shroudb-sigil-cli SCHEMA MIGRATE` against the store to upgrade \
                 persisted schemas (see CHANGELOG v2.0 migration notes)",
                raw.name
            )));
        }
        let kind = raw.kind.unwrap_or_default();

        Ok(FieldDef {
            name: raw.name,
            field_type: raw.field_type,
            kind,
            required: raw.required,
        })
    }
}

impl FieldDef {
    /// Construct a `FieldDef` directly from a `FieldKind`.
    pub fn with_kind(
        name: impl Into<String>,
        field_type: FieldType,
        kind: FieldKind,
        required: bool,
    ) -> Self {
        Self {
            name: name.into(),
            field_type,
            kind,
            required,
        }
    }

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

        self.kind.validate(&self.name)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::PasswordAlgorithm;
    use crate::field_kind::{ClaimPolicy, LockoutPolicy, PiiPolicy};

    fn legacy_credential() -> FieldKind {
        FieldKind::Credential(CredentialPolicy {
            algorithm: PasswordAlgorithm::Argon2id,
            min_length: None,
            max_length: None,
            lockout: Some(LockoutPolicy {
                max_attempts: 5,
                duration_secs: 900,
            }),
        })
    }

    fn field(name: &str, kind: FieldKind) -> FieldDef {
        FieldDef::with_kind(name, FieldType::String, kind, true)
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
                field("email", FieldKind::Pii(PiiPolicy { searchable: false })),
                field("password", legacy_credential()),
                field("org_id", FieldKind::Index { claim: None }),
            ],
        );
        assert!(s.validate().is_ok());
    }

    #[test]
    fn empty_name_rejected() {
        let s = schema("", vec![field("f", FieldKind::Inert { claim: None })]);
        assert!(s.validate().is_err());
    }

    #[test]
    fn invalid_name_chars() {
        let s = schema(
            "my app!",
            vec![field("f", FieldKind::Inert { claim: None })],
        );
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
            vec![
                field("email", FieldKind::Inert { claim: None }),
                field("email", FieldKind::Inert { claim: None }),
            ],
        );
        assert!(s.validate().is_err());
    }

    #[test]
    fn multiple_credential_fields_allowed() {
        let s = schema(
            "myapp",
            vec![
                field("password", legacy_credential()),
                field("pin", legacy_credential()),
            ],
        );
        assert!(s.validate().is_ok());
        assert_eq!(s.credential_fields().len(), 2);
        assert!(s.credential_field_name().is_err());
    }

    #[test]
    fn searchable_with_pii_valid() {
        let s = schema(
            "myapp",
            vec![field(
                "email",
                FieldKind::Pii(PiiPolicy { searchable: true }),
            )],
        );
        assert!(s.validate().is_ok());
    }

    #[test]
    fn schema_json_roundtrip() {
        let s = schema(
            "myapp",
            vec![
                field("email", FieldKind::Pii(PiiPolicy { searchable: true })),
                field("password", legacy_credential()),
            ],
        );
        let json = serde_json::to_string(&s).unwrap();
        let parsed: Schema = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "myapp");
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.fields.len(), 2);
        assert!(matches!(
            &parsed.fields[0].kind,
            FieldKind::Pii(PiiPolicy { searchable: true })
        ));
        assert!(parsed.fields[0].required);
        assert!(parsed.fields[1].kind.is_credential());
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
        let mut s = schema(
            "myapp",
            vec![field(
                "email",
                FieldKind::Pii(PiiPolicy { searchable: false }),
            )],
        );
        s.fields.push(FieldDef::with_kind(
            "phone",
            FieldType::String,
            FieldKind::Pii(PiiPolicy { searchable: false }),
            false,
        ));
        assert!(s.validate().is_ok());
    }

    #[test]
    fn claim_on_index_field_valid() {
        let s = schema(
            "myapp",
            vec![
                field("password", legacy_credential()),
                field(
                    "role",
                    FieldKind::Index {
                        claim: Some(ClaimPolicy::default()),
                    },
                ),
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
                field("password", legacy_credential()),
                field(
                    "display_name",
                    FieldKind::Inert {
                        claim: Some(ClaimPolicy::default()),
                    },
                ),
            ],
        );
        assert!(s.validate().is_ok());
        assert_eq!(s.claim_fields(), vec!["display_name"]);
    }

    #[test]
    fn no_claim_fields_returns_empty() {
        let s = schema(
            "myapp",
            vec![
                field("password", legacy_credential()),
                field("org", FieldKind::Index { claim: None }),
            ],
        );
        assert!(s.claim_fields().is_empty());
    }

    #[test]
    fn lockout_off_on_credential_valid() {
        let s = schema(
            "api_keys",
            vec![field(
                "key_secret",
                FieldKind::Credential(CredentialPolicy::default()),
            )],
        );
        assert!(s.validate().is_ok());
    }

    /// JSON lacking both `annotations` and `kind` deserializes to default
    /// (Inert) — exercises the deserializer's default branch.
    #[test]
    fn no_annotations_no_kind_defaults_to_inert() {
        let json = r#"{"name":"a","fields":[{"name":"display","field_type":"string"}]}"#;
        let s: Schema = serde_json::from_str(json).unwrap();
        assert!(matches!(s.fields[0].kind, FieldKind::Inert { claim: None }));
    }

    /// v2-form JSON with `kind` deserializes directly with policy values
    /// preserved verbatim.
    #[test]
    fn v2_credential_kind_deserializes_with_policy() {
        let json = r#"{"name":"a","fields":[{"name":"password","field_type":"string","kind":{"type":"credential","lockout":{"max_attempts":3,"duration_secs":60}}}]}"#;
        let s: Schema = serde_json::from_str(json).unwrap();
        assert!(s.fields[0].kind.is_credential());
        let p = s.fields[0].kind.credential_policy().unwrap();
        let l = p.lockout.as_ref().unwrap();
        assert_eq!(l.max_attempts, 3);
        assert_eq!(l.duration_secs, 60);
    }

    /// v1-form JSON with `annotations` is rejected with a pointer to the
    /// migration tool.
    #[test]
    fn v1_annotations_key_rejected_with_migration_hint() {
        let json = r#"{"name":"a","fields":[{"name":"password","field_type":"string","annotations":{"credential":true}}]}"#;
        let err = serde_json::from_str::<Schema>(json)
            .unwrap_err()
            .to_string();
        assert!(err.contains("legacy `annotations` key"), "err was: {err}");
        assert!(err.contains("SCHEMA MIGRATE"), "err was: {err}");
    }

    /// Serialize emits v2 canonical (`kind` only); re-parsing restores both
    /// forms via the normalizer. Defines the migration tool's output shape.
    #[test]
    fn serialize_emits_v2_and_roundtrips() {
        let s = schema(
            "myapp",
            vec![
                field("email", FieldKind::Pii(PiiPolicy { searchable: true })),
                field("password", legacy_credential()),
                field(
                    "role",
                    FieldKind::Index {
                        claim: Some(ClaimPolicy::default()),
                    },
                ),
            ],
        );
        let json = serde_json::to_string(&s).unwrap();
        // No `annotations` key in output — v2 canonical form.
        assert!(!json.contains("\"annotations\""));
        assert!(json.contains("\"kind\""));
        // Round-trip preserves routing behavior.
        let parsed: Schema = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.credential_fields(), vec!["password"]);
        assert_eq!(parsed.claim_fields(), vec!["role"]);
        assert!(parsed.fields[0].kind.is_pii());
    }

    // --- Schema::credential_policy resolver ---

    #[test]
    fn credential_policy_resolver_returns_some_for_credential_field() {
        let s = schema("myapp", vec![field("password", legacy_credential())]);
        let p = s.credential_policy("password").unwrap();
        // Default-derived from v1: legacy lockout, Argon2id.
        assert_eq!(p.algorithm, PasswordAlgorithm::Argon2id);
        assert!(p.lockout.is_some());
    }

    #[test]
    fn credential_policy_resolver_returns_none_for_non_credential() {
        let s = schema(
            "myapp",
            vec![
                field("password", legacy_credential()),
                field("email", FieldKind::Pii(PiiPolicy { searchable: false })),
            ],
        );
        assert!(s.credential_policy("email").is_none());
    }

    #[test]
    fn credential_policy_resolver_returns_none_for_unknown_field() {
        let s = schema("myapp", vec![field("password", legacy_credential())]);
        assert!(s.credential_policy("nonexistent").is_none());
    }

    #[test]
    fn field_lockout_reflects_per_field_policy_under_v2_input() {
        let json = r#"{"name":"a","fields":[
            {"name":"password","field_type":"string","kind":{"type":"credential","lockout":{"max_attempts":5,"duration_secs":900}}},
            {"name":"key","field_type":"string","kind":{"type":"credential","algorithm":"sha256"}}
        ]}"#;
        let s: Schema = serde_json::from_str(json).unwrap();
        assert!(s.field_lockout("password"));
        assert!(!s.field_lockout("key"));
    }
}
