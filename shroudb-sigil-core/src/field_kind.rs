//! Per-field cryptographic treatment.
//!
//! `FieldKind` makes mutual exclusion structural (only one variant can be
//! selected) and carries only the policy knobs relevant to each treatment.
//! Credential policy (algorithm, length bounds, lockout) lives on
//! `CredentialPolicy` inside the `Credential` variant.

use serde::{Deserialize, Serialize};

use crate::credential::PasswordAlgorithm;
use crate::error::SigilError;

/// Default minimum credential length when the schema does not specify one.
pub const DEFAULT_MIN_LENGTH: usize = 8;

/// Default maximum credential length when the schema does not specify one.
pub const DEFAULT_MAX_LENGTH: usize = 128;

/// Minimum credential length when the algorithm is `Sha256`.
///
/// SHA-256 is cryptographically sufficient for high-entropy machine
/// credentials (the 2^256 input space defeats offline brute-force regardless
/// of HMAC) but instantly brute-forceable on short or low-entropy inputs.
/// The 32-byte floor matches `shroudb_crypto::generate_api_key`, which
/// produces 32-byte CSPRNG secrets.
pub const SHA256_MIN_LENGTH: usize = 32;

/// Per-field cryptographic treatment.
///
/// Only one variant is possible per field, so mutex rules between
/// `credential`, `pii`, `secret`, and `index` are enforced by the type
/// system — not runtime validation.
///
/// Variants:
/// - `Inert` — opaque envelope field, no crypto treatment.
/// - `Index` — plaintext-indexed for direct lookups.
/// - `Credential` — hashed (Argon2id) or unkeyed-SHA256 for machine creds.
/// - `Pii` — encrypted at rest via Cipher, optionally searchable via Veil.
/// - `Secret` — versioned secret stored via Keep.
///
/// The `claim` policy lives only on `Inert` and `Index` — variants that
/// carry plaintext values suitable for JWT claim enrichment. Placing it
/// there structurally rather than validating "claim only on inert/index"
/// at runtime is deliberate: it's the core thesis of the refactor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FieldKind {
    Inert {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        claim: Option<ClaimPolicy>,
    },
    Index {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        claim: Option<ClaimPolicy>,
    },
    Credential(CredentialPolicy),
    Pii(PiiPolicy),
    Secret(SecretPolicy),
}

impl Default for FieldKind {
    fn default() -> Self {
        FieldKind::Inert { claim: None }
    }
}

impl FieldKind {
    /// Validate per-variant rules. Returns `Ok(())` for `Inert`, `Index`,
    /// `Pii`, and `Secret` (which have no non-structural rules today).
    pub fn validate(&self, field_name: &str) -> Result<(), SigilError> {
        match self {
            FieldKind::Inert { .. } | FieldKind::Index { .. } => Ok(()),
            FieldKind::Credential(p) => p.validate(field_name),
            FieldKind::Pii(_) | FieldKind::Secret(_) => Ok(()),
        }
    }

    /// Claim policy for this field, if the variant supports claim enrichment.
    pub fn claim(&self) -> Option<&ClaimPolicy> {
        match self {
            FieldKind::Inert { claim } | FieldKind::Index { claim } => claim.as_ref(),
            _ => None,
        }
    }

    pub fn is_credential(&self) -> bool {
        matches!(self, FieldKind::Credential(_))
    }

    pub fn is_pii(&self) -> bool {
        matches!(self, FieldKind::Pii(_))
    }

    pub fn is_secret(&self) -> bool {
        matches!(self, FieldKind::Secret(_))
    }

    pub fn is_index(&self) -> bool {
        matches!(self, FieldKind::Index { .. })
    }

    pub fn credential_policy(&self) -> Option<&CredentialPolicy> {
        if let FieldKind::Credential(p) = self {
            Some(p)
        } else {
            None
        }
    }
}

/// Per-field credential policy — algorithm, length bounds, lockout. Resource
/// limits that are genuinely process-scoped (e.g. `max_concurrent_hashes`)
/// live on `EngineResourceConfig` instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CredentialPolicy {
    /// Hashing algorithm. Defaults to Argon2id.
    #[serde(default)]
    pub algorithm: PasswordAlgorithm,
    /// Minimum input length. `None` resolves to `DEFAULT_MIN_LENGTH`
    /// (or `SHA256_MIN_LENGTH` when `algorithm == Sha256`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_length: Option<usize>,
    /// Maximum input length. `None` resolves to `DEFAULT_MAX_LENGTH`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_length: Option<usize>,
    /// Lockout policy. `None` means lockout is disabled for this field.
    /// Absence of the struct — rather than a sentinel like `max_attempts: 0`
    /// — is the signal: sentinels reintroduce the ambiguity the type system
    /// was supposed to eliminate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lockout: Option<LockoutPolicy>,
}

impl CredentialPolicy {
    /// Effective minimum length, resolving `None` against algorithm-specific
    /// defaults.
    pub fn resolved_min_length(&self) -> usize {
        self.min_length.unwrap_or(match self.algorithm {
            PasswordAlgorithm::Sha256 => SHA256_MIN_LENGTH,
            _ => DEFAULT_MIN_LENGTH,
        })
    }

    /// Effective maximum length, resolving `None` against the global default.
    pub fn resolved_max_length(&self) -> usize {
        self.max_length.unwrap_or(DEFAULT_MAX_LENGTH)
    }

    pub fn validate(&self, field_name: &str) -> Result<(), SigilError> {
        if let Some(min) = self.min_length
            && min == 0
        {
            return Err(SigilError::SchemaValidation(format!(
                "field '{field_name}': credential min_length must be > 0"
            )));
        }
        if let (Some(min), Some(max)) = (self.min_length, self.max_length)
            && max < min
        {
            return Err(SigilError::SchemaValidation(format!(
                "field '{field_name}': credential max_length ({max}) < min_length ({min})"
            )));
        }
        if self.algorithm == PasswordAlgorithm::Sha256 {
            let effective_min = self.min_length.unwrap_or(SHA256_MIN_LENGTH);
            if effective_min < SHA256_MIN_LENGTH {
                return Err(SigilError::SchemaValidation(format!(
                    "field '{field_name}': Sha256 credential requires min_length >= \
                     {SHA256_MIN_LENGTH} (SHA-256 is safe only on high-entropy machine credentials)"
                )));
            }
        }
        if let Some(lockout) = &self.lockout {
            lockout.validate(field_name)?;
        }
        Ok(())
    }
}

/// Lockout thresholds for a credential field.
///
/// Presence-of-struct (vs. `Option::None`) is the "is lockout enabled?"
/// signal. Fields inside must be non-zero — zero-valued thresholds would
/// reintroduce the same ambiguity (lock on first failure? never lock?) the
/// `Option` wrapper exists to eliminate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockoutPolicy {
    pub max_attempts: u32,
    pub duration_secs: u64,
}

impl LockoutPolicy {
    pub fn validate(&self, field_name: &str) -> Result<(), SigilError> {
        if self.max_attempts == 0 {
            return Err(SigilError::SchemaValidation(format!(
                "field '{field_name}': lockout max_attempts must be > 0"
            )));
        }
        if self.duration_secs == 0 {
            return Err(SigilError::SchemaValidation(format!(
                "field '{field_name}': lockout duration_secs must be > 0"
            )));
        }
        Ok(())
    }
}

/// PII (encrypted at rest) policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PiiPolicy {
    /// Create a blind index for encrypted search via Veil.
    #[serde(default)]
    pub searchable: bool,
}

/// Secret (Keep-managed) policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SecretPolicy {
    /// Optional rotation hint in days. Advisory metadata — not enforced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_days: Option<u32>,
}

/// Claim-enrichment policy for fields whose plaintext value feeds JWT claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ClaimPolicy {
    /// Rename the JWT claim key on output (e.g. map `client_id` → `sub`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub as_name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // --- default + constructor basics ---

    #[test]
    fn default_is_inert_without_claim() {
        let k = FieldKind::default();
        assert!(matches!(k, FieldKind::Inert { claim: None }));
    }

    #[test]
    fn credential_policy_default_has_argon2id_and_no_lockout() {
        let p = CredentialPolicy::default();
        assert_eq!(p.algorithm, PasswordAlgorithm::Argon2id);
        assert_eq!(p.min_length, None);
        assert_eq!(p.max_length, None);
        assert_eq!(p.lockout, None);
    }

    // --- resolved defaults ---

    #[test]
    fn resolved_min_length_uses_default_for_argon2id_when_unset() {
        let p = CredentialPolicy::default();
        assert_eq!(p.resolved_min_length(), DEFAULT_MIN_LENGTH);
    }

    #[test]
    fn resolved_min_length_uses_sha256_floor_when_unset() {
        let p = CredentialPolicy {
            algorithm: PasswordAlgorithm::Sha256,
            ..Default::default()
        };
        assert_eq!(p.resolved_min_length(), SHA256_MIN_LENGTH);
    }

    #[test]
    fn resolved_min_length_respects_explicit_value() {
        let p = CredentialPolicy {
            min_length: Some(16),
            ..Default::default()
        };
        assert_eq!(p.resolved_min_length(), 16);
    }

    #[test]
    fn resolved_max_length_uses_default_when_unset() {
        let p = CredentialPolicy::default();
        assert_eq!(p.resolved_max_length(), DEFAULT_MAX_LENGTH);
    }

    // --- validation ---

    #[test]
    fn validate_rejects_zero_min_length() {
        let p = CredentialPolicy {
            min_length: Some(0),
            ..Default::default()
        };
        let err = p.validate("password").unwrap_err().to_string();
        assert!(err.contains("min_length must be > 0"));
    }

    #[test]
    fn validate_rejects_max_less_than_min() {
        let p = CredentialPolicy {
            min_length: Some(16),
            max_length: Some(8),
            ..Default::default()
        };
        let err = p.validate("password").unwrap_err().to_string();
        assert!(err.contains("max_length"));
    }

    #[test]
    fn validate_accepts_equal_min_and_max() {
        let p = CredentialPolicy {
            min_length: Some(32),
            max_length: Some(32),
            ..Default::default()
        };
        assert!(p.validate("pin").is_ok());
    }

    #[test]
    fn validate_sha256_rejects_short_explicit_min() {
        let p = CredentialPolicy {
            algorithm: PasswordAlgorithm::Sha256,
            min_length: Some(16),
            ..Default::default()
        };
        let err = p.validate("key_secret").unwrap_err().to_string();
        assert!(err.contains("Sha256"));
        assert!(err.contains("min_length"));
    }

    #[test]
    fn validate_sha256_accepts_default_floor() {
        let p = CredentialPolicy {
            algorithm: PasswordAlgorithm::Sha256,
            ..Default::default()
        };
        assert!(p.validate("key_secret").is_ok());
    }

    #[test]
    fn validate_sha256_accepts_explicit_floor() {
        let p = CredentialPolicy {
            algorithm: PasswordAlgorithm::Sha256,
            min_length: Some(SHA256_MIN_LENGTH),
            ..Default::default()
        };
        assert!(p.validate("key_secret").is_ok());
    }

    #[test]
    fn lockout_validate_rejects_zero_max_attempts() {
        let l = LockoutPolicy {
            max_attempts: 0,
            duration_secs: 900,
        };
        let err = l.validate("password").unwrap_err().to_string();
        assert!(err.contains("max_attempts"));
    }

    #[test]
    fn lockout_validate_rejects_zero_duration() {
        let l = LockoutPolicy {
            max_attempts: 5,
            duration_secs: 0,
        };
        let err = l.validate("password").unwrap_err().to_string();
        assert!(err.contains("duration_secs"));
    }

    #[test]
    fn credential_policy_propagates_lockout_validation() {
        let p = CredentialPolicy {
            lockout: Some(LockoutPolicy {
                max_attempts: 0,
                duration_secs: 900,
            }),
            ..Default::default()
        };
        assert!(p.validate("password").is_err());
    }

    // --- serde round-trips ---

    #[test]
    fn inert_serde_omits_claim_when_none() {
        let k = FieldKind::Inert { claim: None };
        let v = serde_json::to_value(&k).unwrap();
        assert_eq!(v, json!({ "type": "inert" }));
        let parsed: FieldKind = serde_json::from_value(v).unwrap();
        assert_eq!(parsed, k);
    }

    #[test]
    fn inert_serde_roundtrips_with_claim() {
        let k = FieldKind::Inert {
            claim: Some(ClaimPolicy {
                as_name: Some("display_name".into()),
            }),
        };
        let v = serde_json::to_value(&k).unwrap();
        assert_eq!(
            v,
            json!({ "type": "inert", "claim": { "as_name": "display_name" } })
        );
        let parsed: FieldKind = serde_json::from_value(v).unwrap();
        assert_eq!(parsed, k);
    }

    #[test]
    fn index_serde_with_claim_as_name_sub() {
        let k = FieldKind::Index {
            claim: Some(ClaimPolicy {
                as_name: Some("sub".into()),
            }),
        };
        let v = serde_json::to_value(&k).unwrap();
        assert_eq!(v, json!({ "type": "index", "claim": { "as_name": "sub" } }));
    }

    #[test]
    fn credential_serde_minimal_uses_defaults() {
        let json_in = json!({ "type": "credential" });
        let parsed: FieldKind = serde_json::from_value(json_in).unwrap();
        match parsed {
            FieldKind::Credential(p) => {
                assert_eq!(p.algorithm, PasswordAlgorithm::Argon2id);
                assert_eq!(p.min_length, None);
                assert_eq!(p.max_length, None);
                assert_eq!(p.lockout, None);
            }
            _ => panic!("expected Credential variant"),
        }
    }

    #[test]
    fn credential_serde_with_lockout_roundtrips() {
        let json_in = json!({
            "type": "credential",
            "lockout": { "max_attempts": 5, "duration_secs": 900 }
        });
        let parsed: FieldKind = serde_json::from_value(json_in.clone()).unwrap();
        let v = serde_json::to_value(&parsed).unwrap();
        // Defaults are elided (algorithm is the enum's Default::default),
        // so serialized form matches input.
        assert_eq!(
            v,
            json!({ "type": "credential", "algorithm": "argon2id", "lockout": { "max_attempts": 5, "duration_secs": 900 } })
        );
    }

    #[test]
    fn credential_serde_sha256_api_key_shape() {
        let json_in = json!({
            "type": "credential",
            "algorithm": "sha256"
        });
        let parsed: FieldKind = serde_json::from_value(json_in).unwrap();
        match parsed {
            FieldKind::Credential(p) => {
                assert_eq!(p.algorithm, PasswordAlgorithm::Sha256);
                assert_eq!(p.lockout, None);
            }
            _ => panic!("expected Credential variant"),
        }
    }

    #[test]
    fn pii_serde_searchable_flag() {
        let k = FieldKind::Pii(PiiPolicy { searchable: true });
        let v = serde_json::to_value(&k).unwrap();
        assert_eq!(v, json!({ "type": "pii", "searchable": true }));
        let parsed: FieldKind = serde_json::from_value(v).unwrap();
        assert_eq!(parsed, k);
    }

    #[test]
    fn pii_serde_default_searchable_false() {
        let json_in = json!({ "type": "pii" });
        let parsed: FieldKind = serde_json::from_value(json_in).unwrap();
        match parsed {
            FieldKind::Pii(p) => assert!(!p.searchable),
            _ => panic!("expected Pii variant"),
        }
    }

    #[test]
    fn secret_serde_rotation_days() {
        let k = FieldKind::Secret(SecretPolicy {
            rotation_days: Some(90),
        });
        let v = serde_json::to_value(&k).unwrap();
        assert_eq!(v, json!({ "type": "secret", "rotation_days": 90 }));
        let parsed: FieldKind = serde_json::from_value(v).unwrap();
        assert_eq!(parsed, k);
    }

    #[test]
    fn secret_serde_omits_rotation_days_when_none() {
        let k = FieldKind::Secret(SecretPolicy {
            rotation_days: None,
        });
        let v = serde_json::to_value(&k).unwrap();
        assert_eq!(v, json!({ "type": "secret" }));
    }

    #[test]
    fn lockout_null_parses_same_as_absent() {
        let with_null: FieldKind =
            serde_json::from_value(json!({ "type": "credential", "lockout": null })).unwrap();
        let absent: FieldKind = serde_json::from_value(json!({ "type": "credential" })).unwrap();
        assert_eq!(with_null, absent);
    }

    #[test]
    fn unknown_type_rejected() {
        let result: Result<FieldKind, _> = serde_json::from_value(json!({ "type": "bogus" }));
        assert!(result.is_err());
    }

    // --- claim accessor ---

    #[test]
    fn claim_accessor_returns_some_on_inert() {
        let k = FieldKind::Inert {
            claim: Some(ClaimPolicy { as_name: None }),
        };
        assert!(k.claim().is_some());
    }

    #[test]
    fn claim_accessor_returns_some_on_index() {
        let k = FieldKind::Index {
            claim: Some(ClaimPolicy {
                as_name: Some("sub".into()),
            }),
        };
        assert_eq!(k.claim().unwrap().as_name.as_deref(), Some("sub"));
    }

    #[test]
    fn claim_accessor_returns_none_on_credential() {
        let k = FieldKind::Credential(CredentialPolicy::default());
        assert!(k.claim().is_none());
    }

    #[test]
    fn claim_accessor_returns_none_on_pii() {
        let k = FieldKind::Pii(PiiPolicy { searchable: true });
        assert!(k.claim().is_none());
    }

    #[test]
    fn claim_accessor_returns_none_on_secret() {
        let k = FieldKind::Secret(SecretPolicy {
            rotation_days: None,
        });
        assert!(k.claim().is_none());
    }

    // --- variant predicates ---

    #[test]
    fn is_credential_predicate() {
        assert!(FieldKind::Credential(CredentialPolicy::default()).is_credential());
        assert!(!FieldKind::default().is_credential());
    }

    #[test]
    fn credential_policy_accessor() {
        let p = CredentialPolicy {
            min_length: Some(12),
            ..Default::default()
        };
        let k = FieldKind::Credential(p.clone());
        assert_eq!(k.credential_policy().unwrap().min_length, Some(12));
        assert!(FieldKind::default().credential_policy().is_none());
    }
}
