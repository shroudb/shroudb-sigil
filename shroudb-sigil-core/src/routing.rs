use crate::field_kind::FieldKind;

/// The cryptographic treatment to apply to a field value.
///
/// Determined by the field's `FieldKind` at schema registration time.
/// The engine uses this to route field values to the appropriate handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldTreatment {
    /// Hash with Argon2id, or compare against a SHA-256 tag (`Sha256` policy).
    /// Supports verify, change, and optional lockout.
    Credential,
    /// Encrypt at rest via Cipher engine.
    EncryptedPii,
    /// Encrypt via Cipher + create blind index via Veil engine.
    SearchableEncrypted,
    /// Store as a versioned secret via Keep engine.
    VersionedSecret,
    /// Store as plaintext with a direct lookup index.
    PlaintextIndex,
    /// Store as-is with no special treatment.
    Inert,
}

/// Determine the treatment for a field directly from its `FieldKind`.
///
/// Variants map 1:1 to treatments — no runtime mutex checks, no accidental
/// misclassification.
pub fn route_field_from_kind(kind: &FieldKind) -> FieldTreatment {
    match kind {
        FieldKind::Credential(_) => FieldTreatment::Credential,
        FieldKind::Pii(p) if p.searchable => FieldTreatment::SearchableEncrypted,
        FieldKind::Pii(_) => FieldTreatment::EncryptedPii,
        FieldKind::Secret(_) => FieldTreatment::VersionedSecret,
        FieldKind::Index { .. } => FieldTreatment::PlaintextIndex,
        FieldKind::Inert { .. } => FieldTreatment::Inert,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field_kind::{CredentialPolicy, PiiPolicy, SecretPolicy};

    #[test]
    fn kind_credential_routes_to_credential() {
        let k = FieldKind::Credential(CredentialPolicy::default());
        assert_eq!(route_field_from_kind(&k), FieldTreatment::Credential);
    }

    #[test]
    fn kind_pii_non_searchable_routes_to_encrypted_pii() {
        let k = FieldKind::Pii(PiiPolicy { searchable: false });
        assert_eq!(route_field_from_kind(&k), FieldTreatment::EncryptedPii);
    }

    #[test]
    fn kind_pii_searchable_routes_to_searchable_encrypted() {
        let k = FieldKind::Pii(PiiPolicy { searchable: true });
        assert_eq!(
            route_field_from_kind(&k),
            FieldTreatment::SearchableEncrypted
        );
    }

    #[test]
    fn kind_secret_routes_to_versioned_secret() {
        let k = FieldKind::Secret(SecretPolicy {
            rotation_days: None,
        });
        assert_eq!(route_field_from_kind(&k), FieldTreatment::VersionedSecret);
    }

    #[test]
    fn kind_index_routes_to_plaintext_index() {
        let k = FieldKind::Index { claim: None };
        assert_eq!(route_field_from_kind(&k), FieldTreatment::PlaintextIndex);
    }

    #[test]
    fn kind_inert_routes_to_inert() {
        let k = FieldKind::Inert { claim: None };
        assert_eq!(route_field_from_kind(&k), FieldTreatment::Inert);
    }
}
