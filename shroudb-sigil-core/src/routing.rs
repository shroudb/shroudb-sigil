use crate::schema::FieldAnnotations;

/// The cryptographic treatment to apply to a field value.
///
/// Determined by the field's annotations at schema registration time.
/// The engine uses this to route field values to the appropriate handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldTreatment {
    /// Hash with Argon2id. Supports password verify, change, lockout.
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

/// Determine the treatment for a field based on its annotations.
pub fn route_field(annotations: &FieldAnnotations) -> FieldTreatment {
    if annotations.credential {
        FieldTreatment::Credential
    } else if annotations.pii && annotations.searchable {
        FieldTreatment::SearchableEncrypted
    } else if annotations.pii {
        FieldTreatment::EncryptedPii
    } else if annotations.secret {
        FieldTreatment::VersionedSecret
    } else if annotations.index {
        FieldTreatment::PlaintextIndex
    } else {
        FieldTreatment::Inert
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ann(f: impl FnOnce(&mut FieldAnnotations)) -> FieldAnnotations {
        let mut a = FieldAnnotations::default();
        f(&mut a);
        a
    }

    #[test]
    fn credential_field() {
        assert_eq!(
            route_field(&ann(|a| a.credential = true)),
            FieldTreatment::Credential
        );
    }

    #[test]
    fn pii_field() {
        assert_eq!(
            route_field(&ann(|a| a.pii = true)),
            FieldTreatment::EncryptedPii
        );
    }

    #[test]
    fn searchable_pii_field() {
        assert_eq!(
            route_field(&ann(|a| {
                a.pii = true;
                a.searchable = true;
            })),
            FieldTreatment::SearchableEncrypted
        );
    }

    #[test]
    fn secret_field() {
        assert_eq!(
            route_field(&ann(|a| a.secret = true)),
            FieldTreatment::VersionedSecret
        );
    }

    #[test]
    fn index_field() {
        assert_eq!(
            route_field(&ann(|a| a.index = true)),
            FieldTreatment::PlaintextIndex
        );
    }

    #[test]
    fn no_annotations() {
        assert_eq!(
            route_field(&FieldAnnotations::default()),
            FieldTreatment::Inert
        );
    }
}
