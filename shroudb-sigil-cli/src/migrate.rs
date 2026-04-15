//! v1 → v2 schema JSON migration.
//!
//! Phase 6 deleted the `FieldAnnotations`/`PasswordPolicy` types from core and
//! made v2's deserializer refuse the legacy `annotations` key. Persisted v1
//! schemas in a ShrouDB store need to be rewritten before the v2 server can
//! read them. This module does the transformation at the JSON layer — no v1
//! types required, no semantic surprises.
//!
//! Pre-v1.9.2 lockout default (true) is preserved as an explicit
//! `LockoutPolicy { max_attempts: 5, duration_secs: 900 }` to keep observable
//! behavior identical across the upgrade.

use anyhow::{Context, Result};
use serde_json::{Value, json};

/// Legacy `PasswordPolicy::default()` values, baked into the migration to
/// preserve observable behavior of schemas registered before v2.0.
const LEGACY_LOCKOUT_MAX_ATTEMPTS: u32 = 5;
const LEGACY_LOCKOUT_DURATION_SECS: u64 = 900;

/// Outcome of migrating a single schema JSON blob.
#[derive(Debug, PartialEq, Eq)]
pub enum MigrationOutcome {
    /// Schema was v1; returned bytes are the v2-form rewrite.
    Migrated(Vec<u8>),
    /// Schema was already v2; no changes required.
    AlreadyV2,
}

/// Translate a serialized schema from v1 to v2 JSON form. Idempotent — a
/// v2-form input returns `MigrationOutcome::AlreadyV2` unchanged.
///
/// Errors on malformed input (not a JSON object, missing `fields`, field
/// missing required keys, ambiguous annotations that don't map cleanly to a
/// single v2 variant).
pub fn migrate_schema_json(raw: &[u8]) -> Result<MigrationOutcome> {
    let mut value: Value = serde_json::from_slice(raw).context("schema JSON is not valid JSON")?;
    let obj = value
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("schema JSON root is not an object"))?;
    let fields = obj
        .get_mut("fields")
        .ok_or_else(|| anyhow::anyhow!("schema JSON missing `fields` array"))?
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("schema JSON `fields` is not an array"))?;

    let mut any_migrated = false;
    let mut any_v2 = false;
    for field in fields.iter_mut() {
        let field_obj = field
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("schema field is not a JSON object"))?;
        let has_kind = field_obj.contains_key("kind");
        let has_annotations = field_obj.contains_key("annotations");

        if has_kind && has_annotations {
            anyhow::bail!(
                "schema field '{}' has both `kind` (v2) and `annotations` (v1) — refusing to migrate",
                field_obj
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("<unnamed>")
            );
        }

        if has_kind {
            any_v2 = true;
            continue;
        }

        // v1 path: normalize annotations (or their absence) into a kind.
        let field_name = field_obj
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("<unnamed>")
            .to_string();
        let annotations = field_obj.remove("annotations").unwrap_or(json!({}));
        let kind = annotations_to_kind(&annotations, &field_name)?;
        field_obj.insert("kind".into(), kind);
        any_migrated = true;
    }

    if any_migrated {
        let bytes =
            serde_json::to_vec(&value).context("failed to serialize migrated schema JSON")?;
        Ok(MigrationOutcome::Migrated(bytes))
    } else if any_v2 {
        Ok(MigrationOutcome::AlreadyV2)
    } else {
        // Schema with no fields? Shouldn't happen (core validator rejects
        // empty schemas at registration), but be permissive here — leave
        // untouched.
        Ok(MigrationOutcome::AlreadyV2)
    }
}

/// Translate a v1 annotation bag (`{"credential": true}`, etc.) into the
/// corresponding v2 `kind` object. The input may be `{}` (all-false →
/// Inert) or even `null`/missing at the call site.
fn annotations_to_kind(annotations: &Value, field_name: &str) -> Result<Value> {
    let obj = match annotations {
        Value::Object(m) => m,
        Value::Null => {
            return Ok(json!({ "type": "inert" }));
        }
        _ => anyhow::bail!("field '{field_name}': `annotations` is not a JSON object"),
    };

    let credential = bool_flag(obj, "credential");
    let pii = bool_flag(obj, "pii");
    let searchable = bool_flag(obj, "searchable");
    let secret = bool_flag(obj, "secret");
    let index = bool_flag(obj, "index");
    let claim = bool_flag(obj, "claim");
    // Pre-v1.9.2 lockout default was `true`, even when the key was absent.
    let lockout = obj.get("lockout").and_then(|v| v.as_bool()).unwrap_or(true);

    // The v1 validator guaranteed mutual exclusion among credential/pii/secret
    // (and index when none of those are set). If caller-provided input
    // violates that, surface it instead of silently picking one.
    let primary_count = [credential, pii, secret, index]
        .iter()
        .filter(|b| **b)
        .count();
    if primary_count > 1 {
        anyhow::bail!(
            "field '{field_name}': multiple mutually exclusive flags set in annotations \
             (credential={credential}, pii={pii}, secret={secret}, index={index})"
        );
    }
    if searchable && !pii {
        anyhow::bail!(
            "field '{field_name}': `searchable` is set without `pii` — not representable in v2"
        );
    }
    if credential && claim {
        anyhow::bail!(
            "field '{field_name}': `claim` on a credential field — not representable in v2"
        );
    }
    if (pii || secret) && claim {
        anyhow::bail!(
            "field '{field_name}': `claim` on a pii/secret field — not representable in v2"
        );
    }

    if credential {
        if lockout {
            Ok(json!({
                "type": "credential",
                "algorithm": "argon2id",
                "lockout": {
                    "max_attempts": LEGACY_LOCKOUT_MAX_ATTEMPTS,
                    "duration_secs": LEGACY_LOCKOUT_DURATION_SECS,
                }
            }))
        } else {
            Ok(json!({ "type": "credential", "algorithm": "argon2id" }))
        }
    } else if pii {
        if searchable {
            Ok(json!({ "type": "pii", "searchable": true }))
        } else {
            Ok(json!({ "type": "pii" }))
        }
    } else if secret {
        Ok(json!({ "type": "secret" }))
    } else if index {
        if claim {
            Ok(json!({ "type": "index", "claim": {} }))
        } else {
            Ok(json!({ "type": "index" }))
        }
    } else if claim {
        Ok(json!({ "type": "inert", "claim": {} }))
    } else {
        Ok(json!({ "type": "inert" }))
    }
}

fn bool_flag(obj: &serde_json::Map<String, Value>, key: &str) -> bool {
    obj.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v2_round_trips(json_bytes: &[u8]) {
        // A migrated schema must parse cleanly as a v2 Schema.
        let _: shroudb_sigil_core::schema::Schema =
            serde_json::from_slice(json_bytes).expect("migrated bytes should parse as v2 Schema");
    }

    #[test]
    fn migrates_credential_with_default_lockout() {
        let v1 = br#"{"name":"users","version":1,"fields":[
            {"name":"password","field_type":"string","annotations":{"credential":true}}
        ]}"#;
        let out = migrate_schema_json(v1).unwrap();
        let bytes = match out {
            MigrationOutcome::Migrated(b) => b,
            _ => panic!("expected Migrated"),
        };
        v2_round_trips(&bytes);
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        let kind = &v["fields"][0]["kind"];
        assert_eq!(kind["type"], "credential");
        assert_eq!(kind["lockout"]["max_attempts"], 5);
        assert_eq!(kind["lockout"]["duration_secs"], 900);
    }

    #[test]
    fn migrates_credential_lockout_false_to_none() {
        let v1 = br#"{"name":"api","version":1,"fields":[
            {"name":"key","field_type":"string","annotations":{"credential":true,"lockout":false}}
        ]}"#;
        let out = migrate_schema_json(v1).unwrap();
        let bytes = match out {
            MigrationOutcome::Migrated(b) => b,
            _ => panic!("expected Migrated"),
        };
        v2_round_trips(&bytes);
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(v["fields"][0]["kind"].get("lockout").is_none());
    }

    #[test]
    fn migrates_pii_searchable() {
        let v1 = br#"{"name":"u","fields":[
            {"name":"email","field_type":"string","annotations":{"pii":true,"searchable":true}}
        ]}"#;
        let bytes = match migrate_schema_json(v1).unwrap() {
            MigrationOutcome::Migrated(b) => b,
            _ => panic!(),
        };
        v2_round_trips(&bytes);
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["fields"][0]["kind"]["type"], "pii");
        assert_eq!(v["fields"][0]["kind"]["searchable"], true);
    }

    #[test]
    fn migrates_secret() {
        let v1 = br#"{"name":"u","fields":[
            {"name":"key","field_type":"string","annotations":{"secret":true}}
        ]}"#;
        let bytes = match migrate_schema_json(v1).unwrap() {
            MigrationOutcome::Migrated(b) => b,
            _ => panic!(),
        };
        v2_round_trips(&bytes);
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["fields"][0]["kind"]["type"], "secret");
    }

    #[test]
    fn migrates_index_with_claim() {
        let v1 = br#"{"name":"u","fields":[
            {"name":"role","field_type":"string","annotations":{"index":true,"claim":true}}
        ]}"#;
        let bytes = match migrate_schema_json(v1).unwrap() {
            MigrationOutcome::Migrated(b) => b,
            _ => panic!(),
        };
        v2_round_trips(&bytes);
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["fields"][0]["kind"]["type"], "index");
        assert!(v["fields"][0]["kind"]["claim"].is_object());
    }

    #[test]
    fn migrates_index_without_claim() {
        let v1 = br#"{"name":"u","fields":[
            {"name":"org","field_type":"string","annotations":{"index":true}}
        ]}"#;
        let bytes = match migrate_schema_json(v1).unwrap() {
            MigrationOutcome::Migrated(b) => b,
            _ => panic!(),
        };
        v2_round_trips(&bytes);
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["fields"][0]["kind"]["type"], "index");
        assert!(v["fields"][0]["kind"].get("claim").is_none());
    }

    #[test]
    fn migrates_inert_with_claim() {
        let v1 = br#"{"name":"u","fields":[
            {"name":"display","field_type":"string","annotations":{"claim":true}}
        ]}"#;
        let bytes = match migrate_schema_json(v1).unwrap() {
            MigrationOutcome::Migrated(b) => b,
            _ => panic!(),
        };
        v2_round_trips(&bytes);
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["fields"][0]["kind"]["type"], "inert");
    }

    #[test]
    fn migrates_inert_no_annotations() {
        let v1 = br#"{"name":"u","fields":[
            {"name":"note","field_type":"string"}
        ]}"#;
        let bytes = match migrate_schema_json(v1).unwrap() {
            MigrationOutcome::Migrated(b) => b,
            _ => panic!(),
        };
        v2_round_trips(&bytes);
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["fields"][0]["kind"]["type"], "inert");
    }

    #[test]
    fn v2_input_is_noop() {
        let v2 = br#"{"name":"u","fields":[
            {"name":"password","field_type":"string","kind":{"type":"credential","algorithm":"argon2id","lockout":{"max_attempts":5,"duration_secs":900}}}
        ]}"#;
        assert_eq!(
            migrate_schema_json(v2).unwrap(),
            MigrationOutcome::AlreadyV2
        );
    }

    #[test]
    fn mixed_schema_migrates_and_flags_already_v2_as_migrated() {
        // If at least one field needs migration, the whole schema is
        // considered "Migrated" and the output is a full rewrite.
        let v1 = br#"{"name":"u","fields":[
            {"name":"pw","field_type":"string","kind":{"type":"credential"}},
            {"name":"role","field_type":"string","annotations":{"index":true}}
        ]}"#;
        let bytes = match migrate_schema_json(v1).unwrap() {
            MigrationOutcome::Migrated(b) => b,
            _ => panic!("expected Migrated for partial-v1 input"),
        };
        v2_round_trips(&bytes);
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["fields"][0]["kind"]["type"], "credential");
        assert_eq!(v["fields"][1]["kind"]["type"], "index");
    }

    #[test]
    fn rejects_field_with_both_kind_and_annotations() {
        let bad = br#"{"name":"u","fields":[
            {"name":"x","field_type":"string","kind":{"type":"inert"},"annotations":{"pii":true}}
        ]}"#;
        let err = migrate_schema_json(bad).unwrap_err().to_string();
        assert!(err.contains("both"));
        assert!(err.contains("kind"));
        assert!(err.contains("annotations"));
    }

    #[test]
    fn rejects_invalid_mutex_annotations() {
        let bad = br#"{"name":"u","fields":[
            {"name":"x","field_type":"string","annotations":{"credential":true,"pii":true}}
        ]}"#;
        let err = migrate_schema_json(bad).unwrap_err().to_string();
        assert!(err.contains("mutually exclusive"));
    }

    #[test]
    fn rejects_searchable_without_pii() {
        let bad = br#"{"name":"u","fields":[
            {"name":"x","field_type":"string","annotations":{"searchable":true}}
        ]}"#;
        let err = migrate_schema_json(bad).unwrap_err().to_string();
        assert!(err.contains("searchable"));
        assert!(err.contains("pii"));
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(migrate_schema_json(b"not json").is_err());
    }

    #[test]
    fn rejects_non_object_root() {
        assert!(migrate_schema_json(b"[1,2,3]").is_err());
    }

    #[test]
    fn rejects_missing_fields_array() {
        assert!(migrate_schema_json(b"{\"name\":\"u\"}").is_err());
    }

    #[test]
    fn preserves_schema_name_and_version() {
        let v1 = br#"{"name":"myapp","version":7,"fields":[
            {"name":"org","field_type":"string","annotations":{"index":true}}
        ]}"#;
        let bytes = match migrate_schema_json(v1).unwrap() {
            MigrationOutcome::Migrated(b) => b,
            _ => panic!(),
        };
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["name"], "myapp");
        assert_eq!(v["version"], 7);
    }
}
