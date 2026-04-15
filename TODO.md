# TODO

## Schema v2.0: `FieldKind` enum + per-field credential policy

**Problem:** Today's `FieldAnnotations` is a flat bag of booleans (`credential`, `pii`, `searchable`, `secret`, `index`, `claim`, `lockout`) with runtime validation enforcing mutual exclusion and dependency rules. `PasswordPolicy` is engine-global, so every credential field across every schema gets the same algorithm, lockout thresholds, and length validation — that's Sigil hard-coding a "passwords work like this" decision, contradicting the schema-driven thesis.

The recently-shipped `lockout: bool` annotation is a wedge that proves per-field credential policy works. The full v2.0 refactor:

1. Replaces `FieldAnnotations` with a `kind: FieldKind` enum so mutual exclusion is enforced by the type system, not runtime checks.
2. Moves credential policy (algorithm, length bounds, lockout) onto a nested `CredentialPolicy` struct inside the `Credential` variant.
3. Shrinks or deletes `PasswordPolicy`, leaving only true engine-resource concerns at config level.

### Target shape

```rust
pub struct FieldDef {
    pub name: String,
    pub field_type: FieldType,   // unchanged: string | integer | boolean | bytes
    pub kind: FieldKind,
    pub required: bool,
}

#[serde(tag = "type", rename_all = "snake_case")]
pub enum FieldKind {
    Inert  { claim: Option<ClaimPolicy> },   // default
    Index  { claim: Option<ClaimPolicy> },
    Credential(CredentialPolicy),
    Pii(PiiPolicy),
    Secret(SecretPolicy),
}

pub struct CredentialPolicy {
    pub algorithm: PasswordAlgorithm,         // default Argon2id
    pub min_length: Option<usize>,            // None = safe default
    pub max_length: Option<usize>,
    pub lockout: Option<LockoutPolicy>,       // None = no lockout
}

pub struct LockoutPolicy { pub max_attempts: u32, pub duration_secs: u64 }
pub struct PiiPolicy     { pub searchable: bool /* blind index via Veil */ }
pub struct SecretPolicy  { pub rotation_days: Option<u32> }
pub struct ClaimPolicy   { pub as_name: Option<String> /* rename JWT claim */ }
```

JSON examples:

```jsonc
// Password — Argon2id, lockout enabled
{ "name": "password", "field_type": "string",
  "kind": { "type": "credential",
            "lockout": { "max_attempts": 5, "duration_secs": 900 } } }

// API key — fast hash, no lockout (omit the field)
{ "name": "key_secret", "field_type": "string",
  "kind": { "type": "credential", "algorithm": "sha256_hmac" } }

// Searchable PII
{ "name": "email", "field_type": "string",
  "kind": { "type": "pii", "searchable": true } }

// Index field shipped as a JWT claim, renamed to `sub`
{ "name": "client_id", "field_type": "string",
  "kind": { "type": "index", "claim": { "as_name": "sub" } } }

// Inert
{ "name": "display_name", "field_type": "string", "kind": { "type": "inert" } }
```

### What this kills (runtime check → type system)

| Today's runtime rule | v2.0 type-level enforcement |
|---|---|
| `credential ⊕ pii ⊕ secret ⊕ index` mutex | Single `FieldKind` enum — only one variant possible |
| `searchable` requires `pii` | `searchable` field only exists on `PiiPolicy` |
| `lockout=false` requires `credential=true` | `LockoutPolicy` only exists inside `CredentialPolicy`; `None` means no lockout |
| `claim` invalid on credential/pii/secret | `claim` only present on `Inert` and `Index` variants |
| `lockout: bool` (just-shipped flag) | Subsumed by `Option<LockoutPolicy>` — presence-of-struct is the signal |

`Option<LockoutPolicy>` over a sentinel like `max_attempts: 0`: we explicitly chose this. Sentinels reintroduce the ambiguity (`0` could mean "never lock" or "lock on first failure") that the type system was supposed to eliminate, and any future lockout knob (sliding window, exponential backoff) becomes structurally valid even when lockout is off.

### Audit of `PasswordPolicy` fields

| Field | Today | v2.0 home | Notes |
|---|---|---|---|
| `algorithm: PasswordAlgorithm` | engine-global | `CredentialPolicy.algorithm` | Argon2id correct for passwords, wrong for API keys (verify-cost throughput; high-entropy random secrets don't need KDF stretching). |
| `max_failed_attempts: u32` | engine-global | `LockoutPolicy.max_attempts` | |
| `lockout_duration_secs: u64` | engine-global | `LockoutPolicy.duration_secs` | |
| `min_length: usize` | engine-global | `CredentialPolicy.min_length` | Passwords need a floor; API keys are fixed-length random; PINs may want exact length. |
| `max_length: usize` | engine-global | `CredentialPolicy.max_length` | Same. |
| `max_concurrent_hashes: u32` | engine-global | **stays engine-global** | Process-wide memory bound on Argon2id — resource limit, not credential property. |

### Open design questions

1. **Non-Argon2id path for machine credentials.** Add `PasswordAlgorithm::Sha256Hmac` (or similar fast constant-time hash)? If yes, where does the HMAC key come from — engine startup config, Keep-managed, schema-level? If no, document that API-key schemas pay the Argon2id cost.
2. **Where do unset-field defaults live?** Hard-coded secure constants in `shroudb-sigil-core` (preferred — single source of truth, schema-driven), or engine-config fallback (more flexible, but reintroduces "engine knows about passwords").
3. **`PasswordPolicy` survival.** Options: (a) shrink to `EngineResourceConfig` with just `max_concurrent_hashes`; (b) delete and move semaphore size to a separate engine-startup arg; (c) rename to `CredentialDefaults` as fallback for unset fields (only viable if we go with option (2b)).
4. **Validation surface inside `CredentialPolicy`.** What combinations are illegal? E.g., `algorithm: Sha256Hmac` + `min_length: 8` is probably nonsensical. Need explicit rules.
5. **`claim` placement.** Current sketch puts `claim: Option<ClaimPolicy>` inside `Inert`/`Index` variants only (strictest typing — can't even express on a credential field). Alternative: keep `claim` as a top-level `FieldDef` field with one runtime "claim only on inert/index" check, gain simpler access (`field.claim.is_some()` vs. pattern-match). The strict version is more in keeping with the thesis; the loose version is friendlier to future cross-cutting metadata.

### Migration

This is a breaking schema-format change. No serde shim cleanly migrates `{"annotations": {"credential": true}}` to `{"kind": {"type": "credential"}}` without ambiguity. Path:

1. Bump to v2.0.0.
2. Ship a one-shot migration tool (`shroudb-sigil-cli SCHEMA MIGRATE`) that reads stored v1 schemas and rewrites them in v2 form.
3. Document the JSON format change in the changelog and DOCS.md.
4. Update downstream consumers (Moat, codegen, any SDK examples).

### Implementation sketch

1. Resolve the open design questions (separate design pass before code).
2. Define `FieldKind`, `CredentialPolicy`, `LockoutPolicy`, `PiiPolicy`, `SecretPolicy`, `ClaimPolicy` in `shroudb-sigil-core/src/schema.rs`.
3. Delete the old `FieldAnnotations` struct and the entire `validate()` method body — it collapses into structural impossibility.
4. Add `Schema::credential_policy(field_name) -> Option<&CredentialPolicy>` resolver.
5. Refactor `CredentialManager` to take a resolved `CredentialPolicy` per-call instead of holding a `PasswordPolicy`. Keep the `Semaphore` for hash concurrency.
6. Update every call site in `engine.rs` to resolve the policy and pass it through.
7. Shrink or delete `PasswordPolicy` per the decision in question (3).
8. Tests: per-field algorithm selection, per-field length bounds, per-field lockout thresholds, mixed-policy schemas (e.g., `users` schema with Argon2id + lockout, `api_keys` schema with SHA256-HMAC + no lockout, in the same engine).
9. Migration tool + tests against v1 schema fixtures.
10. Docs: `protocol.toml` (full type rewrite), `README.md`, `DOCS.md`, `ABOUT.md`. The "Account Lockout" section in `DOCS.md` folds into a broader "Credential Policy" section.

### Files in scope

- `shroudb-sigil-core/src/schema.rs` — `FieldKind` enum, policies, resolver
- `shroudb-sigil-core/src/credential.rs` — `PasswordPolicy` shape decision
- `shroudb-sigil-engine/src/credential.rs` — `CredentialManager` API change
- `shroudb-sigil-engine/src/engine.rs` — call-site wiring
- `shroudb-sigil-engine/src/write_coordinator.rs` — length validation now needs schema context
- `shroudb-sigil-server/src/config.rs` — server-side schema config mirror (also needs v2 format)
- `shroudb-sigil-cli/` — new `SCHEMA MIGRATE` subcommand
- `protocol.toml`, `README.md`, `DOCS.md`, `ABOUT.md`, `CHANGELOG.md`
