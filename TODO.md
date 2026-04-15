# Design Record — Schema v2.0

> Status: shipped in v2.0.0. This file is retained as the motivation / rationale record for the refactor. For how to use the new shapes, see `DOCS.md`, `README.md`, and `protocol.toml`.

## Schema v2.0: `FieldKind` enum + per-field credential policy

**Problem (as it stood pre-v2.0):** `FieldAnnotations` was a flat bag of booleans (`credential`, `pii`, `searchable`, `secret`, `index`, `claim`, `lockout`) with runtime validation enforcing mutual exclusion and dependency rules. `PasswordPolicy` was engine-global, so every credential field across every schema got the same algorithm, lockout thresholds, and length validation — Sigil hard-coding a "passwords work like this" decision, contradicting the schema-driven thesis.

The v1.9.2 `lockout: bool` annotation was a wedge that proved per-field credential policy worked. The v2.0 refactor:

1. Replaced `FieldAnnotations` with a `kind: FieldKind` enum so mutual exclusion is enforced by the type system, not runtime checks.
2. Moved credential policy (algorithm, length bounds, lockout) onto a nested `CredentialPolicy` struct inside the `Credential` variant.
3. Shrank `PasswordPolicy` to `EngineResourceConfig`, leaving only true engine-resource concerns at config level.

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
  "kind": { "type": "credential", "algorithm": "sha256" } }

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

This was a breaking schema-format change. No serde shim cleanly migrates `{"annotations": {"credential": true}}` to `{"kind": {"type": "credential"}}` without ambiguity. Path taken:

1. Version bumped to v2.0.0.
2. Shipped a one-shot migration tool (`shroudb-sigil-cli SCHEMA MIGRATE --store <path> [--dry-run]`) that reads stored v1 schemas and rewrites them in v2 form. Idempotent. Preserves pre-v1.9.2 implicit lockout by emitting an explicit `LockoutPolicy { max_attempts: 5, duration_secs: 900 }` on migrated credential fields.
3. JSON format change documented in the changelog and `DOCS.md`.
4. Downstream consumers (Moat, codegen, SDK examples) flagged for update in the `v2.0.0` release notes.

### Resolved decisions

The five open questions above have been settled as follows:

- **Q1 — Non-Argon2id path.** Ship `PasswordAlgorithm::Sha256` (unkeyed SHA-256 with constant-time comparison). Deliberately *not* HMAC: Sigil's `KeepOps` capability is explicitly one-way (`store_secret` / `delete_secret`; "Sigil never reads secrets back"), so an HMAC key would have to come from either a doctrine break on `KeepOps` or engine-startup config — both reintroduce the "Sigil deciding" coupling this refactor exists to remove. For 256-bit CSPRNG-generated API keys (as produced by `shroudb-crypto::generate_api_key`), unkeyed SHA-256 + constant-time compare is cryptographically sufficient; HMAC's value is defending against offline brute-force of *low-entropy* inputs, which machine credentials are not. Validation rule: `algorithm == Sha256` requires `min_length >= 32` (refuses use on short/low-entropy fields). Future Sha256Hmac path is not blocked — it can be added as another variant when/if low-entropy machine creds appear with a solved key-sourcing story.
- **Q2 — Default location.** Hard-coded constants in `shroudb-sigil-core` (`DEFAULT_MIN_LENGTH = 8`, `DEFAULT_MAX_LENGTH = 128`, `SHA256_MIN_LENGTH = 32`). No engine-config fallback — engine-side overrides would reintroduce the coupling v2.0 removes.
- **Q3 — `PasswordPolicy` survival.** Option (a): shrink to `EngineResourceConfig { max_concurrent_hashes: u32 }` in `shroudb-sigil-core::credential`. Rename `SigilConfig::password_policy` → `engine_resources`. Option (b) adds constructor churn with no upside; option (c) contradicts Q2.
- **Q4 — `CredentialPolicy` validation.** Minimum viable: `min_length > 0`; `max_length >= min_length` when both set; `LockoutPolicy.max_attempts > 0` and `duration_secs > 0`; `algorithm == Sha256` requires `min_length >= 32`. No algorithm × length cross-checks beyond the Sha256 floor.
- **Q5 — `claim` placement.** Strict: `claim: Option<ClaimPolicy>` lives on `Inert` and `Index` variants only. The whole point of the refactor is making invalid states unrepresentable; hoisting `claim` to `FieldDef` reintroduces the runtime check v2.0 deletes.

### Delivery plan (as shipped)

Two PRs against `main`:

- **PR1 — Core types + engine wiring (Phases 1–4).** Introduced v2 types alongside v1, cut the engine over to per-field `CredentialPolicy` (including `Sha256` dispatch), rewrote test fixtures to v2 form. A transitional deserializer accepted both v1 (`annotations`) and v2 (`kind`) JSON so existing tests kept passing throughout. No wire-format break. Released as `v2.0.0-rc.1` for downstream testing.
- **PR2 — Format break + migration + docs (Phases 5–8).** Server config TOML flipped to v2-only, `FieldAnnotations` + `PasswordPolicy` deleted, `shroudb-sigil-cli SCHEMA MIGRATE` shipped, all docs (`protocol.toml`, `README.md`, `DOCS.md`, `ABOUT.md`, `CHANGELOG.md`) rewritten, `protocol.toml` version bumped to `2.0.0`.

Cross-repo impact: `shroudb-moat` gets `SigilConfig` rename (`password_policy` → `engine_resources`) + schema-config TOML format break + 2.0 version pin (and its own migration step if it stores schemas via the embedded engine); `shroudb-codegen` regenerates from the new `protocol.toml` (tagged-union types replace `FieldAnnotations`). `shroudb-crypto` required zero code changes — `hmac_sign`, `sha256`, `constant_time_eq`, `password_hash`, `password_verify`, and `generate_api_key` were already exposed.

### Files touched

- `shroudb-sigil-core/src/field_kind.rs` — new `FieldKind` enum, policies, resolver
- `shroudb-sigil-core/src/credential.rs` — `EngineResourceConfig` replaces `PasswordPolicy`
- `shroudb-sigil-engine/src/credential.rs` — `CredentialManager` takes per-call `CredentialPolicy`
- `shroudb-sigil-engine/src/engine.rs` — call-site wiring
- `shroudb-sigil-engine/src/write_coordinator.rs` — length validation now schema-aware
- `shroudb-sigil-server/src/config.rs` — server-side schema config mirror (v2 format only)
- `shroudb-sigil-cli/` — `SCHEMA MIGRATE` subcommand
- `protocol.toml`, `README.md`, `DOCS.md`, `ABOUT.md`, `CHANGELOG.md`, `AGENTS.md`, `shroudb-sigil.md`, `CLAUDE.md`
