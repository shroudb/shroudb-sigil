# Sigil Documentation

## Configuration

### Config file

```toml
[server]
tcp_bind = "0.0.0.0:6499"
http_bind = "0.0.0.0:6500"

[store]
mode = "embedded"          # "embedded" or "remote"
data_dir = "./sigil-data"  # embedded mode
# uri = "shroudb+tls://token@host:6399"  # remote mode

[jwt]
access_ttl = "15m"
refresh_ttl = "30d"
jwt_algorithm = "ES256"    # ES256, ES384, RS256, RS384, RS512, EdDSA
```

### Master key

```sh
openssl rand -hex 32
export SHROUDB_MASTER_KEY="<64-hex-chars>"
```

Without a master key, Sigil starts in dev mode with an ephemeral key — data won't survive restarts.

## Schemas

A schema defines the shape of a credential record. Each field has a type and a `kind` (a tagged `FieldKind` variant) that determines how Sigil processes it.

### Registration

```sh
# HTTP
curl -X POST http://localhost:6500/sigil/schemas \
  -H "Content-Type: application/json" \
  -d '{
    "name": "myapp",
    "fields": [
      {"name": "email",    "field_type": "string", "kind": {"type": "pii", "searchable": true}},
      {"name": "password", "field_type": "string", "kind": {"type": "credential", "lockout": {"max_attempts": 5, "duration_secs": 900}}},
      {"name": "org_id",   "field_type": "string", "kind": {"type": "index"}},
      {"name": "name",     "field_type": "string", "kind": {"type": "inert"}}
    ]
  }'

# Wire protocol
SCHEMA REGISTER myapp {"fields":[...]}
```

### Field kinds

A field's `kind` is a tagged-union value, internally tagged on `type`. There are five variants:

#### `inert`

Stored as-is. No crypto treatment. Safe default for display names, timestamps, anything non-sensitive. Optionally carries `claim` to include the value in issued JWTs.

```json
{ "name": "display_name", "field_type": "string", "kind": { "type": "inert" } }
```

#### `index`

Plaintext lookup index. Enables `ENVELOPE LOOKUP` / `SESSION LOGIN` on the field. Optionally carries `claim`.

```json
{ "name": "role", "field_type": "string",
  "kind": { "type": "index", "claim": { "as_name": "sub" } } }
```

`claim.as_name` is optional — if omitted, the claim key matches the field name.

#### `credential`

Hashed and verified. Never returned on reads. Carries a `CredentialPolicy` — algorithm, length bounds, optional lockout.

```json
// Human password: Argon2id, lockout enabled
{ "name": "password", "field_type": "string",
  "kind": { "type": "credential",
            "lockout": { "max_attempts": 5, "duration_secs": 900 } } }

// Machine credential: unkeyed SHA-256 with constant-time compare, no lockout
{ "name": "key_secret", "field_type": "string",
  "kind": { "type": "credential", "algorithm": "sha256" } }
```

#### `pii`

Encrypted at rest via Cipher. Optionally blind-indexed via Veil.

```json
{ "name": "email", "field_type": "string",
  "kind": { "type": "pii", "searchable": true } }
```

#### `secret`

Versioned storage via Keep. Sigil forwards writes and never reads back — `KeepOps` is one-way by design.

```json
{ "name": "api_client_secret", "field_type": "string",
  "kind": { "type": "secret", "rotation_days": 90 } }
```

`rotation_days` is advisory metadata — Sigil does not itself trigger rotation.

### Credential Policy

The `credential` variant carries a per-field `CredentialPolicy`:

| Field | Default | Notes |
|-------|---------|-------|
| `algorithm` | `argon2id` | `argon2id` for human credentials, `sha256` for high-entropy machine credentials. Legacy import-only variants: `argon2i`, `argon2d`, `bcrypt`, `scrypt` (all transparently rehashed to Argon2id on next successful verify). |
| `min_length` | `None` → `8` (or `32` for `sha256`) | Minimum plaintext length enforced at write time. |
| `max_length` | `None` → `128` | Maximum plaintext length enforced at write time. |
| `lockout` | `None` → no lockout | Presence of a `LockoutPolicy { max_attempts, duration_secs }` enables failed-attempt lockout on this field. |

Policy is **per-field**, not engine-wide. One schema can carry a `password` (Argon2id, lockout on) and an `api_key` (Sha256, no lockout) simultaneously:

```sh
SCHEMA REGISTER myapp '{"fields":[
  {"name":"password",   "field_type":"string",
   "kind":{"type":"credential",
           "lockout":{"max_attempts":5,"duration_secs":900}}},
  {"name":"api_key",    "field_type":"string",
   "kind":{"type":"credential","algorithm":"sha256"}},
  {"name":"email",      "field_type":"string",
   "kind":{"type":"pii","searchable":true}}
]}'
```

#### Why `sha256` is unkeyed (not HMAC)

`PasswordAlgorithm::Sha256` is deliberately unkeyed SHA-256 with constant-time comparison, not HMAC-SHA-256.

An HMAC path would require a key, and that key has to come from somewhere. The candidates:

- **Sigil engine-startup config.** Reintroduces the "Sigil decides how credentials work" coupling that v2.0 exists to remove.
- **`KeepOps`.** Sigil's `KeepOps` capability is explicitly one-way: `store_secret` / `delete_secret`, and Sigil never reads secrets back. Fetching an HMAC key from Keep at verify time would break that doctrine.

Neither is acceptable. Meanwhile, HMAC's security value is defending against offline brute-force of low-entropy inputs. Machine credentials generated by `shroudb-crypto::generate_api_key` are 256-bit CSPRNG output — brute-force at 2^256 is not a threat. For that input, unkeyed SHA-256 with constant-time compare is cryptographically sufficient.

Schema validation enforces this: `algorithm == sha256` requires `min_length >= 32`. The algorithm cannot be attached to low-entropy fields where the HMAC rationale would apply.

If a use case later demands keyed verification of low-entropy machine credentials, a future `Sha256Hmac` variant can be added without breaking the current model — the decision above is about defaults, not permanence.

### Engine Resources

The only engine-wide credential knob left is `EngineResourceConfig`:

```toml
[engine_resources]
max_concurrent_hashes = 4  # default; Semaphore bounds concurrent Argon2id hashes
```

This is a process-wide memory bound on Argon2id — a resource limit, not a credential property. All other knobs that used to live on the removed `PasswordPolicy` (algorithm, length bounds, lockout thresholds) are now per-field on `CredentialPolicy`.

### Validation rules

- Multiple `credential` fields allowed (e.g., `password` + `recovery_key` + `api_key`).
- Mutual exclusion between `credential` / `pii` / `secret` / `index` / `inert` is structural — a field can only have one `kind`.
- `claim` only exists on `inert` and `index` variants — JWT claims are inappropriate on credential / PII / secret fields.
- `pii.searchable = true` requires Cipher + Veil capability (rejected at registration if missing).
- `CredentialPolicy.min_length > 0`; `max_length >= min_length` when both set; `LockoutPolicy.max_attempts > 0` and `duration_secs > 0`.
- `algorithm == sha256` requires `min_length >= 32`.
- Field names: alphanumeric + underscores only.

### Capability requirements

Schema registration is rejected if a `kind` requires an engine that isn't available. This is fail-closed: a `pii` field without Cipher capability is an error, not a silent plaintext store.

In standalone mode, only `inert`, `index`, and `credential` are available. `pii` / `secret` require the corresponding engines (Cipher, Veil, Keep) to be configured.

## Envelope Lifecycle

Sigil is entity-agnostic. The `ENVELOPE` commands work with any entity type. The `USER` commands are sugar that infer the credential field from the schema.

### Create

```sh
# Generic envelope
curl -X POST http://localhost:6500/sigil/myapp/users \
  -H "Content-Type: application/json" \
  -d '{"fields": {"entity_id": "alice", "email": "alice@example.com", "password": "correct-horse", "org_id": "acme", "name": "Alice"}}'

# Wire protocol (generic)
ENVELOPE CREATE myapp alice {"email":"alice@example.com","password":"correct-horse","org_id":"acme","name":"Alice"}

# Wire protocol (user sugar — identical behavior)
USER CREATE myapp alice {"email":"alice@example.com","password":"correct-horse","org_id":"acme","name":"Alice"}
```

Each field is routed to the appropriate handler based on its schema `kind`. Credential fields are hashed per their `CredentialPolicy` (Argon2id or Sha256) and stored separately. PII fields are encrypted via Cipher. The envelope record contains only non-sensitive field values.

All fields are written atomically. If any field fails (e.g., Cipher is unavailable for a PII field), the entire operation is rolled back.

### Import

Import an envelope with pre-hashed credential fields. Non-credential fields are processed normally (PII encrypted, indexes created, etc.). The credential value is treated as a hash — validated and stored directly, not hashed again.

```sh
curl -X POST http://localhost:6500/sigil/myapp/users/import \
  -H "Content-Type: application/json" \
  -d '{"fields": {"entity_id": "alice", "password": "$2b$12$saltsalt...", "org_id": "acme"}}'
```

Supported hash formats: Argon2id, Argon2i, Argon2d, bcrypt (`$2b$`/`$2a$`/`$2y$`), scrypt. On the next successful verify, non-Argon2id hashes are transparently rehashed.

Wire protocol: `ENVELOPE IMPORT <schema> <id> <json>` or `USER IMPORT <schema> <id> <json>`

### Per-Field Blind Mode

Individual fields in a create or update payload can be marked as blind. When a field includes `"blind": true`, Sigil skips server-side processing for that field and stores the pre-processed value directly. This enables client-side encryption and tokenization (end-to-end encryption) where the server never sees plaintext.

The blind wrapper is per-request, per-field. It is not part of the schema `kind`. The schema `kind` (`pii`, `pii` with `searchable: true`, `credential`) still defines what processing a field requires. The blind wrapper signals that the client has already performed that processing.

#### Blind wrapper format

```json
{"blind": true, "value": "<pre-processed value>"}
{"blind": true, "value": "<ciphertext>", "tokens": "<b64 BlindTokenSet>"}
```

#### Behavior per field `kind`

| Field `kind` | Blind `value` | Blind `tokens` | What's skipped |
|--------------|---------------|----------------|----------------|
| `pii` | CiphertextEnvelope string (from `shroudb-cipher-blind`) | — | Cipher.encrypt() |
| `pii` with `searchable: true` | CiphertextEnvelope string | Base64-encoded BlindTokenSet (from `shroudb-veil-blind`) | Cipher.encrypt() + Veil tokenization |
| `credential` | Pre-hashed credential string | — | Hashing step (same as import mode) |
| `inert` / `index` | Not allowed | — | Error: no processing to skip |

#### Mixed payloads

Blind and standard fields can coexist in the same request. Standard fields are processed normally by the server.

```sh
# Create with mixed blind and standard fields
curl -X POST http://localhost:6500/sigil/myapp/users \
  -H "Content-Type: application/json" \
  -d '{
    "fields": {
      "entity_id": "alice",
      "email": {"blind": true, "value": "<ciphertext>", "tokens": "<b64 BlindTokenSet>"},
      "name": {"blind": true, "value": "<ciphertext>"},
      "password": "correct-horse",
      "org_id": "acme"
    }
  }'
```

In this example, `email` and `name` are blind (client-encrypted), while `password` is hashed server-side and `org_id` is stored as a plaintext index -- all in the same request.

Wire protocol: blind fields use the same JSON format in `ENVELOPE CREATE`, `ENVELOPE UPDATE`, `USER CREATE`, and `USER UPDATE` payloads.

### Get

```sh
curl http://localhost:6500/sigil/myapp/users/alice
```

Returns the envelope record with non-sensitive fields. Credential fields are never returned.

### Update

```sh
curl -X PATCH http://localhost:6500/sigil/myapp/users/alice \
  -H "Content-Type: application/json" \
  -d '{"fields": {"name": "Alice Smith", "org_id": "newcorp"}}'
```

Updates non-credential fields. Credential fields cannot be updated through this endpoint — use credential change/reset instead.

### Delete

```sh
curl -X DELETE http://localhost:6500/sigil/myapp/users/alice
```

Deletes the envelope and all associated data (credentials, sessions).

### Verify (generic — explicit field)

```sh
# Wire protocol: explicit credential field
ENVELOPE VERIFY myapp svc1 api_key supersecretkey1
```

For multi-credential schemas or non-user entities, `ENVELOPE VERIFY` takes the credential field name explicitly. `USER VERIFY` infers it from the schema.

### Lookup

Look up an envelope by an indexed or searchable field value.

```sh
# HTTP
curl -X POST http://localhost:6500/sigil/myapp/lookup \
  -H "Content-Type: application/json" \
  -d '{"field": "email", "value": "alice@example.com"}'

# Wire protocol (generic)
ENVELOPE LOOKUP myapp email alice@example.com

# Wire protocol (user sugar)
USER LOOKUP myapp email alice@example.com
```

Returns the `entity_id` of the matching envelope. Follow up with `ENVELOPE GET` / `USER GET` if you need the full record.

## Authentication

### AUTH

When token-based auth is enabled, connections must authenticate before issuing protected commands.

```
AUTH <token>
```

### Login

```sh
curl -X POST http://localhost:6500/sigil/myapp/sessions \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "alice", "password": "correct-horse"}'
```

Returns:
```json
{
  "access_token": "eyJ...",
  "refresh_token": "a3f2...",
  "expires_in": 900
}
```

Wire protocol: `SESSION CREATE <schema> <id> <password> [META <json>]`

Fields whose `kind` (`inert` or `index`) carries a `claim` policy are automatically read from the entity's envelope and merged into the JWT access token. Enriched values (from the envelope) override any caller-provided META for the same key, ensuring authoritative fields like `role` always come from the database. Non-enriched META claims pass through as-is. If the claim policy sets `as_name`, the claim is emitted under that key instead of the field name.

### Login by Field

Login using a field value (e.g., email) instead of entity ID.

```sh
curl -X POST http://localhost:6500/sigil/myapp/sessions/login \
  -H "Content-Type: application/json" \
  -d '{"field": "email", "value": "alice@example.com", "password": "correct-horse"}'
```

Wire protocol: `SESSION LOGIN <schema> <field> <value> <password> [META <json>]`

### Refresh

```sh
curl -X POST http://localhost:6500/sigil/myapp/sessions/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "a3f2..."}'
```

Issues a new access token and rotates the refresh token. If the old refresh token is reused (indicating theft), the entire token family is revoked. Claim fields are re-read from the entity's current envelope on each refresh, so changes (e.g., role updates) take effect without requiring a full re-login.

### Logout

```sh
# Single session
curl -X DELETE http://localhost:6500/sigil/myapp/sessions \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "a3f2..."}'

# All sessions
curl -X DELETE http://localhost:6500/sigil/myapp/sessions \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "alice"}'
```

### JWKS

```sh
curl http://localhost:6500/sigil/myapp/.well-known/jwks.json
```

Returns the JSON Web Key Set for external token verification.

## Credential Management

### Password commands (sugar — infers credential field)

```sh
# Change (requires old password)
curl -X POST http://localhost:6500/sigil/myapp/password/change \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "alice", "old_password": "old-pw", "new_password": "new-pw"}'

# Reset (admin / reset token) — clears lockout
curl -X POST http://localhost:6500/sigil/myapp/password/reset \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "alice", "new_password": "new-pw"}'

# Import pre-hashed password
curl -X POST http://localhost:6500/sigil/myapp/password/import \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "alice", "hash": "$2b$12$..."}'
```

### Credential commands (generic — explicit field)

For schemas with multiple credential fields, or for non-user entities:

```sh
# Wire protocol
CREDENTIAL CHANGE myapp svc1 api_key old-key new-key
CREDENTIAL RESET myapp svc1 recovery_key new-recovery-key
CREDENTIAL IMPORT myapp svc1 api_key $argon2id$v=19$...
```

Accepts pre-hashed credentials in Argon2id, Argon2i, Argon2d, bcrypt, or scrypt format. On the next successful verify, non-Argon2id hashes are transparently rehashed.

## Account Lockout

Lockout is a per-field opt-in, carried as a `LockoutPolicy` on the credential field's `CredentialPolicy`. Presence of the policy enables lockout; absence disables it. There is no engine-global default — if you want lockout, declare it on the field.

```json
{ "name": "password", "field_type": "string",
  "kind": { "type": "credential",
            "lockout": { "max_attempts": 5, "duration_secs": 900 } } }
```

When enabled, after `max_attempts` failed credential verification attempts, the field is locked for `duration_secs`. Correct credential during lockout still returns locked. `CREDENTIAL RESET` / `PASSWORD RESET` clears lockout. Lockout state is per credential field — locking the `password` field does not affect the `recovery_key` field.

When disabled (no `lockout` sub-object on the credential field's kind), failed attempts are not counted, `locked_until` is never set, and `ACCOUNT_LOCKED` is never returned for that field — verify simply returns `VERIFICATION_FAILED` on a wrong value, regardless of how many times it's been wrong.

**When to enable lockout:** human-auth credentials — passwords, PINs, recovery keys typed by a person. Lockout mitigates online brute-force against a guessable secret.

**When to omit lockout:** machine-auth credentials — API keys, service tokens, signing secrets where the entity ID is the public half of the key (e.g., `key_id` + `key_secret`). With lockout on, an attacker who learns a tenant's `key_id` can lock that tenant out of production by hammering bad secrets against the verify endpoint. With lockout off, brute-force protection comes from the secret's entropy (a 32-byte random secret is not feasibly guessable) and from the rate-limiting layer in front of Sigil — not from the lockout state.

```sh
# API-key schema: high-entropy secret (sha256), no lockout
SCHEMA REGISTER api_keys '{"fields":[
  {"name":"key_secret", "field_type":"string",
   "kind":{"type":"credential","algorithm":"sha256"}},
  {"name":"client_id",  "field_type":"string",
   "kind":{"type":"index","claim":{"as_name":"sub"}}},
  {"name":"scopes",     "field_type":"string",
   "kind":{"type":"inert","claim":{}}}
]}'
```

### Migrating from v1 `lockout: bool`

The pre-v2.0 shape used `"lockout": true|false` on a `FieldAnnotations` bag. The `shroudb-sigil-cli SCHEMA MIGRATE` tool rewrites those to v2 form:

- `lockout: true` (or unset, since v1 defaulted to on) → `lockout: { max_attempts: 5, duration_secs: 900 }` (the pre-v2 implicit defaults, now explicit).
- `lockout: false` → `lockout` omitted.

This preserves observable behavior across upgrade. See the `v2.0.0` entry in `CHANGELOG.md` for operational steps.

## Envelope Recovery

Sigil does not implement a password reset workflow (token issuance, email delivery, single-use enforcement). Those are application-level concerns that depend on delivery mechanisms Sigil has no knowledge of. Instead, Sigil provides the primitives that any recovery workflow builds on.

### Recovery via a secondary credential

A schema can declare multiple credential fields. Each has independent lockout state. This lets a consumer verify identity through one credential and reset another.

```sh
# Schema with a recovery credential
SCHEMA REGISTER myapp {"fields":[
  {"name":"email",        "field_type":"string",
   "kind":{"type":"pii","searchable":true}},
  {"name":"password",     "field_type":"string",
   "kind":{"type":"credential",
           "lockout":{"max_attempts":5,"duration_secs":900}}},
  {"name":"recovery_key", "field_type":"string",
   "kind":{"type":"credential",
           "lockout":{"max_attempts":5,"duration_secs":900}}},
  {"name":"org_id",       "field_type":"string",
   "kind":{"type":"index"}}
]}
```

The recovery flow is two steps:

```sh
# 1. Verify identity via the recovery credential
ENVELOPE VERIFY myapp alice recovery_key user-recovery-key-value

# 2. Reset the primary credential (clears lockout)
CREDENTIAL RESET myapp alice password new-password
```

`CREDENTIAL RESET` replaces the hash without requiring the old value and clears any lockout on that field. It is gated by ACL config (or Sentry policy when configured).

### Recovery via application-issued token

When the consumer owns the proof-of-identity mechanism (email link, SMS OTP, admin action), the pattern is simpler — the consumer validates identity externally and calls reset directly:

```sh
# Consumer has already validated the reset token / OTP / admin approval
PASSWORD RESET myapp alice new-password
```

### What Sigil owns vs. what the consumer owns

| Concern | Owner |
|---------|-------|
| Credential hashing and storage | Sigil |
| Reset without old credential (`CREDENTIAL RESET`) | Sigil |
| Lockout clear on reset | Sigil |
| Per-field independent lockout | Sigil |
| ACL / policy gating on reset | Sigil (config or Sentry) |
| Proof of identity (token, OTP, recovery key verification) | Consumer |
| Token issuance and single-use enforcement | Consumer |
| Delivery mechanism (email, SMS, push) | Consumer |
| Deciding which recovery method to offer | Consumer |

## Security

- **Password plaintext:** zeroed from memory after hashing/verification
- **JWT private keys:** zeroed on drop
- **Core dumps:** disabled on Linux (prctl) and macOS (setrlimit)
- **CORS:** configurable allowed origins
- **CSRF:** Origin/Referer validation on POST requests
- **Rate limiting:** per-IP token bucket on credential-sensitive endpoints
- **Fail-closed:** PII fields without Cipher → write rejected, not stored plaintext

## CLI

The CLI connects over TCP (RESP3) and supports single-command and interactive modes.

```sh
# Connect to a specific server
shroudb-sigil-cli --addr 127.0.0.1:6499

# Single command
shroudb-sigil-cli HEALTH
shroudb-sigil-cli SCHEMA REGISTER myapp '{"fields":[{"name":"password","field_type":"string","kind":{"type":"credential"}}]}'
shroudb-sigil-cli USER CREATE myapp alice '{"password":"test12345678"}'
shroudb-sigil-cli USER VERIFY myapp alice test12345678
shroudb-sigil-cli SESSION CREATE myapp alice test12345678
shroudb-sigil-cli JWKS myapp
shroudb-sigil-cli PASSWORD CHANGE myapp alice test12345678 newpassword
shroudb-sigil-cli SESSION REVOKE ALL myapp alice
```

Interactive mode starts when no command is given:

```
$ shroudb-sigil-cli
sigil> HEALTH
OK
sigil> SCHEMA LIST
myapp
sigil> quit
```

JSON arguments with braces are preserved as single arguments (not split on whitespace).

## Rust Client SDK

```rust
use shroudb_sigil_client::SigilClient;

let mut client = SigilClient::connect("127.0.0.1:6499").await?;

// Schema
client.schema_register("myapp", schema_json).await?;
let schema = client.schema_get("myapp").await?;
let names = client.schema_list().await?;

// Users
let record = client.user_create("myapp", "alice", fields_json).await?;
let record = client.user_import("myapp", "alice", fields_with_hash).await?;
let record = client.user_get("myapp", "alice").await?;
let record = client.user_update("myapp", "alice", updates_json).await?;
client.user_delete("myapp", "alice").await?;
let valid = client.user_verify("myapp", "alice", "password").await?;

// Sessions
let tokens = client.session_create("myapp", "alice", "password", None).await?;
let tokens = client.session_refresh("myapp", &tokens.refresh_token).await?;
client.session_revoke("myapp", &tokens.refresh_token).await?;
let count = client.session_revoke_all("myapp", "alice").await?;
let sessions = client.session_list("myapp", "alice").await?;

// Password
client.password_change("myapp", "alice", "old", "new").await?;
client.password_reset("myapp", "alice", "new").await?;
let algo = client.password_import("myapp", "alice", "$2b$12$...").await?;

// JWT
let jwks = client.jwks("myapp").await?;
```

Response types:

- `TokenPair` — `access_token: String`, `refresh_token: String`, `expires_in: u64`
- `EnvelopeRecord` — `entity_id: String`, `fields: serde_json::Value`, `created_at: Option<u64>`, `updated_at: Option<u64>` (also re-exported as `UserRecord` for the `USER` sugar methods)
