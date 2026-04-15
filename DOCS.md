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

[auth]
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

A schema defines the shape of a credential record. Each field has a type and optional annotations that determine how Sigil processes it.

### Registration

```sh
# HTTP
curl -X POST http://localhost:6500/sigil/schemas \
  -H "Content-Type: application/json" \
  -d '{
    "name": "myapp",
    "fields": [
      {"name": "email",    "field_type": "string", "annotations": {"pii": true, "searchable": true}},
      {"name": "password", "field_type": "string", "annotations": {"credential": true}},
      {"name": "org_id",   "field_type": "string", "annotations": {"index": true}},
      {"name": "name",     "field_type": "string"}
    ]
  }'

# Wire protocol
SCHEMA REGISTER myapp {"fields":[...]}
```

### Field annotations

| Annotation | Treatment | Requires |
|-----------|-----------|----------|
| `credential: true` | Argon2id hash, verify, change, lockout | — |
| `pii: true` | Encrypt at rest, decrypt on read | Cipher engine |
| `searchable: true` | Encrypted + blind index for search | Cipher + Veil engines |
| `secret: true` | Versioned secret with rotation | Keep engine |
| `index: true` | Plaintext lookup index | — |
| `claim: true` | Auto-include in JWT claims on session create/refresh | — |
| `lockout: false` | Disable failed-attempt lockout on a credential field. Default `true` | `credential: true` |
| (none) | Stored as-is | — |

### Validation rules

- Multiple `credential` fields allowed (e.g., password + recovery_key)
- `searchable` requires `pii`
- `credential` and `pii` are mutually exclusive (credentials are hashed, not encrypted)
- `credential` and `secret` are mutually exclusive
- `claim` is mutually exclusive with `credential`, `pii`, and `secret` (only index/inert field values can be included in JWTs)
- `lockout: false` is only valid on credential fields (lockout is meaningless without verify)
- Field names: alphanumeric + underscores only

### Capability requirements

Schema registration is rejected if annotations require engines that aren't available. This is fail-closed: a `pii: true` field without Cipher capability is an error, not a silent plaintext store.

In standalone mode, only `credential`, `index`, and unannotated fields are available. Other annotations require the corresponding engines (Cipher, Veil, Keep) to be configured.

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

Each field is routed to the appropriate handler based on schema annotations. Credential fields are hashed with Argon2id and stored separately. PII fields are encrypted via Cipher. The envelope record contains only non-sensitive field values.

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

The blind wrapper is per-request, per-field. It is not a schema annotation. The schema annotations (`pii`, `searchable`, `credential`) still define what processing a field requires. The blind wrapper signals that the client has already performed that processing.

#### Blind wrapper format

```json
{"blind": true, "value": "<pre-processed value>"}
{"blind": true, "value": "<ciphertext>", "tokens": "<b64 BlindTokenSet>"}
```

#### Behavior per field treatment

| Annotation | Blind `value` | Blind `tokens` | What's skipped |
|-----------|---------------|----------------|----------------|
| `pii` | CiphertextEnvelope string (from `shroudb-cipher-blind`) | — | Cipher.encrypt() |
| `pii` + `searchable` | CiphertextEnvelope string | Base64-encoded BlindTokenSet (from `shroudb-veil-blind`) | Cipher.encrypt() + Veil tokenization |
| `credential` | Pre-hashed credential string | — | Argon2id hashing (same as import mode) |
| (none) | Not allowed | — | Error: no processing to skip |

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

Returns the matching envelope record.

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

Fields annotated with `claim: true` in the schema are automatically read from the entity's envelope and merged into the JWT access token. Enriched values (from the envelope) override any caller-provided META for the same key, ensuring authoritative fields like `role` always come from the database. Non-enriched META claims pass through as-is.

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

Issues a new access token and rotates the refresh token. If the old refresh token is reused (indicating theft), the entire token family is revoked. Claim-annotated fields are re-read from the entity's current envelope on each refresh, so changes (e.g., role updates) take effect without requiring a full re-login.

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

After a configurable number of failed credential verification attempts (default: 5), the credential is locked for a configurable duration (default: 15 minutes). Correct credential during lockout still returns locked. Credential reset clears lockout. Lockout is per credential field — locking the `password` field doesn't affect the `recovery_key` field.

### Disabling lockout per field (`lockout: false`)

Lockout is on by default for every credential field. It can be disabled per field by setting `lockout: false` on the field's annotations. When disabled, failed attempts are not counted, `locked_until` is never set, and `ACCOUNT_LOCKED` is never returned for that field — verify simply returns `VERIFICATION_FAILED` on a wrong value, regardless of how many times it's been wrong.

**When to leave it on (the default):** human-auth credentials — passwords, PINs, recovery keys typed by a person. Lockout mitigates online brute-force against a guessable secret.

**When to turn it off:** machine-auth credentials — API keys, service tokens, signing secrets where the entity ID is the public half of the key (e.g., `key_id` + `key_secret`). With lockout on, an attacker who learns a tenant's `key_id` can lock that tenant out of production by hammering bad secrets against the verify endpoint. With lockout off, brute-force protection comes from the secret's entropy (a 32-byte random secret is not feasibly guessable) and from the rate-limiting layer in front of Sigil — not from the lockout state.

If `lockout: false` is set on a non-credential field, schema registration fails with `SCHEMA_VALIDATION` — lockout is meaningless without a verify path.

```sh
# API-key schema: high-entropy secret, lockout disabled
SCHEMA REGISTER api_keys '{"fields":[
  {"name":"key_secret", "field_type":"string", "annotations":{"credential":true, "lockout":false}},
  {"name":"client_id",  "field_type":"string", "annotations":{"index":true, "claim":true}},
  {"name":"scopes",     "field_type":"string", "annotations":{"claim":true}}
]}'
```

## Envelope Recovery

Sigil does not implement a password reset workflow (token issuance, email delivery, single-use enforcement). Those are application-level concerns that depend on delivery mechanisms Sigil has no knowledge of. Instead, Sigil provides the primitives that any recovery workflow builds on.

### Recovery via a secondary credential

A schema can declare multiple credential fields. Each has independent lockout state. This lets a consumer verify identity through one credential and reset another.

```sh
# Schema with a recovery credential
SCHEMA REGISTER myapp {"fields":[
  {"name":"email",        "field_type":"string", "annotations":{"pii":true,"searchable":true}},
  {"name":"password",     "field_type":"string", "annotations":{"credential":true}},
  {"name":"recovery_key", "field_type":"string", "annotations":{"credential":true}},
  {"name":"org_id",       "field_type":"string", "annotations":{"index":true}}
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
shroudb-sigil-cli SCHEMA REGISTER myapp '{"fields":[{"name":"password","field_type":"string","annotations":{"credential":true}}]}'
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
- `UserRecord` — `user_id: String`, `fields: serde_json::Value`, `created_at: Option<u64>`, `updated_at: Option<u64>`
