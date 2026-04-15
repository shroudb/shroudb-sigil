# Sigil

A schema-driven credential envelope engine for [ShrouDB](https://github.com/shroudb/shroudb).

## What It Does

Sigil is not an auth service. It's a field-level crypto router. You register a credential schema where each field carries a `kind` — a tagged `FieldKind` variant — and Sigil applies the correct cryptographic treatment per field automatically.

```toml
# Register a schema
SCHEMA REGISTER myapp {
  "fields": [
    {"name": "email",    "field_type": "string", "kind": {"type": "pii", "searchable": true}},
    {"name": "password", "field_type": "string", "kind": {"type": "credential", "lockout": {"max_attempts": 5, "duration_secs": 900}}},
    {"name": "org_id",   "field_type": "string", "kind": {"type": "index"}},
    {"name": "role",     "field_type": "string", "kind": {"type": "index", "claim": {}}}
  ]
}
```

Then `USER CREATE myapp alice {"email":"a@b.com","password":"secret","org_id":"acme","role":"admin"}` knows what to do with each field:

| `FieldKind` variant | Treatment | Engine |
|---------------------|-----------|--------|
| `credential` | Per-field `CredentialPolicy`: algorithm (Argon2id or Sha256), length bounds, optional lockout | Sigil (internal) |
| `pii` | Encrypt at rest | Cipher |
| `pii` with `searchable: true` | Encrypt + blind index | Cipher + Veil |
| `secret` | Versioned secret storage | Keep |
| `index` | Plaintext lookup index | Sigil (internal) |
| `inert` / `index` with `claim` | Auto-include field value in JWT claims on login/refresh (optionally renamed via `as_name`) | Sigil (internal) |

Credential policy is per-field. One schema can carry a human `password` (Argon2id + lockout) and a machine `api_key` (Sha256 + no lockout) side by side. Omit the `lockout` sub-object on a `credential` field to disable failed-attempt lockout — appropriate for API keys and service tokens where lockout is a denial-of-service vector.

For high-entropy machine credentials, use `"algorithm": "sha256"` on the credential field. Sigil validates `min_length >= 32` on that algorithm so it can't be attached to low-entropy inputs — see `DOCS.md` for the unkeyed-SHA-256 vs. HMAC rationale.

The developer's API surface is "store this entity shape" and "verify this credential." Sigil routes fields to the right engines internally.

## Quick Start

```sh
# Build and run (dev mode — ephemeral master key)
cargo run

# Or with a master key for durable storage
export SHROUDB_MASTER_KEY="$(openssl rand -hex 32)"
cargo run
```

Sigil listens on TCP port 6499 (RESP3 wire protocol) and HTTP port 6500 (REST API).

## HTTP API

```
POST   /sigil/schemas                        — register schema
GET    /sigil/schemas/{name}                  — get schema definition
POST   /sigil/{schema}/users                  — create user
POST   /sigil/{schema}/users/import           — import user with pre-hashed credentials
GET    /sigil/{schema}/users/{id}             — get user
PATCH  /sigil/{schema}/users/{id}             — update non-credential fields
DELETE /sigil/{schema}/users/{id}             — delete user
POST   /sigil/{schema}/verify                 — verify credentials
POST   /sigil/{schema}/lookup                 — lookup by indexed field
POST   /sigil/{schema}/sessions               — login (issue tokens)
POST   /sigil/{schema}/sessions/login         — login by field value (e.g., email)
DELETE /sigil/{schema}/sessions               — logout
POST   /sigil/{schema}/sessions/refresh       — refresh tokens
GET    /sigil/{schema}/sessions/{user_id}     — list sessions
POST   /sigil/{schema}/password/change        — change password
POST   /sigil/{schema}/password/reset         — reset password
POST   /sigil/{schema}/password/import        — import pre-hashed password
GET    /sigil/{schema}/.well-known/jwks.json  — JWKS
GET    /sigil/health                          — health check
```

## Wire Protocol (RESP3)

### Schema

```
SCHEMA REGISTER <name> <json>
SCHEMA GET <name>
SCHEMA LIST
```

### Envelope (generic -- any entity type)

```
ENVELOPE CREATE <schema> <id> <json>
ENVELOPE GET <schema> <id>
ENVELOPE IMPORT <schema> <id> <json>
ENVELOPE UPDATE <schema> <id> <json>
ENVELOPE DELETE <schema> <id>
ENVELOPE VERIFY <schema> <id> <field> <value>
ENVELOPE LOOKUP <schema> <field> <value>
```

### User (sugar -- infers credential field from schema)

```
USER CREATE <schema> <id> <json>
USER IMPORT <schema> <id> <json>
USER GET <schema> <id>
USER UPDATE <schema> <id> <json>
USER DELETE <schema> <id>
USER VERIFY <schema> <id> <password>
USER LOOKUP <schema> <field> <value>
```

### Session

```
SESSION CREATE <schema> <id> <password> [META <json>]
SESSION LOGIN <schema> <field> <value> <password> [META <json>]
SESSION REFRESH <schema> <token>
SESSION REVOKE <schema> <token>
SESSION REVOKE ALL <schema> <id>
SESSION LIST <schema> <id>
```

### Credential (generic -- explicit field)

```
CREDENTIAL CHANGE <schema> <id> <field> <old> <new>
CREDENTIAL RESET <schema> <id> <field> <new>
CREDENTIAL IMPORT <schema> <id> <field> <hash> [META <json>]
```

### Password (sugar -- infers credential field)

```
PASSWORD CHANGE <schema> <id> <old> <new>
PASSWORD RESET <schema> <id> <new>
PASSWORD IMPORT <schema> <id> <hash> [META <json>]
```

### JWT and Operational

```
JWKS <schema>
AUTH <token>
HEALTH
```

## Configuration

```sh
shroudb-sigil --config config.toml
```

| Setting | CLI flag | Env var | Default |
|---------|----------|---------|---------|
| Config file | `--config` | `SIGIL_CONFIG` | — |
| Master key | — | `SHROUDB_MASTER_KEY` | ephemeral (dev) |
| Master key file | — | `SHROUDB_MASTER_KEY_FILE` | — |
| Data directory | `--data-dir` | `SIGIL_DATA_DIR` | `./sigil-data` |
| TCP bind | `--tcp-bind` | `SIGIL_TCP_BIND` | `0.0.0.0:6499` |
| HTTP bind | `--http-bind` | `SIGIL_HTTP_BIND` | `0.0.0.0:6500` |
| Log level | `--log-level` | `SIGIL_LOG_LEVEL` | `info` |

## Session Lifecycle

- **Access tokens:** JWT (ES256), configurable TTL (default 15m)
- **Refresh tokens:** opaque, family-based rotation with reuse detection
- **Claim enrichment:** `inert` and `index` fields carrying a `claim` policy are auto-included in JWT claims from the entity's envelope on both login and refresh. Enriched values always reflect the current envelope state, so role changes take effect on the next refresh without re-login. Use `claim: { as_name: "sub" }` to rename the claim key.
- **Key rotation:** active → draining → retired lifecycle
- **Account lockout:** per-field, set via `CredentialPolicy.lockout`. Omit to disable.
- **JWKS:** public key set for external JWT verification

## Per-Field Blind Mode

Sigil supports per-field blind mode in `ENVELOPE CREATE` and `ENVELOPE UPDATE` payloads (and their `USER` sugar equivalents). When a field value is wrapped with a blind object, Sigil skips server-side processing for that field and stores the pre-processed data directly.

This lets clients perform encryption and tokenization locally (e.g., via `shroudb-cipher-blind` and `shroudb-veil-blind`) and send the results to Sigil without the server touching plaintext.

```json
{
  "fields": {
    "entity_id": "alice",
    "email": {"blind": true, "value": "<ciphertext>", "tokens": "<b64 BlindTokenSet>"},
    "name": {"blind": true, "value": "<ciphertext>"},
    "role": "admin"
  }
}
```

The blind wrapper is per-request, per-field -- not part of the schema `kind`. The schema `FieldKind` still defines what processing a field needs. The blind wrapper says "I already did that processing." Standard (non-blind) fields in the same record are processed normally.

| Field `kind` | Blind behavior |
|--------------|----------------|
| `pii` | `value` is a CiphertextEnvelope string; Cipher.encrypt() skipped |
| `pii` with `searchable: true` | `value` is ciphertext + `tokens` is base64-encoded BlindTokenSet; Cipher and Veil skipped |
| `credential` | `value` is pre-hashed; same as import mode |
| `inert` / `index` | Cannot use blind -- no processing to skip |

## Password Import

Sigil accepts pre-hashed passwords for migration from existing systems:

```
PASSWORD IMPORT myapp user1 "$2b$12$saltsaltsaltsaltsaltsOhash..."
```

Supported formats: Argon2id, Argon2i, Argon2d, bcrypt, scrypt. On the next successful verify, non-Argon2id hashes are transparently rehashed to Argon2id.

## Security

- Passwords zeroed from memory after hashing/verification (zeroize)
- JWT private keys zeroed on drop
- Core dumps disabled (Linux + macOS)
- CORS, CSRF, and per-IP rate limiting on all HTTP endpoints
- Fail-closed: PII fields without Cipher capability → rejected, not silently stored plaintext

## Architecture

```
shroudb-sigil-core/        — domain types (Schema, FieldKind, CredentialPolicy, etc.)
shroudb-sigil-engine/      — Store-backed engine (SigilEngine)
shroudb-sigil-protocol/    — RESP3 command parsing + dispatch
shroudb-sigil-server/      — Axum HTTP + TCP binary
shroudb-sigil-client/      — Rust client SDK
shroudb-sigil-cli/         — CLI tool (single command + interactive REPL, incl. SCHEMA MIGRATE)
```

See [`protocol.toml`](protocol.toml) for the full protocol specification.

## CLI

```sh
# Single command
shroudb-sigil-cli HEALTH
shroudb-sigil-cli SCHEMA REGISTER myapp '{"fields":[...]}'
shroudb-sigil-cli USER CREATE myapp alice '{"password":"secret","org":"acme"}'
shroudb-sigil-cli SESSION CREATE myapp alice secret

# Interactive REPL
shroudb-sigil-cli
sigil> HEALTH
OK
sigil> USER VERIFY myapp alice secret
valid
sigil> quit
```

## Rust Client SDK

```rust
use shroudb_sigil_client::SigilClient;

let mut client = SigilClient::connect("127.0.0.1:6499").await?;

client.schema_register("myapp", serde_json::json!({
    "fields": [
        {"name": "password", "field_type": "string", "kind": {"type": "credential"}},
        {"name": "org", "field_type": "string", "kind": {"type": "index"}}
    ]
})).await?;

client.user_create("myapp", "alice", serde_json::json!({
    "password": "correct-horse", "org": "acme"
})).await?;

let tokens = client.session_create("myapp", "alice", "correct-horse", None).await?;
println!("JWT: {}", tokens.access_token);
```

## License

MIT OR Apache-2.0
