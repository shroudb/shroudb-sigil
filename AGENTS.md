# Sigil (formerly Auth) — Agent Instructions

> Schema-driven credential envelope engine: field-level crypto routing for passwords, PII, secrets, and searchable encrypted data with JWT session management.

## Quick Context

- **Role in ecosystem**: Credential domain layer on top of ShrouDB Store — bridges generic KV with auth-specific operations (hashing, JWT, envelope verification)
- **Deployment modes**: embedded | remote (TCP port 6499, HTTP port 6500)
- **Wire protocol**: RESP3 + HTTP REST
- **Backing store**: ShrouDB Store trait; delegates to Cipher (PII), Veil (search), Keep (secrets) via capability traits

## Workspace Layout

```
shroudb-sigil-core/      # Domain types: Schema, FieldAnnotations, CredentialRecord, TokenPair, errors
shroudb-sigil-engine/    # SigilEngine, CredentialManager, SessionManager, JwtManager, WriteCoordinator
shroudb-sigil-protocol/  # RESP3 command parsing + dispatch
shroudb-sigil-server/    # TCP + HTTP binary
shroudb-sigil-client/    # Typed Rust SDK
shroudb-sigil-cli/       # CLI tool
```

## RESP3 Commands

### Schema Commands

| Command | Args | Returns | Description |
|---------|------|---------|-------------|
| `SCHEMA REGISTER` | `<name> <json>` | `{status, version}` | Register schema; auto-creates 4 namespaces |
| `SCHEMA GET` | `<name>` | Schema JSON | Retrieve schema definition |
| `SCHEMA LIST` | — | `[names]` | List all schemas |

### Envelope Commands (generic — any entity type)

| Command | Args | Returns | Description |
|---------|------|---------|-------------|
| `ENVELOPE CREATE` | `<schema> <id> <json>` | `{status, entity_id, fields, created_at}` | Create with field routing |
| `ENVELOPE GET` | `<schema> <id>` | `{entity_id, fields, created_at, updated_at}` | Retrieve (credentials never returned) |
| `ENVELOPE IMPORT` | `<schema> <id> <json>` | Same as CREATE | Import with pre-hashed credentials |
| `ENVELOPE UPDATE` | `<schema> <id> <json>` | Same as CREATE | Update non-sensitive fields |
| `ENVELOPE DELETE` | `<schema> <id>` | `{status}` | Delete envelope + all related records |
| `ENVELOPE VERIFY` | `<schema> <id> <field> <value>` | `{status, valid}` | Verify credential (explicit field) |
| `ENVELOPE LOOKUP` | `<schema> <field> <value>` | `{status, entity_id}` | Find entity by index field |

### User Commands (sugar — infers credential field)

| Command | Args | Returns | Description |
|---------|------|---------|-------------|
| `USER CREATE` | `<schema> <id> <json>` | Same as ENVELOPE CREATE | Infers credential field from schema |
| `USER GET` | `<schema> <id>` | Same as ENVELOPE GET | |
| `USER IMPORT` | `<schema> <id> <json>` | Same as CREATE | Import pre-hashed password |
| `USER UPDATE` | `<schema> <id> <json>` | Same as CREATE | |
| `USER DELETE` | `<schema> <id>` | `{status}` | |
| `USER VERIFY` | `<schema> <id> <password>` | `{status, valid}` | Infers credential field |
| `USER LOOKUP` | `<schema> <field> <value>` | `{status, entity_id}` | |

### Session Commands

| Command | Args | Returns | Description |
|---------|------|---------|-------------|
| `SESSION CREATE` | `<schema> <id> <password> [META <json>]` | `{status, access_token, refresh_token, expires_in}` | Verify password + issue tokens |
| `SESSION LOGIN` | `<schema> <field> <value> <password> [META <json>]` | Same as CREATE | Login by field (e.g., email) |
| `SESSION REFRESH` | `<schema> <token>` | Same as CREATE | Rotate refresh token |
| `SESSION REVOKE` | `<schema> <token>` | `{status}` | Revoke single session |
| `SESSION REVOKE ALL` | `<schema> <id>` | `{status, revoked}` | Revoke all sessions for entity |
| `SESSION LIST` | `<schema> <id>` | Array of sessions | List active sessions |

### Credential / Password Commands

| Command | Args | Returns | Description |
|---------|------|---------|-------------|
| `CREDENTIAL CHANGE` | `<schema> <id> <field> <old> <new>` | `{status}` | Change (requires old value) |
| `CREDENTIAL RESET` | `<schema> <id> <field> <new>` | `{status}` | Force-reset (no old required) |
| `CREDENTIAL IMPORT` | `<schema> <id> <field> <hash> [META <json>]` | `{status, algorithm}` | Import pre-hashed |
| `PASSWORD CHANGE` | `<schema> <id> <old> <new>` | `{status}` | Sugar: infers field |
| `PASSWORD RESET` | `<schema> <id> <new>` | `{status}` | Sugar: infers field |
| `PASSWORD IMPORT` | `<schema> <id> <hash> [META <json>]` | `{status, algorithm}` | Sugar: infers field |
| `JWKS` | `<schema>` | `{keys: [...]}` | Public key set for JWT verification |

### Command Examples

```
> SCHEMA REGISTER myapp {"fields":[{"name":"password","field_type":"string","annotations":{"credential":true}},{"name":"email","field_type":"string","annotations":{"pii":true,"searchable":true}},{"name":"org_id","field_type":"string","annotations":{"index":true}}]}
{"status":"ok","version":1}

> USER CREATE myapp alice {"password":"s3cret","email":"alice@example.com","org_id":"acme"}
{"status":"ok","entity_id":"alice","fields":{"org_id":"acme"},"created_at":1711843200}

> SESSION CREATE myapp alice s3cret
{"status":"ok","access_token":"eyJ...","refresh_token":"abc123...","expires_in":900}
```

## HTTP REST API

Base path: `/sigil` on port 6500. All request/response bodies are JSON. Auth via `Authorization: Bearer <token>` header (optional when `auth.method` is not `"token"`).

Middleware stack: CORS → CSRF (POST only, Origin/Referer validation) → Rate Limit (token bucket per IP on write routes).

### Schema Routes

| Method | Path | Body | Response | Description |
|--------|------|------|----------|-------------|
| `POST` | `/sigil/schemas` | `{ name, fields: [FieldDef] }` | `201 { version }` | Register schema |
| `GET` | `/sigil/schemas/{name}` | — | `200 Schema` | Get schema definition |

### User Routes

| Method | Path | Body | Response | Description |
|--------|------|------|----------|-------------|
| `POST` | `/sigil/{schema}/users` | `{ fields: { entity_id, ... } }` | `201 { user_id, fields, created_at }` | Create user (rate-limited) |
| `POST` | `/sigil/{schema}/users/import` | `{ fields: { entity_id, ... } }` | `201 { user_id, fields, created_at }` | Import with pre-hashed credential (rate-limited) |
| `GET` | `/sigil/{schema}/users/{id}` | — | `200 { user_id, fields, created_at, updated_at }` | Get user |
| `PATCH` | `/sigil/{schema}/users/{id}` | `{ fields: { ... } }` | `200 UserRecord` | Update non-credential fields |
| `DELETE` | `/sigil/{schema}/users/{id}` | — | `200 { status: "deleted" }` | Delete user + all related records |

### Auth & Session Routes

| Method | Path | Body | Response | Description |
|--------|------|------|----------|-------------|
| `POST` | `/sigil/{schema}/verify` | `{ entity_id, password }` | `200 { valid }` | Verify password (rate-limited) |
| `POST` | `/sigil/{schema}/lookup` | `{ field, value }` | `200 UserRecord` | Lookup by indexed field (rate-limited) |
| `POST` | `/sigil/{schema}/sessions` | `{ entity_id, password, metadata? }` | `200 { access_token, refresh_token, expires_in }` | Create session (rate-limited) |
| `POST` | `/sigil/{schema}/sessions/login` | `{ field, value, password, metadata? }` | `200 TokenResponse` | Login by field value (rate-limited) |
| `POST` | `/sigil/{schema}/sessions/refresh` | `{ refresh_token }` | `200 TokenResponse` | Rotate refresh token |
| `DELETE` | `/sigil/{schema}/sessions` | `{ refresh_token? }` or `{ entity_id? }` | `200 { status }` | Revoke session(s) |
| `GET` | `/sigil/{schema}/sessions/{entity_id}` | — | `200 { sessions }` | List active sessions |

### Password Routes

| Method | Path | Body | Response | Description |
|--------|------|------|----------|-------------|
| `POST` | `/sigil/{schema}/password/change` | `{ entity_id, old_password, new_password }` | `200 { status }` | Change (requires old) (rate-limited) |
| `POST` | `/sigil/{schema}/password/reset` | `{ entity_id, new_password }` | `200 { status }` | Force-reset (rate-limited) |
| `POST` | `/sigil/{schema}/password/import` | `{ entity_id, hash }` | `200 { algorithm }` | Import pre-hashed (rate-limited) |

### JWKS & Health

| Method | Path | Body | Response | Description |
|--------|------|------|----------|-------------|
| `GET` | `/sigil/{schema}/.well-known/jwks.json` | — | `200 { keys }` | Public key set for JWT verification |
| `GET` | `/sigil/health` | — | `200 { status }` | Health check |

### HTTP Error Codes

| Status | Condition |
|--------|-----------|
| 400 | Validation error, missing field, bad input, import failed |
| 401 | Verification failed, invalid/expired token, token reuse |
| 403 | Access denied (ACL) |
| 404 | Entity/schema not found |
| 409 | Already exists |
| 429 | Account locked (too many failed attempts) or rate limit exceeded |
| 503 | Missing capability (Cipher/Veil/Keep not configured) |

### HTTP Example

```bash
# Register schema
curl -X POST http://localhost:6500/sigil/schemas \
  -H "Content-Type: application/json" \
  -d '{"name":"myapp","fields":[{"name":"password","field_type":"string","annotations":{"credential":true}},{"name":"email","field_type":"string","annotations":{"index":true}}]}'

# Create user
curl -X POST http://localhost:6500/sigil/myapp/users \
  -H "Content-Type: application/json" \
  -d '{"fields":{"entity_id":"alice","password":"s3cret","email":"alice@example.com"}}'

# Login
curl -X POST http://localhost:6500/sigil/myapp/sessions \
  -H "Content-Type: application/json" \
  -d '{"entity_id":"alice","password":"s3cret"}'
# → {"access_token":"eyJ...","refresh_token":"abc...","expires_in":900}
```

## Public API (Embedded Mode)

### Core Types

```rust
pub struct Schema { pub name: String, pub fields: Vec<FieldDef> }
pub struct FieldDef { pub name: String, pub field_type: FieldType, pub annotations: FieldAnnotations }
pub struct FieldAnnotations { pub credential: bool, pub pii: bool, pub searchable: bool, pub secret: bool, pub index: bool }
pub struct EnvelopeRecord { pub entity_id: String, pub fields: HashMap<String, Value>, pub created_at: u64, pub updated_at: u64 }
pub struct CredentialRecord { pub entity_id: String, pub hash: String, pub algorithm: PasswordAlgorithm, pub failed_attempts: u32, pub locked_until: Option<u64>, /* ... */ }
pub struct TokenPair { pub access_token: String, pub refresh_token: String, pub expires_in: u64 }
pub enum FieldTreatment { Credential, EncryptedPii, SearchableEncrypted, VersionedSecret, PlaintextIndex, Inert }
```

### Field Routing

```rust
// Routing determined by annotations:
credential=true                  → Argon2id hash (internal)
pii=true AND searchable=true     → Cipher encrypt + Veil blind index
pii=true                         → Cipher encrypt
secret=true                      → Keep versioned storage
index=true                       → Plaintext lookup index
(none)                           → Stored as-is (inert)
```

### Capability Traits

```rust
pub trait CipherOps: Send + Sync {
    fn encrypt(&self, plaintext: &[u8], context: Option<&str>) -> BoxFut<String>;
    fn decrypt(&self, ciphertext: &str, context: Option<&str>) -> BoxFut<SensitiveBytes>;
}
pub trait VeilOps: Send + Sync {
    fn put(&self, entry_id: &str, plaintext: &[u8], field: Option<&str>) -> BoxFut<()>;
    fn delete(&self, entry_id: &str) -> BoxFut<()>;
    fn search(&self, query: &str, field: Option<&str>, limit: Option<usize>) -> BoxFut<Vec<(String, f64)>>;
}
pub trait KeepOps: Send + Sync {
    fn store_secret(&self, path: &str, value: &[u8]) -> BoxFut<u64>;
    fn delete_secret(&self, path: &str) -> BoxFut<()>;
}
```

Missing capability = operation rejected (fail-closed). PII fields are never silently stored as plaintext.

## Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `server.tcp_bind` | `SocketAddr` | `"0.0.0.0:6499"` | RESP3 TCP endpoint |
| `server.http_bind` | `SocketAddr` | `"0.0.0.0:6500"` | REST HTTP endpoint |
| `auth.jwt_algorithm` | `String` | `"ES256"` | JWT signing algorithm |
| `auth.access_ttl` | `String` | `"15m"` | Access token lifetime |
| `auth.refresh_ttl` | `String` | `"30d"` | Refresh token lifetime |
| `cipher.addr` | `String` | — | Cipher server address (for PII) |
| `cipher.keyring` | `String` | — | Keyring name |
| `veil.addr` | `String` | — | Veil server address (for search) |
| `veil.index` | `String` | — | Index name |
| `keep.addr` | `String` | — | Keep server address (for secrets) |

## Data Model

Per schema `{name}`, four namespaces are auto-created:

| Namespace | Key | Value | Purpose |
|-----------|-----|-------|---------|
| `sigil.{schema}.envelopes` | `entity_id` | JSON `EnvelopeRecord` | Non-sensitive fields only |
| `sigil.{schema}.credentials` | `{entity_id}/{field_name}` | JSON `CredentialRecord` | Password hashes + lockout state |
| `sigil.{schema}.sessions` | refresh token (opaque) | JSON `RefreshTokenRecord` | Refresh token families |
| `sigil.{schema}.keys` | key_id (UUID) | JSON `SigningKeyRecord` | JWT signing keys |

Credential fields are **never** included in envelope GET responses. They are verify-only.

### Refresh Token Rotation

Tokens belong to families. On `SESSION REFRESH`:
1. If token state is `Rotated` (already used) → entire family revoked (theft detection)
2. Old token marked `Rotated`, new token issued with incremented generation
3. Same `family_id` links all tokens in the chain

## Common Mistakes

- `credential` and `pii` annotations are mutually exclusive — a field cannot be both
- `searchable` requires `pii=true` — you can't blind-index an unencrypted field
- `USER` commands require exactly one credential field in the schema; use `ENVELOPE` commands for multi-credential schemas
- Non-Argon2id hashes (bcrypt, scrypt) imported via `CREDENTIAL IMPORT` are transparently rehashed to Argon2id on first successful verify
- After 5 failed verification attempts (configurable), account is locked for 15 minutes
- WriteCoordinator uses compensating deletes for rollback — if Cipher encrypt succeeds but Veil put fails, the Cipher ciphertext is cleaned up

## Related Crates

| Crate | Relationship |
|-------|-------------|
| `shroudb-store` | Provides Store trait for envelope/credential/session persistence |
| `shroudb-cipher` | Encrypts PII fields via `CipherOps` trait |
| `shroudb-veil` | Creates blind indexes for searchable encrypted fields via `VeilOps` trait |
| `shroudb-keep` | Stores versioned secrets via `KeepOps` trait |
| `shroudb-sentry` | Optional policy evaluation via `PolicyEvaluator` trait |
| `shroudb-crypto` | Argon2id hashing, JWT signing, zeroization |
