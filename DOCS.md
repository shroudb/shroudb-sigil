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
| (none) | Stored as-is | — |

### Validation rules

- At most one `credential` field per schema
- `searchable` requires `pii`
- `credential` and `pii` are mutually exclusive (credentials are hashed, not encrypted)
- `credential` and `secret` are mutually exclusive
- Field names: alphanumeric + underscores only

### Capability requirements

Schema registration is rejected if annotations require engines that aren't available. This is fail-closed: a `pii: true` field without Cipher capability is an error, not a silent plaintext store.

In standalone mode, only `credential`, `index`, and unannotated fields are available. Other annotations require the corresponding engines (Cipher, Veil, Keep) to be configured.

## User Lifecycle

### Create

```sh
curl -X POST http://localhost:6500/sigil/myapp/users \
  -H "Content-Type: application/json" \
  -d '{"fields": {"user_id": "alice", "email": "alice@example.com", "password": "correct-horse", "org_id": "acme", "name": "Alice"}}'
```

Each field is routed to the appropriate handler based on schema annotations. Credential fields (password) are hashed with Argon2id and stored separately from the user record. PII fields are encrypted via Cipher. The user record contains only non-sensitive field values.

All fields are written atomically. If any field fails (e.g., Cipher is unavailable for a PII field), the entire operation is rolled back.

### Get

```sh
curl http://localhost:6500/sigil/myapp/users/alice
```

Returns the user record with non-sensitive fields. Credential fields are never returned.

### Update

```sh
curl -X PATCH http://localhost:6500/sigil/myapp/users/alice \
  -H "Content-Type: application/json" \
  -d '{"fields": {"name": "Alice Smith", "org_id": "newcorp"}}'
```

Updates non-credential fields. Credential fields cannot be updated through this endpoint — use password change/reset instead.

### Delete

```sh
curl -X DELETE http://localhost:6500/sigil/myapp/users/alice
```

Deletes the user and all associated data (credentials, sessions).

## Authentication

### Login

```sh
curl -X POST http://localhost:6500/sigil/myapp/sessions \
  -H "Content-Type: application/json" \
  -d '{"user_id": "alice", "password": "correct-horse"}'
```

Returns:
```json
{
  "access_token": "eyJ...",
  "refresh_token": "a3f2...",
  "expires_in": 900
}
```

### Refresh

```sh
curl -X POST http://localhost:6500/sigil/myapp/sessions/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "a3f2..."}'
```

Issues a new access token and rotates the refresh token. If the old refresh token is reused (indicating theft), the entire token family is revoked.

### Logout

```sh
# Single session
curl -X DELETE http://localhost:6500/sigil/myapp/sessions \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "a3f2..."}'

# All sessions
curl -X DELETE http://localhost:6500/sigil/myapp/sessions \
  -H "Content-Type: application/json" \
  -d '{"user_id": "alice"}'
```

### JWKS

```sh
curl http://localhost:6500/sigil/myapp/.well-known/jwks.json
```

Returns the JSON Web Key Set for external token verification.

## Password Management

### Change (requires old password)

```sh
curl -X POST http://localhost:6500/sigil/myapp/password/change \
  -H "Content-Type: application/json" \
  -d '{"user_id": "alice", "old_password": "old-pw", "new_password": "new-pw"}'
```

### Reset (admin / reset token)

```sh
curl -X POST http://localhost:6500/sigil/myapp/password/reset \
  -H "Content-Type: application/json" \
  -d '{"user_id": "alice", "new_password": "new-pw"}'
```

Clears any account lockout.

### Import (migration)

```sh
curl -X POST http://localhost:6500/sigil/myapp/password/import \
  -H "Content-Type: application/json" \
  -d '{"user_id": "alice", "hash": "$2b$12$..."}'
```

Accepts pre-hashed passwords in Argon2id, Argon2i, Argon2d, bcrypt, or scrypt format. On the next successful verify, non-Argon2id hashes are transparently rehashed.

## Account Lockout

After a configurable number of failed password attempts (default: 5), the account is locked for a configurable duration (default: 15 minutes). Correct password during lockout still returns locked. Password reset clears lockout.

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
