# Sigil

A schema-driven credential envelope engine for [ShrouDB](https://github.com/shroudb/shroudb).

## What It Does

Sigil is not an auth service. It's a field-level crypto router. You register a credential schema with annotations, and Sigil applies the correct cryptographic treatment per field automatically.

```toml
# Register a schema
SCHEMA REGISTER myapp {
  "fields": [
    {"name": "email",    "field_type": "string", "annotations": {"pii": true, "searchable": true}},
    {"name": "password", "field_type": "string", "annotations": {"credential": true}},
    {"name": "org_id",   "field_type": "string", "annotations": {"index": true}}
  ]
}
```

Then `USER CREATE myapp alice {"email":"a@b.com","password":"secret","org_id":"acme"}` knows what to do with each field:

| Annotation | Treatment | Engine |
|-----------|-----------|--------|
| `credential` | Argon2id hash, verify, lockout | Sigil (internal) |
| `pii` | Encrypt at rest | Cipher |
| `pii` + `searchable` | Encrypt + blind index | Cipher + Veil |
| `secret` | Versioned secret storage | Keep |
| `index` | Plaintext lookup index | Sigil (internal) |

The developer's API surface is "store this user shape" and "verify this credential." Sigil routes fields to the right engines internally.

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
GET    /sigil/{schema}/users/{id}             — get user
PATCH  /sigil/{schema}/users/{id}             — update non-credential fields
DELETE /sigil/{schema}/users/{id}             — delete user
POST   /sigil/{schema}/verify                 — verify credentials
POST   /sigil/{schema}/sessions               — login (issue tokens)
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

```
SCHEMA REGISTER <name> <json>
SCHEMA GET <name>
SCHEMA LIST
USER CREATE <schema> <id> <json>
USER GET <schema> <id>
USER UPDATE <schema> <id> <json>
USER DELETE <schema> <id>
USER VERIFY <schema> <id> <password>
SESSION CREATE <schema> <id> <password> [META <json>]
SESSION REFRESH <schema> <token>
SESSION REVOKE <schema> <token>
SESSION REVOKE ALL <schema> <id>
SESSION LIST <schema> <id>
PASSWORD CHANGE <schema> <id> <old> <new>
PASSWORD RESET <schema> <id> <new>
PASSWORD IMPORT <schema> <id> <hash> [META <json>]
JWKS <schema>
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
- **Key rotation:** active → draining → retired lifecycle
- **Account lockout:** configurable failed attempt threshold + lockout duration
- **JWKS:** public key set for external JWT verification

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
shroudb-sigil-core/        — domain types (Schema, FieldAnnotations, etc.)
shroudb-sigil-engine/      — Store-backed engine (SigilEngine)
shroudb-sigil-protocol/    — RESP3 command parsing + dispatch
shroudb-sigil-server/      — Axum HTTP + TCP binary
shroudb-sigil-client/      — Rust client SDK (planned)
shroudb-sigil-cli/         — CLI tool (planned)
```

See [`protocol.toml`](protocol.toml) for the full protocol specification.

## License

MIT OR Apache-2.0
