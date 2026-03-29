# Understanding Sigil

## For Everyone: What Sigil Does

Applications that handle user credentials face a common problem: every field in a user profile needs different security treatment. Passwords need hashing. Email addresses need encryption. Some fields need to be searchable even while encrypted. API keys need versioned rotation. And the developer building the signup form shouldn't have to think about any of this.

**Sigil is a credential envelope engine.** You define a schema — the shape of your user record — with annotations that describe what each field is. Sigil reads those annotations and applies the correct cryptographic treatment automatically:

- **Passwords** are hashed with Argon2id, with lockout after failed attempts
- **PII** (email, phone, address) is encrypted at rest via the Cipher engine
- **Searchable PII** gets encrypted storage plus a blind index for querying
- **Secrets** (API keys, tokens) get versioned storage with rotation via Keep
- **Everything else** is stored as-is

The developer's API is: register a schema, create users, verify credentials, manage sessions. Sigil handles the rest.

## For Technical Leaders: Architecture and Trade-offs

### The Problem

Building credential management requires stitching together password hashing, JWT signing, session management, PII encryption, and key rotation. Each of these is a distinct security concern, and getting any of them wrong creates a vulnerability. Teams either build this stack from scratch for every project or adopt an identity provider that owns their user model.

### What Sigil Is

Sigil is a **credential envelope engine** — not an identity provider, not an auth service. It protects and verifies credential shapes that you define. You keep ownership of your user model; Sigil applies cryptographic treatment per field based on schema annotations.

### Key Architectural Decisions

| Decision | Rationale |
|----------|-----------|
| **Schema-driven field routing** | Annotations on the schema definition determine treatment. No application code decides how to hash or encrypt — the schema is the source of truth. |
| **Sigil owns domain crypto** | Password hashing (Argon2id) and JWT signing (ES256) happen in Sigil, not in ShrouDB. ShrouDB is a generic KV store — it has no business knowing about passwords or JWTs. |
| **Capability-aware integration** | Sigil works standalone (credential + index fields only) or with other engines (Cipher for PII, Veil for search, Keep for secrets). Fail-closed: missing capability = rejected write, not plaintext storage. |
| **All-or-nothing writes** | A user creation that touches multiple engines either protects every field or rejects the write entirely. Compensating deletes roll back partial writes. |
| **Dual protocol** | TCP (RESP3) for machine-to-machine and Moat embedding. HTTP (REST) for web applications. Same engine, same semantics. |

### Operational Model

- **Authentication:** JWT access tokens (ES256, configurable TTL) with family-based refresh token rotation and reuse detection.
- **Password lifecycle:** Argon2id hashing, transparent rehash on verify (imported bcrypt/scrypt hashes upgraded automatically), account lockout after failed attempts.
- **Key rotation:** Signing keys follow an active → draining → retired lifecycle. JWKS endpoint for external verification.
- **Durability:** ShrouDB v1 Store trait for persistence. Embedded mode (in-process ShrouDB) or remote mode (TCP to ShrouDB server).
- **Security:** Passwords and private keys zeroed from memory after use. Core dumps disabled. CORS, CSRF, and rate limiting on HTTP. Fail-closed on missing capabilities.

### Ecosystem

Sigil is one engine in the ShrouDB ecosystem:

- **ShrouDB** — encrypted versioned KV store (the foundation)
- **Sigil** — credential envelope (this engine)
- **Cipher** — encryption-as-a-service (PII field encryption)
- **Veil** — encrypted search (blind indexes for searchable PII)
- **Keep** — versioned secrets (API keys, tokens)
- **Forge** — certificate authority
- **Sentry** — authorization policy (post-verify enrichment)
- **Courier** — secure notifications
- **Chronicle** — audit events
- **Moat** — unified binary embedding all engines
