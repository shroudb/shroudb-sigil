# Understanding Sigil

## For Everyone: What Sigil Does

Applications that handle credentials face a common problem: every field in a credential record needs different security treatment. Passwords need hashing. Email addresses need encryption. Some fields need to be searchable even while encrypted. API keys need versioned rotation. And the developer building the signup form shouldn't have to think about any of this.

**Sigil is a credential envelope engine.** You define a schema — the shape of your credential record — with annotations that describe what each field is. Sigil reads those annotations and applies the correct cryptographic treatment automatically:

- **Credentials** (passwords, API keys, recovery keys) are hashed with Argon2id, with lockout after failed attempts
- **PII** (email, phone, address) is encrypted at rest via the Cipher engine
- **Searchable PII** gets encrypted storage plus a blind index for querying
- **Secrets** (third-party tokens) get versioned storage with rotation via Keep
- **Everything else** is stored as-is

Sigil is entity-agnostic. The same schema annotations work for users, services, devices, or any entity that holds credentials. The generic `ENVELOPE` commands work with any entity type. The `USER` commands are sugar that infer the credential field — same engine underneath.

## End-to-End Encryption (Per-Field Blind Mode)

Sigil supports per-field blind mode, enabling true end-to-end encryption where the server never sees plaintext for sensitive fields. Clients perform encryption and tokenization locally using `shroudb-cipher-blind` and `shroudb-veil-blind`, then send the pre-processed results to Sigil.

When a field value is wrapped with `{"blind": true, "value": "..."}`, Sigil skips server-side processing and stores the pre-processed data directly. For searchable PII fields, the wrapper also includes `"tokens"` containing a pre-computed BlindTokenSet. Standard (non-blind) fields in the same record are processed normally by the server -- you can mix both in a single request.

This is a per-request, per-field decision, not a schema change. The schema annotations (`pii`, `searchable`, `credential`) still define what processing a field needs. The blind wrapper declares that the client has already performed that processing.

**Why this matters:** In the default mode, Sigil's server performs Cipher encryption and Veil tokenization -- the server sees field plaintext transiently. With blind mode, plaintext never leaves the client. The server stores and indexes opaque ciphertext and tokens. This is the difference between "encrypted at rest" and "end-to-end encrypted."

## For Technical Leaders: Architecture and Trade-offs

### The Problem

Building credential management requires stitching together password hashing, JWT signing, session management, PII encryption, and key rotation. Each of these is a distinct security concern, and getting any of them wrong creates a vulnerability. Teams either build this stack from scratch for every project or adopt an identity provider that owns their data model.

### What Sigil Is

Sigil is a **credential envelope engine** — not an identity provider, not an auth service. It protects and verifies credential shapes that you define. You keep ownership of your data model; Sigil applies cryptographic treatment per field based on schema annotations. Any entity — user, service, device — can be an envelope.

### Key Architectural Decisions

| Decision | Rationale |
|----------|-----------|
| **Schema-driven field routing** | Annotations on the schema definition determine treatment. No application code decides how to hash or encrypt — the schema is the source of truth. |
| **Entity-agnostic envelopes** | The same engine handles users, services, devices — any entity that holds credentials. `ENVELOPE` commands are generic; `USER` commands are sugar. |
| **Sigil owns domain crypto** | Credential hashing (Argon2id) and JWT signing (ES256) happen in Sigil, not in ShrouDB. ShrouDB is a generic KV store — it has no business knowing about passwords or JWTs. |
| **Multi-credential support** | Schemas can have multiple credential fields (e.g., password + recovery_key). `ENVELOPE VERIFY` takes an explicit field name; `USER VERIFY` infers the single credential field. |
| **Capability-aware integration** | Sigil works standalone (credential + index fields only) or with other engines (Cipher for PII, Veil for search, Keep for secrets). Fail-closed: missing capability = rejected write, not plaintext storage. |
| **All-or-nothing writes** | An envelope creation that touches multiple engines either protects every field or rejects the write entirely. Compensating deletes roll back partial writes. |
| **Dual protocol** | TCP (RESP3) for machine-to-machine and Moat embedding. HTTP (REST) for web applications. Same engine, same semantics. |

### Operational Model

- **Authentication:** JWT access tokens (ES256, configurable TTL) with family-based refresh token rotation and reuse detection.
- **Credential lifecycle:** Argon2id hashing, transparent rehash on verify (imported bcrypt/scrypt hashes upgraded automatically), account lockout after failed attempts. Per-field credential storage supports multiple credential fields per entity.
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
