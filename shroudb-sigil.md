# Sigil — ShrouDB Repository Analysis

**Component:** shroudb-sigil  
**Type:** Engine (6-crate workspace: domain types, engine, RESP3 protocol, HTTP+TCP server binary, Rust client SDK, CLI)  
**Language:** Rust (edition 2024, MSRV 1.92)  
**License:** MIT OR Apache-2.0  
**Published:** Private registry (`shroudb` at crates.shroudb.dev), Docker images (amd64/aarch64)  
**Analyzed:** /Users/nlucas/dev/shroudb/shroudb-sigil

---

## Role in Platform

Sigil is the credential envelope engine — a field-level crypto router. Developers register a schema with field annotations (`credential`, `pii`, `searchable`, `secret`, `index`), and Sigil automatically routes each field to the correct cryptographic treatment: Argon2id hashing, Cipher encryption, Veil blind indexing, Keep versioned secret storage, or plaintext lookup. Without Sigil, applications must manually orchestrate per-field crypto across multiple engines, defeating the platform's "declare intent, not implementation" contract. Sigil also owns the session lifecycle (JWT signing, refresh token rotation with reuse detection) and password policy enforcement (lockout, transparent rehashing).

---

## Behavioral Surface

### Public API

**RESP3 Wire Protocol (TCP :6499)** — 32 commands across 7 categories:
- **Schema:** REGISTER, GET, LIST
- **Envelope (generic):** CREATE, GET, IMPORT, UPDATE, DELETE, VERIFY, LOOKUP
- **User (sugar, infers credential field):** CREATE, GET, IMPORT, UPDATE, DELETE, VERIFY, LOOKUP
- **Session:** CREATE, CREATE-BY-FIELD, REFRESH, REVOKE, REVOKE ALL, LIST
- **Credential (generic, explicit field):** CHANGE, RESET, IMPORT
- **Password (sugar):** CHANGE, RESET, IMPORT
- **JWT/Ops:** JWKS, HEALTH, AUTH

**HTTP REST API (Axum :6500)** — 20+ routes under `/sigil/`:
- Rate-limited: user create/import, verify, lookup, session create/login, password change/reset/import
- Open: schema register/get, user get/update/delete, session refresh/revoke/list, JWKS, health

**Embedded API (library crate)** — `SigilEngine<S: Store>` generic over Store trait, 30+ async methods mirroring the wire commands.

**Client SDK** — `SigilClient` with typed async methods over TCP RESP3.

**CLI** — Single-command and interactive modes via `shroudb-sigil-cli`.

### Core operations traced

**1. Envelope Create (all-or-nothing write)**
`WriteCoordinator::create_envelope` → validates required fields against schema → iterates fields, routing each by annotation: `credential` → `CredentialManager::set_credential` (Argon2id hash via semaphore-limited pool) → `pii` → `CipherOps::encrypt` (base64 → remote Cipher) → `searchable` → Cipher encrypt + `VeilOps::put` (blind index) → `secret` → `KeepOps::store_secret` → `index` → plaintext Store write → collects `CompensatingOp` for each completed step → emits Chronicle audit event (fail-closed) → writes envelope record → on failure, executes all compensating DELETEs in reverse.

Blind mode variant: client submits `{"blind": true, "value": "<ciphertext>", "tokens": "<BlindTokenSet>"}` — Sigil stores pre-encrypted value and forwards pre-computed blind tokens to Veil without seeing plaintext.

**2. Session Create (login + JWT issuance)**
`SigilEngine::session_create` → `CredentialManager::verify` (Argon2id verify with lockout check; transparent rehash if legacy algorithm) → `SessionManager::create_session` → `JwtManager::ensure_active_key` (create ES256 key if none) → `JwtManager::sign` (PKCS8 private key, iat/exp claims) → generate opaque refresh token → store `RefreshTokenRecord` with family_id + generation 0 → return `TokenPair`.

**3. Session Refresh (token rotation with reuse detection)**
`SessionManager::refresh` → look up refresh token record → if `Active`: mark as `Rotated`, generate new token in same family with generation+1 → if `Rotated` (reuse detected): revoke entire token family, return `TokenReuse` error → if `Revoked`/expired: reject.

### Capability gating

Engine capabilities are optional trait objects in `Capabilities` struct: `cipher: Option<Box<dyn CipherOps>>`, `veil: Option<Box<dyn VeilOps>>`, `keep: Option<Box<dyn KeepOps>>`, `sentry: Option<Arc<dyn PolicyEvaluator>>`, `chronicle: Option<Arc<dyn ChronicleOps>>`. Schema registration is rejected if field annotations require a missing capability (fail-closed). No feature flags or license checks — gating is purely capability presence.

---

## Cryptographic Constructs

**Password hashing:** Argon2id v19 (default parameters from `argon2` 0.5 crate). OsRng salt generation. Semaphore-limited concurrent hashes (default 4, ~64 MiB each). Supports import of Argon2i, Argon2d, bcrypt ($2a$/$2b$/$2y$), and scrypt hashes. Transparent rehash to Argon2id on successful verification of non-Argon2id hashes.

**JWT signing:** ES256 (ECDSA P-256) via `shroudb-crypto` / `ring` 0.17. Keys stored as PKCS8 in Store namespace `sigil.{schema}.keys`. Key lifecycle: Active → Draining → Retired. Verification tries all non-retired keys. 30-second expiry leeway. JWKS endpoint exposes public keys.

**Envelope encryption (delegated):** PII fields encrypted via Cipher with context string `{schema}/{entity_id}/{field_name}` for per-field unique keys. Sigil never decrypts on the read path — PII fields returned as `"[encrypted]"`.

**Blind indexing (delegated):** Searchable fields get both Cipher encryption and Veil blind index entries. Supports client-side blind mode where pre-encrypted values and pre-computed blind tokens are passed through without Sigil seeing plaintext.

**Secret storage (delegated):** Secret fields forwarded to Keep under path `{schema}/{entity_id}/{field_name}`. Sigil never reads secrets back. Bytes zeroized after store.

**Zeroization:** Password bytes zeroized after hashing. PKCS8 private key bytes zeroized on drop. Secret field bytes zeroized after Keep storage. Uses `zeroize` 1.x with derive feature.

**Core dump mitigation:** `shroudb_crypto::disable_core_dumps()` called at server startup.

**Master key:** Chained source: env var (`SHROUDB_MASTER_KEY`) → file (`SHROUDB_MASTER_KEY_FILE`) → ephemeral (random, dev-only).

---

## Engine Relationships

### Calls out to

- **Cipher** — TCP client (`shroudb-cipher-client`). Encrypt/decrypt PII fields. Fresh connection per operation.
- **Veil** — TCP client (`shroudb-veil-client`, `shroudb-veil-blind`). Blind index put/delete/search. Standard and blind modes.
- **Keep** — TCP client (`shroudb-keep-client`). Versioned secret store/delete.
- **Chronicle** — Via `ChronicleOps` trait. Audit event emission on create/update/delete. Fail-closed.
- **shroudb-store** — Abstract Store trait for all persistent state.
- **shroudb-storage** — `EmbeddedStore` implementation (in-process storage backend).
- **shroudb-crypto** — JWT signing primitives, key generation, core dump disable.

### Called by

- **Moat** — Planned embedding via `SigilEngine` + `Capabilities` wiring. Not yet implemented; blocked on engine v1 completions.
- **shroudb-codegen** — Reads `protocol.toml` for code generation.
- **Any application** — Via TCP RESP3, HTTP REST, or Rust client SDK.

### Sentry / ACL integration

**shroudb-acl wired:** Yes. `ServerAuthConfig` from `shroudb-acl` handles token-based auth. `check_dispatch_acl` enforced before every command dispatch (both TCP and HTTP). Commands declare `AclRequirement`: None (health, JWKS), Admin (schema register), or Namespace+Scope (read/write on `sigil.{schema}.*`).

**Sentry PolicyEvaluator:** `WriteCoordinator::check_policy` calls `sentry.evaluate()` on create/update/delete with principal/resource/action request. Optional — skipped if not configured.

**Sentry session enrichment:** Defined in `ENGINE_INTEGRATION.md` but not yet wired. Would merge authorization grants into JWT claims after credential verification.

---

## Store Trait

Sigil is generic over `Store` from `shroudb-store`. The server binary uses `EmbeddedStore` from `shroudb-storage` (in-process). Config supports `mode = "embedded"` (default) or `mode = "remote"` (not yet implemented). No migration code exists. Schema registration is idempotent. Data organized into namespaces: `sigil.{schema}.envelopes`, `sigil.{schema}.credentials`, `sigil.{schema}.indexes`, `sigil.{schema}.sessions`, `sigil.{schema}.keys`.

---

## Licensing Tier

**Tier:** Open core (MIT OR Apache-2.0)

All six crates are MIT OR Apache-2.0. No feature flags fence commercial behavior. No capability traits gate paid features — capability presence is purely about which sibling engines are deployed. The commercial value is platform-level (Moat bundling, engine ecosystem, managed hosting), not component-level. Published to private registry (`shroudb` at crates.shroudb.dev), not crates.io.

---

## Standalone Extractability

**Extractable as independent product:** Yes, with caveats.

Sigil standalone handles `credential` and `index`/`inert` annotations without any sibling engines — this covers password hashing, JWT sessions, envelope CRUD, and plaintext lookups. This is a functional identity/credential management system on its own.

PII encryption, searchable encryption, and versioned secret storage require Cipher, Veil, and Keep respectively. Without them, schemas using those annotations are rejected at registration (fail-closed). The trait-based capability pattern means alternative implementations could be wired without forking Sigil.

Extracting Sigil requires bringing `shroudb-store`, `shroudb-storage`, `shroudb-crypto`, `shroudb-acl`, `shroudb-protocol-wire`, and `shroudb-server-tcp` as dependencies — all from the private registry.

### Target persona if standalone

Backend teams building applications that need schema-driven credential management with per-field crypto treatment. Companies migrating off DIY auth (bcrypt + manual JWT) who want declarative field-level security without adopting a full identity platform. B2B SaaS needing multi-tenant credential isolation.

### Pricing model fit if standalone

Open core + support tier. The standalone credential/session engine is the open-core offering. Commercial value accrues from: managed hosting, Moat bundle (all engines), enterprise support SLAs, and the engine ecosystem (Cipher, Veil, Keep integration).

---

## Deployment Profile

**Standalone binary:** Multi-arch Docker images (Alpine, non-root, amd64/aarch64). Dual protocol: TCP RESP3 (:6499) + HTTP REST (:6500). Self-hostable with embedded storage — single binary, single data directory.

**Library crate:** `SigilEngine<S>` embeddable in any Rust binary. Moat integration path defined but not yet implemented.

**Infrastructure dependencies:** Embedded storage requires only filesystem. Remote engines (Cipher, Veil, Keep) optional — needed only for PII/searchable/secret field annotations. Chronicle optional for audit. No database, no external queue, no Redis.

**Self-hostable without expertise:** Yes for basic credential management. Engine integration (Cipher/Veil/Keep) requires deploying and configuring those engines.

---

## Monetization Signals

**Rate limiting:** Per-IP token bucket on sensitive HTTP endpoints (user create, login, password operations). Configurable burst/rate.

**Account lockout:** Policy-driven (max_failed_attempts, lockout_duration_secs). Per-entity, not global.

**Tenant scoping:** `tenant_override` field present in command parsing. ACL tokens carry tenant identity. Namespace isolation per schema.

**Quota enforcement:** Not present. No usage counters, API key quotas, or billing hooks.

**API key validation:** Token-based auth via `shroudb-acl`. Static tokens in config with tenant/actor/grants. No dynamic API key management.

---

## Architectural Moat (Component-Level)

**Schema-driven field routing:** The core abstraction — declare field annotations, get correct crypto treatment automatically — is non-trivial to reproduce correctly. The combinatorial explosion (credential + pii mutual exclusion, searchable requiring pii, blind mode variants, all-or-nothing writes with compensating operations) encodes hard-won design decisions.

**All-or-nothing write coordinator:** Multi-engine transactional writes with compensating rollback across Store, Cipher, Veil, and Keep. The compensating operation pattern with fail-closed audit is operationally complex to get right.

**Token rotation with family-based reuse detection:** The generation-tracked refresh token family with automatic family revocation on reuse is a well-implemented security primitive that most auth libraries get wrong or skip.

**Transparent credential migration:** Import bcrypt/scrypt/argon2i hashes, automatically rehash to Argon2id on next successful verify. Zero-downtime migration from legacy auth systems.

**Per-field blind mode:** Client-side encryption with pre-computed blind tokens forwarded opaquely. Enables true end-to-end encryption where Sigil never sees plaintext — rare in credential management systems.

The moat is partially platform-level (Cipher/Veil/Keep ecosystem) and partially component-level (write coordinator, blind mode, credential migration).

---

## Gaps and Liabilities

**Read-path decryption not wired:** `envelope_get` / `user_get` returns `"[encrypted]"` for PII fields. No `ReadCoordinator` or decryption pass exists. Acknowledged in `ENGINE_INTEGRATION.md`.

**Remote Store mode not implemented:** Config accepts `mode = "remote"` but the code path doesn't exist.

**Sentry session enrichment not wired:** Trait defined, integration point documented, but `session_create` doesn't call Sentry for JWT claim enrichment.

**No schema evolution:** Schemas are immutable after registration. No migration path for adding/removing/renaming fields. Schema changes require a new schema name.

**No CHANGELOG:** Version history not tracked in repo. Commit history is the only record.

**No LICENSE file:** License declared in `Cargo.toml` but no LICENSE-MIT or LICENSE-APACHE-2.0 files in the repo root.

**No connection pooling for remote engines:** Fresh TCP connection per Cipher/Veil/Keep operation. Fine for low throughput; bottleneck under load.

**Private registry dependency:** All `shroudb-*` crates come from `crates.shroudb.dev`. External consumers cannot build without registry access.

**`deny.toml` advisory ignores:** RUSTSEC-2023-0071 (RSA Marvin Attack, not exploitable here) and RUSTSEC-2023-0089 (atomic-polyfill unmaintained, transitive via postcard). Both documented with justification.

---

## Raw Signals for Evaluator

- Workspace version 1.5.3 with 6 crates. Internal crate versions lag at 1.4.10 — workspace version advances independently of internal crate versions.
- Published to private `shroudb` registry, not crates.io. Docker images built via multi-stage musl cross-compilation.
- 23 integration tests (2005 lines) + unit tests in write_coordinator. Tests spawn real server processes and dependent engine binaries. Good coverage of HTTP, TCP, ACL, remote engine integration. Gaps in Sentry, remote store, Moat.
- `protocol.toml` (438 lines) is a machine-readable protocol definition consumed by `shroudb-codegen`. This is a mature codegen pipeline.
- The entity-agnostic design (ENVELOPE commands generic, USER commands are sugar) is a deliberate architectural choice that enables non-user credential envelopes (services, devices, API clients) without code changes.
- Per-field blind mode is a differentiator — it enables zero-knowledge credential management where the server never sees plaintext. This is uncommon in the market.
- The fail-closed Chronicle integration means audit is not optional when configured — operations fail rather than proceed unaudited. This is the correct security posture for credential infrastructure.
- `ENGINE_INTEGRATION.md` explicitly tracks what's wired vs. outstanding. Honest about gaps.
- The codebase uses Rust edition 2024 and MSRV 1.92, indicating active maintenance and willingness to adopt latest language features.
