# Sigil Engine DAG

## Overview

Sigil is the schema-driven credential envelope engine for ShrouDB. Developers
register a `Schema` where each field carries a tagged `FieldKind` variant
(`inert`, `index`, `credential`, `pii`, `secret`), and the engine routes
writes to the correct subsystem per-field: credentials are hashed in-process
(Argon2id or unkeyed SHA-256), `pii` fields are encrypted through Cipher
(with an optional Veil blind index when `searchable: true`), and `secret`
fields are versioned through Keep. On top of this core, Sigil provides user
CRUD (entity-agnostic `ENVELOPE_*` with `USER_*` sugar), session issuance
backed by ES256 JWTs with family-based refresh rotation and reuse detection,
password change/reset/import with transparent rehash, per-field lockout
(declare `LockoutPolicy` to enable), claim enrichment of JWTs from
`inert`/`index` fields annotated with `claim`, and a JWKS endpoint for
external token verification. Every mutating operation is audited through
Chronicle and gated by Sentry policy when those capabilities are present.
Sigil is the most interconnected engine in the ShrouDB ecosystem — at runtime
it reaches into Chronicle, Cipher, Veil, Keep, and Sentry; at build time its
server integration tests also pull in the `cipher-blind` and `veil-blind`
wire crates to validate end-to-end blind mode.

## Crate dependency DAG

Internal crates in this workspace (direct edges only; every crate also
consumes ShrouDB commons such as `shroudb-store`, `shroudb-acl`,
`shroudb-crypto`, and the relevant engine clients):

```
                         +----------------------+
                         |  shroudb-sigil-core  |   domain types
                         +----------+-----------+   (Schema, FieldKind,
                                    |               EnvelopeRecord,
                                    |               CredentialRecord,
                                    |               RefreshTokenRecord)
                                    v
                         +----------+-----------+
                         | shroudb-sigil-engine |   SigilEngine,
                         +----+----------+------+   CredentialManager,
                              |          |          JwtManager,
                              |          |          SessionManager,
                              |          |          WriteCoordinator,
                              |          |          CipherOps/VeilOps/
                              |          |          KeepOps traits +
                              |          |          Remote* impls
                              |          |
                              v          v
                 +------------+---+   +--+-------------------+
                 | sigil-protocol |   |  sigil-http (router) |
                 +-------+--------+   +--+-------------------+
                         |               |
                         v               v
                        +-----------------+
                        |  sigil-server   |   binary: HTTP + TCP (RESP3)
                        +--------+--------+
                                 ^
                                 |
                        +--------+--------+        +-------------------+
                        |   sigil-client  |<-------+    sigil-cli      |
                        +-----------------+        +-------------------+
```

Notes:

- `sigil-http` depends on both `sigil-engine` and `sigil-protocol`: HTTP
  handlers translate REST requests into `SigilCommand` values and route them
  through the same `dispatch` used by the TCP RESP3 path, so ACL enforcement
  lives in one place.
- `sigil-server` is the default binary and is the only crate that pulls in
  `shroudb-server-tcp`, `shroudb-storage`, `shroudb-client`
  (`EmbeddedStore` vs. `RemoteStore`), `shroudb-server-bootstrap` (the
  `Capability<T>` tri-state), `shroudb-engine-bootstrap` (resolving
  `[chronicle]` / `[sentry]` config sections into Chronicle / Sentry
  capabilities), `shroudb-protocol-wire`, `tokio-rustls`, and — to support
  in-process embedded cipher/veil/keep — `shroudb-cipher-engine` /
  `shroudb-cipher-core`, `shroudb-veil-engine` / `shroudb-veil-core`, and
  `shroudb-keep-engine` / `shroudb-keep-core`. The embedded engine crates
  are *not* pulled by `sigil-engine` itself; they live on the binary side
  because they are chosen at process-boot time.
- `sigil-engine` depends on `shroudb-server-bootstrap` for the
  `Capability<T>` type used in its public `Capabilities` struct, plus
  `shroudb-audit` and `shroudb-chronicle-core` for audit event plumbing.
- `sigil-client` depends only on `shroudb-client-common`; `sigil-cli`
  depends on `sigil-client` + `sigil-core` plus `shroudb-store` /
  `shroudb-storage` (for local-store CLI paths). Neither links the engine.

## Capabilities

Schema (entity-agnostic):

- Register, get, list, alter schemas; additive `add_fields` and
  `remove_fields` with per-variant validation enforced by `FieldKind`.
- Per-field `FieldKind` tagged union: `Inert`, `Index`, `Credential`,
  `Pii`, `Secret`. Mutual exclusion is structural, not runtime-validated.
- Per-field `CredentialPolicy` (algorithm, min/max length, optional
  `LockoutPolicy`) lives on the `Credential` variant.
- Per-field `ClaimPolicy` (with optional rename `as_name`) lives on
  `Inert` and `Index` and marks a field as a JWT claim source.

User / envelope CRUD:

- `envelope_create`, `envelope_import`, `envelope_get` (with
  `decrypt: bool`), `envelope_update`, `envelope_delete`,
  `envelope_verify(field)`, `envelope_lookup(field, value)`.
- `user_*` sugar wraps the same paths and infers the credential field
  from the schema via `Schema::credential_field_name`.
- All-or-nothing multi-field writes via `WriteCoordinator`:
  completed sub-operations (credential store, Cipher ciphertext, Veil
  entry, Keep secret) are recorded as `CompensatingOp`s and rolled back
  in reverse order on any subsequent failure. Orphaned rollback targets
  are surfaced in the returned error and logged at `tracing::warn!`.
- Per-field blind mode: a field value shaped as
  `{"blind": true, "value": "...", "tokens": "..."}` bypasses server-side
  Cipher/Veil processing for that field only. Standard and blind fields
  mix freely in one request.
- `get_envelope` always redacts blind fields and redacts server-encrypted
  PII when `decrypt=false` or when Cipher is absent.

Session / token:

- `session_create` (by `entity_id`) and `session_create_by_field`
  (e.g. email lookup via Veil, then verify).
- JWT access tokens signed with ES256 (default) via an active signing key
  per schema stored in `sigil.{schema}.keys`; signing keys follow
  `Active → Draining → Retired`. Private key material is zeroized on drop.
- `session_refresh` rotates the refresh token and re-enriches claims
  from the envelope on every refresh.
- Opaque refresh tokens with family IDs; reuse of an already-rotated token
  revokes the entire family (`TOKEN_REUSE`).
- `session_revoke`, `session_revoke_all`, `session_list`.
- Claim enrichment: fields tagged `claim` in the schema (only allowed on
  `Inert`/`Index`) are merged into JWT claims on both `session_create` and
  `session_refresh`; envelope-side values always override caller-provided
  `extra_claims` for the same key.
- `jwks(schema)` endpoint exposes public keys (JWKS) for external verifiers.

Credential / password:

- `credential_change`, `credential_reset`, `credential_import` (explicit
  field name) plus `password_change`, `password_reset`, `password_import`
  sugar that infers the field.
- Import accepts legacy `bcrypt`, `scrypt`, `argon2i`, `argon2d` hashes;
  verify transparently rehashes to Argon2id on success.
- Per-field lockout: if the field's `CredentialPolicy.lockout` is `Some`,
  repeated failures produce `ACCOUNT_LOCKED` (HTTP 429); if `lockout` is
  `None`, no lockout is tracked — this is how API-key / machine-credential
  fields avoid denial-of-service via lockout.
- `EngineResourceConfig.max_concurrent_hashes` bounds parallel Argon2id
  computations via a Tokio semaphore; `Sha256` credentials do not hold
  the permit.

Import / migration:

- `envelope_import` / `user_import` / `credential_import` store
  already-hashed credentials and mark the algorithm for later rehash.

## Engine dependencies

Sigil's engine-to-engine integrations go through the `Capabilities` struct,
whose slots are the explicit tri-state `Capability<T>` type from
`shroudb-server-bootstrap`: `Enabled(T)`, `DisabledForTests`, or
`DisabledWithJustification { reason }`. *Absence is never silent.*

- `cipher: Capability<Box<dyn CipherOps>>`
- `veil: Capability<Box<dyn VeilOps>>`
- `keep: Capability<Box<dyn KeepOps>>`
- `sentry: Capability<Arc<dyn PolicyEvaluator>>`
- `chronicle: Capability<Arc<dyn ChronicleOps>>`

In standalone mode (`shroudb-sigil` binary) the server wires cipher / veil
/ keep from optional `[cipher]`, `[veil]`, `[keep]` config sections which
each accept `mode = "remote" | "embedded"`. In remote mode the server
constructs `RemoteCipherOps` / `RemoteVeilOps` / `RemoteKeepOps` with TCP
connection pools via `deadpool`. In embedded mode it builds a fresh
`CipherEngine` / `VeilEngine` / `KeepEngine` against the same
`StorageEngine` (requiring `store.mode = "embedded"`), wraps it in
`EmbeddedCipherOps` / `EmbeddedVeilOps` / `EmbeddedKeepOps`, and hands that
to Sigil's `Capabilities`. Embedded engines have their own `policy` and
`audit` slots `Capability::disabled`'d with a justification that routing
goes through Sigil's own sentry/chronicle slots, so there is exactly one
policy and one audit surface in a sigil-server process. `[chronicle]` and
`[sentry]` are **required top-level sections** resolved through
`shroudb-engine-bootstrap` — they accept
`mode = "remote" | "embedded" | "disabled"`, and `mode = "disabled"`
requires an explicit `justification = "<reason>"` string. Missing
`[chronicle]` or `[sentry]` causes startup to fail-closed with a diagnostic.
In Moat mode the engine instances are passed in directly. At the engine
level, each runtime operation either succeeds, gets rejected with
`CapabilityMissing(...)`, or silently skips a non-blocking control (audit
emit, policy check), as described below.

### Dependency: chronicle (via `shroudb-chronicle-core`)

- **What breaks without it:** audit events are silently dropped. The
  `WriteCoordinator::emit_audit_event` path short-circuits to `Ok(())` when
  `capabilities.chronicle` is `None`. All mutating operations still succeed,
  but there is no audit trail for schema register/alter, envelope
  create/read/update/delete/verify/lookup, session create/refresh/revoke,
  or credential change/reset/import.
- **What works with it:** every engine operation emits a Chronicle event
  before the commit window closes; audit is fail-closed — if Chronicle is
  configured and returns an error, the calling operation fails with
  `Internal("audit event failed: …")` and any completed sub-writes are
  rolled back. Events carry `Engine::Sigil`, operation name, resource path,
  and actor.

### Dependency: cipher (via `shroudb-cipher-client` + `RemoteCipherOps`, or embedded `shroudb-cipher-engine` + `EmbeddedCipherOps`)

- **What breaks without it:** any field whose `FieldKind` is `Pii(…)` is
  rejected with `CapabilityMissing("cipher")` on write — including the
  searchable variant (`Pii { searchable: true }`). Rejection happens
  per-field during `process_field`, so an envelope that includes a PII
  field cannot be created, imported, or updated at all; completed
  sub-writes for earlier fields are rolled back. Blind PII values
  (`{"blind": true, "value": "..."}`) bypass Cipher and continue to work
  because the client already produced the ciphertext. On read,
  `envelope_get(.., decrypt=true)` still succeeds — it just redacts any
  server-encrypted PII field to `"[encrypted]"` instead of decrypting.
  Fields that are not PII (credentials, secrets, index, inert) are
  unaffected, and sessions / JWTs / lookups / claim enrichment continue
  to work as long as they don't touch a non-blind PII column.
- **What works with it:** `Pii` fields are encrypted at rest with a
  per-entity context `"{schema}/{entity_id}/{field}"` used as associated
  data, stored as ciphertext inside the envelope record, and decrypted on
  `envelope_get(.., decrypt=true)`.

### Dependency: cipher-blind (via `shroudb-cipher-blind`)

- **What breaks without it:** nothing at runtime for the Sigil binary —
  `shroudb-cipher-blind` is a dev-dependency of `shroudb-sigil-server`
  only. It powers integration tests that verify the blind wire contract
  (server accepts a pre-encrypted `{"blind": true, "value": "..."}`
  wrapper and stores it verbatim).
- **What works with it:** clients using the `shroudb-cipher-blind` SDK can
  produce ciphertext locally and send it through the blind wrapper, giving
  true end-to-end encryption for PII (the server never holds plaintext).

### Dependency: veil (via `shroudb-veil-client` + `RemoteVeilOps`, or embedded `shroudb-veil-engine` + `EmbeddedVeilOps`)

- **What breaks without it:** two distinct capabilities disappear. First,
  any field annotated `Pii { searchable: true }` is rejected on write with
  `CapabilityMissing("veil")` (it also needs Cipher), so schemas that use
  `email`/`phone`/etc. as searchable PII cannot be written. Second,
  `envelope_lookup` / `user_lookup` and therefore `session_login` /
  `session_create_by_field` fail immediately with
  `CapabilityMissing("veil")` — applications cannot log a user in by email
  or any other searchable field; they can still log them in by explicit
  `entity_id` via `session_create`. Envelope rollbacks that would delete a
  Veil entry are skipped silently when Veil is absent (the coordinator
  simply has nothing to call). Sigil can still create users whose schemas
  use only credential / non-searchable PII (if Cipher is present) /
  secret / index / inert fields.
- **What works with it:** searchable PII is tokenized and indexed via
  `Veil.put(entry_id, plaintext-or-tokens, Some(field), blind)` where
  `entry_id = "{entity_id}/{field_name}"`, and lookups resolve the
  plaintext (or a pre-computed `BlindTokenSet`) back to the entity.

### Dependency: veil-blind (via `shroudb-veil-blind`)

- **What breaks without it:** nothing at runtime for the Sigil binary —
  it is a dev-dependency of `shroudb-sigil-server` only, used to generate
  the `BlindTokenSet` that server integration tests embed in the blind
  wrapper.
- **What works with it:** clients produce blinded tokens locally and send
  them as the `tokens` field of the blind wrapper, so searchable PII can
  be indexed on the server without the server ever seeing the plaintext
  token-space.

### Dependency: keep (via `shroudb-keep-client` + `RemoteKeepOps`, or embedded `shroudb-keep-engine` + `EmbeddedKeepOps`)

- **What breaks without it:** any field whose `FieldKind` is `Secret(…)`
  is rejected on write with `CapabilityMissing("keep")`. An envelope that
  carries a third-party API token or refresh token cannot be created or
  updated; compensating deletes on rollback simply skip the Keep path.
  Fields that are not secrets are unaffected. Sigil does not read secrets
  back even when Keep is present — retrieval is delegated to Keep or
  Courier directly, so read paths are not affected by Keep availability.
- **What works with it:** `Secret` fields are serialized to
  `{schema}/{entity_id}/{field}` in Keep via `store_secret`, the plaintext
  is zeroized immediately after the call, and the envelope record carries
  no copy of the secret. Rollback deletes the Keep entry.

### Dependency: sentry (via `shroudb-acl::PolicyEvaluator`)

- **What breaks without it:** policy enforcement is bypassed. Every
  sensitive engine call routes through
  `WriteCoordinator::check_policy(principal, schema, action)` — when
  `capabilities.sentry` is `None`, that function short-circuits to
  `Ok(())` and the operation proceeds without any authorization check.
  Actions evaluated are `read`, `verify`, `lookup`, `session.create`,
  `session.refresh`, `session.revoke`, `session.revoke_all`,
  `session.list`, `credential.change`, `credential.reset`,
  `credential.import`. Without Sentry these all succeed for any caller
  that got past the HTTP layer's token validation.
- **What works with it:** each request is packaged into a `PolicyRequest`
  (principal id, resource `{type: "schema", id: schema_name}`, action
  string); a `PolicyEffect::Deny` yields `SigilError::PolicyDenied` with
  the matched policy name. This is how Sigil enforces scope-based access
  to schemas at runtime.

## Reverse dependencies

Sigil is terminal on the application side — applications consume it through
the HTTP REST API, the RESP3 TCP interface, `shroudb-sigil-client`, or by
embedding `SigilEngine` inside `shroudb-moat`. Known reverse dependencies:

- `shroudb-moat` embeds `SigilEngine` plus `shroudb-sigil-protocol` and
  reuses `shroudb-sigil-http::router` to expose the same REST surface
  under the unified Moat binary.
- `shroudb-codegen` reads `protocol.toml` to generate typed client SDKs.
- No other ShrouDB engine depends on Sigil. Cipher, Veil, Keep, Sentry,
  and Chronicle are below Sigil in the release DAG, not above it.

## Deployment modes

Sigil supports two deployment shapes, both built from the same
`SigilEngine<S>` generic over the `Store` trait.

Standalone (the `shroudb-sigil` binary in `shroudb-sigil-server`):

- Store: `EmbeddedStore` (in-process ShrouDB against a local data directory)
  or `RemoteStore` (TCP to a remote ShrouDB server), selected via
  `store.mode = "embedded" | "remote"` in the TOML config.
- Capabilities: each of `[cipher]`, `[veil]`, `[keep]` is optional and
  picks `mode = "remote" | "embedded"`. In remote mode the server builds
  `RemoteCipherOps` / `RemoteVeilOps` / `RemoteKeepOps` (address + optional
  auth token + optional pool size via `deadpool`). In embedded mode it
  instantiates `CipherEngine` / `VeilEngine` / `KeepEngine` against the
  same `StorageEngine` (requires `store.mode = "embedded"`) and wraps them
  in `EmbeddedCipherOps` / `EmbeddedVeilOps` / `EmbeddedKeepOps`. Embedded
  engines have their own policy / audit slots
  `Capability::disabled`-with-justification so that sigil-server has
  exactly one policy and one audit surface — Sigil's own. Any section
  that is omitted becomes `Capability::DisabledWithJustification` with a
  reason string, which produces the fallback behaviors described above.
  `[chronicle]` and `[sentry]` are required top-level sections resolved by
  `shroudb-engine-bootstrap`; they accept
  `mode = "remote" | "embedded" | "disabled"` and `disabled` requires an
  explicit `justification`. Missing either section fails startup with a
  diagnostic rather than silently disabling the control.
- Surface: HTTP (Axum) on `default_http_port = 6500` with CORS, CSRF, and
  token-bucket rate limiting; RESP3 TCP on `default_tcp_port = 6499`,
  optionally wrapped in TLS (`tokio-rustls`). Both paths translate to
  `SigilCommand` and go through the same `dispatch` for ACL enforcement.

Embedded (inside Moat):

- Moat constructs `Capabilities` directly with concrete engine instances
  (Cipher, Veil, Keep, Sentry, Chronicle) — no TCP, no connection pools,
  no probing. The same `sigil-http` router and `sigil-protocol` dispatch
  are reused so the REST and RESP3 contracts are identical to standalone.
- The Moat binary is the "all-engines-in-one" distribution; Sigil's
  behavior under Moat is a strict superset of standalone because the
  in-process engine wiring cannot suffer partial-capability availability.
