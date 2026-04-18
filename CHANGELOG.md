# Changelog

All notable changes to ShrouDB Sigil are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added

- `[cipher] mode = "embedded"`, `[veil] mode = "embedded"`, `[keep] mode = "embedded"` config slots on `sigil-server`. When set, Sigil runs in-process `CipherEngine` / `VeilEngine` / `KeepEngine` instances on dedicated namespaces of its own `StorageEngine` and wires the narrow `CipherOps`/`VeilOps`/`KeepOps` capabilities directly — no separate sidecars required. Each slot remains `mode = "remote"` by default (existing pool-based client behavior). Embedded mode requires `store.mode = "embedded"`; mixing embedded capability with remote store fails-closed at startup.

### Changed

- Sentry policy checks and Chronicle audit events now fire on all entity-scoped engine paths, not just envelope create/update/delete. Reads (`envelope_get`, `envelope_verify`, `envelope_lookup`), sessions (`session_create`, `session_refresh`, `session_revoke`, `session_revoke_all`, `session_list`), credential lifecycle (`credential_change`, `credential_reset`, `credential_import`), and schema lifecycle (`schema_register`, `schema_alter`) are now gated and audited. When Sentry/Chronicle are absent from Capabilities, behavior is unchanged (calls short-circuit to Ok). When configured, an unreachable Chronicle fails the operation (fail-closed), matching existing write-path semantics. Action strings: `read`, `verify`, `lookup`, `session.*`, `credential.*`, `schema.*`.

## [v2.1.0] - 2026-04-16

### Added

- `PING` meta-command (RESP3 + HTTP `GET /sigil/ping`). Sigil was the only engine missing PING across the ShrouDB fleet; this restores uniform meta-command coverage alongside `AUTH` and `HEALTH`. Client SDKs gain a `ping()` helper; the CLI accepts `PING` and prints `PONG`.

## [v2.0.0] - 2026-04-15

### Added

- `FieldKind` tagged enum (`inert` | `index` | `credential` | `pii` | `secret`) as the schema's per-field crypto-treatment selector. Mutual exclusion is now enforced by the type system rather than runtime validation.
- Per-field `CredentialPolicy` (`algorithm`, `min_length`, `max_length`, `lockout`) inside the `credential` variant. One schema can now mix, e.g., an Argon2id `password` with lockout enabled and a `sha256` `api_key` with no lockout.
- `PasswordAlgorithm::Sha256` — unkeyed SHA-256 with constant-time comparison, for high-entropy machine credentials (256-bit CSPRNG-generated API keys). Gated on `min_length >= 32` at schema-validation time so it can't be attached to low-entropy fields.
- `LockoutPolicy`, `PiiPolicy`, `SecretPolicy`, `ClaimPolicy` nested policy types carried only by the variants where they apply.
- `EngineResourceConfig` (currently just `max_concurrent_hashes: u32`) for true engine-resource knobs.
- `shroudb-sigil-cli SCHEMA MIGRATE --store <path> [--dry-run]` — one-shot tool that rewrites v1 schemas stored on disk into v2 form. Idempotent.

### Changed

- Schema JSON and TOML wire shape: `annotations: { credential: true, ... }` is replaced with `kind: { type: "credential", ... }` (internally tagged on `type`). All schema samples in `README.md`, `DOCS.md`, `ABOUT.md`, `AGENTS.md`, and `protocol.toml` updated.
- `SigilConfig::password_policy: PasswordPolicy` renamed to `engine_resources: EngineResourceConfig`. The algorithm, length bounds, and lockout settings that used to live there now live per-field on `CredentialPolicy`.
- `CredentialManager` no longer holds a global policy — it receives a resolved `CredentialPolicy` per call, sourced from the schema via `Schema::credential_policy(field_name)`.
- `protocol.toml` bumped to `2.0.0`. `FieldDef.annotations` replaced with `FieldDef.kind`; `FieldAnnotations` type block replaced with `FieldKind` + the nested policy types.

### Removed

- `FieldAnnotations` struct and its `validate()` cross-field rules (`credential ⊕ pii ⊕ secret ⊕ index` mutex, `searchable requires pii`, `claim invalid on credential/pii/secret`, `lockout=false requires credential=true`). Structurally impossible in the new shape.
- `PasswordPolicy` struct. Its fields moved to `CredentialPolicy` (per-field) and `EngineResourceConfig` (engine-wide).
- `SchemaFieldConfig` flat-boolean TOML keys in server config. The parser now rejects them with a pointer to `shroudb-sigil-cli SCHEMA MIGRATE`.
- Engine-global lockout threshold, length bounds, and algorithm selection. All three are per-field in v2.

### Security

- Pre-v1.9.2 schemas had implicit `lockout: true` semantics. The migration tool preserves observable behavior by writing an explicit `LockoutPolicy { max_attempts: 5, duration_secs: 900 }` onto every migrated credential field that did not opt out via `lockout: false`. Upgrade does not silently weaken lockout for any existing schema.
- `PasswordAlgorithm::Sha256` is deliberately unkeyed (not HMAC). The rationale: Sigil's `KeepOps` capability is explicitly one-way (`store_secret` / `delete_secret`; Sigil never reads secrets back), so an HMAC key would have to come from either a doctrine break on `KeepOps` or engine-startup config — both reintroduce the "Sigil deciding" coupling v2.0 exists to remove. At 256 bits of CSPRNG entropy, unkeyed SHA-256 + constant-time compare is cryptographically sufficient; HMAC's value is against offline brute-force of low-entropy inputs, which machine credentials are not. The schema-validation rule `Sha256 requires min_length >= 32` refuses the algorithm on low-entropy fields where this reasoning doesn't hold.

### Migration

Breaking change for schemas stored on disk and for schema TOML in server config. The server refuses to start against a v1 schema store.

1. Stop the Sigil server.
2. Run `shroudb-sigil-cli SCHEMA MIGRATE --store <path>` against the Sigil data directory. Use `--dry-run` first to preview. The tool is idempotent.
3. Update any server-config TOML `[[schemas.fields]]` entries from flat booleans to the `kind = { type = "...", ... }` form. The migration tool prints guidance for this step.
4. Restart the server.

**Downstream repos** — not updated by this release; file issues against each:

- `shroudb-moat` — embeds `SigilEngine` + `SigilConfig`. Needs the `password_policy` → `engine_resources` rename, the schema TOML format break propagated to its own seeded-schema config, and a 2.0 version pin on `shroudb-sigil-*` deps.
- `shroudb-codegen` — reads `protocol.toml`. Regenerate client bindings; the `FieldAnnotations` type is gone, replaced by a tagged-union `FieldKind` that downstream codegen must handle.
- `shroudb-crypto` — no code changes required; `sha256`, `constant_time_eq`, `password_hash`, `password_verify`, and `generate_api_key` are already exposed.

## [v1.9.2] - 2026-04-15

### Added

- `lockout` field annotation on `FieldAnnotations` (default `true`): per-credential-field opt-out for failed-attempt lockout. Set `lockout: false` on machine-auth schemas (API keys, service tokens) where lockout is a denial-of-service vector — an attacker who learns a tenant's `entity_id` could otherwise lock that tenant out of production by hammering bad secrets. Schema-level validation rejects `lockout: false` on non-credential fields.
- `Schema::field_lockout(name)` resolver returns the effective lockout flag for a named field.
- New tests covering `lockout: false` (no lock after many failed attempts) and switching the flag to bypass an existing `locked_until` state.

### Changed

- `CredentialManager::verify` and `CredentialManager::change_credential` now take an `enforce_lockout: bool` parameter, resolved per-call from the schema's credential field annotation.
- When `lockout: false`, failed attempts are not counted, `locked_until` is never set, and `ACCOUNT_LOCKED` is never returned for that field — verify returns `VERIFICATION_FAILED` instead.
- `protocol.toml` adds `lockout` to `FieldAnnotations`; `ACCOUNT_LOCKED` description clarifies it only fires on credential fields with the default `lockout: true`.
- Server-side `SchemaFieldConfig` mirrors the new annotation.
- Documentation: `README.md`, `DOCS.md`, `ABOUT.md` cover the human-auth vs. machine-auth guidance with an `api_keys` schema example.

### Security

- Bumped `rustls-webpki` 0.103.11 → 0.103.12 to clear RUSTSEC-2026-0098 and RUSTSEC-2026-0099 (name-constraint handling for URI and wildcard names).

## [v1.9.0] - 2026-04-11

### Added

- New `shroudb-sigil-http` crate: shared Axum HTTP router extracted from `shroudb-sigil-server` for reuse by both standalone Sigil and Moat gateway
- CORS layer now allows PATCH and DELETE methods (required by user update/delete endpoints)

### Changed

- `shroudb-sigil-server` now depends on `shroudb-sigil-http` instead of bundling HTTP handlers inline
- Removed `cors.rs`, `csrf.rs`, `rate_limit.rs`, `http.rs` from server binary (now in shared crate)
- Protocol spec bumped to v1.2.0

## [v1.8.0] - 2026-04-11

### Added

- `claim` field annotation: auto-include index/inert field values in JWT claims on session create and refresh
- `Schema::claim_fields()` method returns claim-annotated field names
- `SessionManager::peek_entity_id()` for reading entity_id from refresh tokens without modification
- `SigilEngine::build_enriched_claims()` merges envelope values with caller META claims
- `SigilResponse::body()` for extracting response payloads
- `JwtManager::store()` accessor
- 19 new tests (7 schema validation, 3 session unit, 6 protocol dispatch, 3 HTTP integration)

### Changed

- `SessionManager::refresh()` accepts `extra_claims` parameter for claim enrichment
- `SigilEngine::session_create()` auto-enriches from claim-annotated fields after credential verification
- `SigilEngine::session_refresh()` re-reads claim fields from current envelope, reflecting role changes without re-login
- Enriched claim values override caller-provided META for the same key
- Protocol spec bumped to v1.1.0

## [v1.5.5] - 2026-04-09

### Fixed

- gate PII decryption behind platform ACL, track blind fields
- track blind fields to prevent server decrypt of client-encrypted PII

### Other

- test: verify platform ACL gates PII decryption

## [v1.5.4] - 2026-04-09

### Added

- adapt to chronicle-core 1.3.0 event model

### Other

- bump version to 1.5.4

## [v1.5.3] - 2026-04-04

### Changed

- use shared ServerAuthConfig from shroudb-acl

## [v1.5.2] - 2026-04-03

### Fixed

- rename metadata parameter to meta in protocol.toml

### Other

- docs: add per-field blind mode documentation

## [v1.5.1] - 2026-04-03

### Fixed

- blind VeilOps put must not double-base64-encode tokens

## [v1.5.0] - 2026-04-03

### Added

- per-field blind mode for E2EE client-side encryption

## [v1.4.10] - 2026-04-02

### Fixed

- use entrypoint script to fix volume mount permissions

### Other

- Add Argon2id concurrency limit to prevent credential DoS

## [v1.4.9] - 2026-04-01

### Other

- Use check_dispatch_acl for consistent ACL error formatting

## [v1.4.8] - 2026-04-01

### Other

- Reorder delete path: audit → commit → cleanup to eliminate orphans

## [v1.4.7] - 2026-04-01

### Other

- Track Phase 1 deletions and surface orphans when delete commit fails

## [v1.4.6] - 2026-04-01

### Other

- Migrate TCP handler to shroudb-server-tcp

## [v1.4.5] - 2026-04-01

### Other

- Add rollback orphan surfacing test, concurrent duplicate rejection test

## [v1.4.4] - 2026-04-01

### Other

- Add 12 missing client SDK methods for envelope, lookup, credential (v1.4.4)

## [v1.4.3] - 2026-03-31

### Other

- Add unit tests to sigil-core: credential types, envelope serialization (v1.4.3)

## [v1.4.2] - 2026-03-31

### Other

- Replace Mutex-serialized remote clients with per-request connections
- Log degraded state when delete commit-point fails
- Surface rollback orphans, unify delete error handling, fix now_secs
- Remove dead SigilEngine::verify_token() method

## [v1.4.1] - 2026-03-31

### Other

- Harden server: expect context on unwraps (v1.4.1)
- Fail closed on audit: block operations when Chronicle unreachable
- Wire ChronicleOps audit trail into WriteCoordinator (v1.4.0)
- Recover from poisoned mutex in rate limiter instead of panicking
- Add rollback failure-injection tests for all capability traits

## [v1.3.0] - 2026-03-31

### Other

- Fix SensitiveBytes leak: CipherOps::decrypt returns SensitiveBytes (v1.3.0)
- Wire Sentry ABAC into Sigil WriteCoordinator (v1.2.0)
- Add integration tests for rollback, blind index cleanup, PII redaction
- Harden Sigil v1.1.0: rollback, error handling, dead code, dedup
- Add config-seeded schemas — zero API calls to get started
- Integrate Keep for secret field versioned storage
- Redact PII on USER GET — plaintext only via Courier just-in-time
- Add login-by-encrypted-field: register and sign in without plaintext PII
- Integrate Veil for searchable encrypted PII fields
- Add Cipher integration test: PII field encrypt/decrypt roundtrip
- Integrate Cipher for PII field encryption/decryption

## [v1.0.0] - 2026-03-29

### Other

- Add CI, release workflows, and Dockerfile
- Wire token auth config + ACL integration tests
- Remove redundant _store field from SigilEngine
- Add ACL via shroudb-acl: token auth on TCP + HTTP, per-command checks
- Add USER IMPORT command for single-operation user migration
- Update docs with CLI usage and client SDK reference
- Fix session list expiry + delete user session cleanup
- Add client SDK and CLI with full command coverage
- Add README, DOCS, and ABOUT documentation
- Add USER UPDATE command, protocol.toml, integration test coverage
- Add integration tests against real server (HTTP + TCP)
- Security hardening + wire middleware + fix capability stubs
- Add HTTP server with full REST API
- Remove accidentally committed sigil-data, add to gitignore
- Add TCP server, config, and main entry point
- Add SigilEngine facade, wire protocol commands, and dispatch
- Add session manager with family-based refresh token rotation
- Add JWT manager with key lifecycle and JWKS
- Add write coordinator and capability traits
- Add credential manager with full password lifecycle
- Add schema registry with Store-backed persistence
- Add schema validation rules with tests
- Add multi-algorithm support for PASSWORD IMPORT migration path
- Scaffold Sigil v1 workspace with core types

