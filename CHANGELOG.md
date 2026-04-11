# Changelog

All notable changes to ShrouDB Sigil are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

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

