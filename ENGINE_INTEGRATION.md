# Sigil Engine Integration Guide

When other ShrouDB engines reach v1, they integrate with Sigil through the capability traits in `shroudb-sigil-engine/src/capabilities.rs`. Each trait is a focused interface — Sigil calls through it without importing engine crates.

## Current State

Sigil standalone handles `credential` and `index`/`inert` field annotations. All other annotations (`pii`, `searchable`, `secret`) require engine capabilities. Schema registration is rejected if annotations require missing capabilities (fail-closed).

The capability traits are defined and the write coordinator calls through them. What's missing is the engine-side trait implementations and the wiring in Moat.

## Cipher (shroudb-transit → shroudb-cipher)

**Required for:** `pii: true` fields

**Trait:** `CipherOps`

```rust
pub trait CipherOps: Send + Sync {
    fn encrypt(&self, plaintext: &[u8]) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, SigilError>> + Send + '_>>;
    fn decrypt(&self, ciphertext: &[u8]) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, SigilError>> + Send + '_>>;
}
```

**What the Cipher v1 team needs to implement:**
1. A struct that implements `CipherOps` by calling Cipher's encrypt/decrypt API
2. In Moat: instantiate this struct wrapping the Cipher engine and pass it to `Capabilities`
3. In standalone: instantiate wrapping a TCP client to a remote Cipher instance

**Write path:** `USER CREATE` with a `pii` field → `cipher.encrypt(plaintext)` → hex-encoded ciphertext stored in user record.

**Read path:** `USER GET` → hex-decode → `cipher.decrypt(ciphertext)` → plaintext returned to caller. (Read-path decryption is not yet wired in `WriteCoordinator::get_user` — needs a `ReadCoordinator` or decryption pass in the get path.)

**Testing:** Round-trip test: create user with PII field → get user → verify plaintext matches.

## Veil (shroudb-veil)

**Required for:** `searchable: true` fields (also requires Cipher)

**Trait:** `VeilOps`

```rust
pub trait VeilOps: Send + Sync {
    fn index(&self, plaintext: &[u8]) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, SigilError>> + Send + '_>>;
}
```

**What the Veil v1 team needs to implement:**
1. A struct that implements `VeilOps` by calling Veil's blind index creation API
2. Blind indexes need to be stored separately (in a `sigil.{schema}.indexes` namespace or via Veil's own namespace)
3. A search path that takes a plaintext query → generates blind index token → queries Veil

**Write path:** `USER CREATE` with `searchable` field → `cipher.encrypt()` for storage + `veil.index()` for search index.

**Search path:** Not yet designed. Needs a `USER SEARCH` command that takes a field name + plaintext query value, generates the blind index token, and queries Veil.

## Keep (shroudb-keep)

**Required for:** `secret: true` fields

**Trait:** `KeepOps`

```rust
pub trait KeepOps: Send + Sync {
    fn store_secret(&self, key: &[u8], value: &[u8]) -> Pin<Box<dyn Future<Output = Result<u64, SigilError>> + Send + '_>>;
    fn get_secret(&self, key: &[u8]) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, SigilError>> + Send + '_>>;
}
```

**What the Keep v1 team needs to implement:**
1. A struct that implements `KeepOps` by calling Keep's secret storage API
2. Secrets are stored under a key derived from `{schema}/{user_id}/{field_name}`

**Write path:** `USER CREATE` with `secret` field → `keep.store_secret(key, value)`.

**Read path:** `USER GET` with `secret` field → `keep.get_secret(key)` → value returned.

## Sentry (shroudb-sentry)

**Required for:** Post-verification authorization enrichment

**Trait:** `SentryOps`

```rust
pub trait SentryOps: Send + Sync {
    fn evaluate(&self, user_id: &str, context: &serde_json::Value)
        -> Pin<Box<dyn Future<Output = Result<serde_json::Value, SigilError>> + Send + '_>>;
}
```

**What the Sentry v1 team needs to implement:**
1. A struct that implements `SentryOps` by calling Sentry's policy evaluation API
2. Returns authorization grants (roles, permissions, scopes)

**Integration point:** After `SESSION CREATE` verifies credentials, if Sentry is available:
1. Call `sentry.evaluate(user_id, context)` to get authorization grants
2. Merge grants into the JWT access token claims
3. Return enriched token

This is not wired yet. The `SigilEngine::session_create` method needs a conditional Sentry call after credential verification.

## Moat Integration

In Moat, all engines are embedded in a single binary. Moat constructs `Capabilities` with real engine instances:

```rust
let cipher_ops = Arc::new(CipherAdapter::new(cipher_engine));
let veil_ops = Arc::new(VeilAdapter::new(veil_engine));
let keep_ops = Arc::new(KeepAdapter::new(keep_engine));
let sentry_ops = Arc::new(SentryAdapter::new(sentry_engine));

let capabilities = Capabilities {
    cipher: Some(cipher_ops),
    veil: Some(veil_ops),
    keep: Some(keep_ops),
    sentry: Some(sentry_ops),
};

let sigil = SigilEngine::new(store, config, capabilities).await?;
```

Each adapter struct wraps the engine's library API and implements the corresponding `*Ops` trait.

## Outstanding Work

| Item | Blocked On | Description |
|------|-----------|-------------|
| Cipher field encryption | Cipher v1 | `CipherOps` impl + read-path decryption |
| Veil searchable fields | Veil v1 | `VeilOps` impl + `USER SEARCH` command |
| Keep secret fields | Keep v1 | `KeepOps` impl + read-path retrieval |
| Sentry enrichment | Sentry v1 | `SentryOps` impl + JWT claim merging |
| Read-path decryption | Cipher v1 | `get_user` currently returns raw ciphertext for PII fields |
| USER SEARCH command | Veil v1 | Blind index query for searchable encrypted fields |
| USER UPDATE command | — | Update non-credential fields on existing user |
| Moat engine/sigil.rs | All engines | Adapter structs + feature flag |
| Remote capability clients | — | TCP clients wrapping `*Ops` traits for standalone mode |
