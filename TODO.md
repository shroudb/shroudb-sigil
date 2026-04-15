# TODO

## PasswordPolicy → per-field credential policy

**Problem:** `PasswordPolicy` is engine-global, which contradicts Sigil's schema-driven thesis. Today every credential field across every schema gets the same algorithm, lockout thresholds, and length validation — that's Sigil hard-coding a "passwords work like this" decision, not the schema describing what each credential is.

The recently-shipped `lockout: bool` annotation is a wedge that proves per-field credential policy works. The full refactor moves the rest of `PasswordPolicy` onto `FieldAnnotations` (or removes it entirely), leaving only true engine-resource concerns at config level.

### Audit of `PasswordPolicy` fields

| Field | Today | Should be | Notes |
|---|---|---|---|
| `algorithm: PasswordAlgorithm` | engine-global | per-field | Argon2id is correct for passwords, wrong for API keys (verify-cost throughput problem; high-entropy random secrets don't need KDF stretching). API-key schemas probably want a fast constant-time hash (SHA-256 + HMAC, or similar). |
| `max_failed_attempts: u32` | engine-global | per-field | Already established by the `lockout` work. |
| `lockout_duration_secs: u64` | engine-global | per-field | Same. |
| `min_length: usize` | engine-global | per-field | Passwords need a floor (8 chars). API keys are fixed-length random — the validator is irrelevant or rejects valid keys. PINs may want exact length. |
| `max_length: usize` | engine-global | per-field | Same logic — depends on credential shape. |
| `max_concurrent_hashes: u32` | engine-global | **stays engine-global** | Process-wide memory bound on Argon2id (~64 MiB × N concurrent). This is a resource limit, not a credential property. |

### Open design questions

1. **Does Sigil offer a non-Argon2id path for machine credentials?** If yes, what does it look like — a new `PasswordAlgorithm::Sha256Hmac` variant, a separate trait, something else? If no, API-key schemas pay the Argon2id cost and that's a documented limitation.
2. **Where do defaults live when an annotation is unset?** Hard-coded secure constants in `shroudb-sigil-core` (preferred — single source of truth), or engine-config fallback (more flexible, but reintroduces the "engine knows about passwords" problem)?
3. **Does `PasswordPolicy` survive at all?** Options: (a) shrink to `EngineResourceConfig` with just `max_concurrent_hashes`; (b) delete entirely and move the semaphore size to a separate engine-startup arg; (c) rename to `CredentialDefaults` and keep as fallback for unset annotations.
4. **Validation surface for new annotations:** what combinations are illegal? E.g., `algorithm: Sha256Hmac` + `min_length: 8` is probably nonsensical (machine creds aren't length-bounded). Need explicit rules, not just "trust the user."
5. **Migration:** existing schemas have no per-field policy fields. Defaulting them to the current global values keeps behavior identical; defaulting to hard-coded constants might shift behavior. Pick one and document.

### Implementation sketch

1. Decide on the answers to the open questions above (separate design pass before code).
2. Add new fields to `FieldAnnotations` (or a nested `CredentialPolicy` struct):
   - `algorithm: Option<PasswordAlgorithm>` — only valid with `credential: true`
   - `min_length: Option<usize>` — only valid with `credential: true`
   - `max_length: Option<usize>` — only valid with `credential: true`
   - `lockout_max_attempts: Option<u32>` — only valid with `credential: true && lockout: true`
   - `lockout_duration_secs: Option<u64>` — only valid with `credential: true && lockout: true`
3. Add a resolver on `Schema` that takes a field name and returns the effective `CredentialPolicy` (annotation overrides → defaults).
4. Refactor `CredentialManager` to take the resolved policy per-call instead of holding a `PasswordPolicy`. Keep the `Semaphore` for hash concurrency — that's the only resource concern.
5. Update every call site in `engine.rs` to resolve the policy and pass it through.
6. Shrink or delete `PasswordPolicy` per the decision in (3).
7. Tests: per-field algorithm selection, per-field length bounds, per-field lockout thresholds, mixed-policy schemas (e.g., `users` schema with default password policy + `api_keys` schema with custom machine-cred policy in the same engine).
8. Docs: `protocol.toml`, `README.md`, `DOCS.md`, `ABOUT.md`. The "Account Lockout" section in `DOCS.md` should be folded into a broader "Credential Policy" section.

### Files in scope

- `shroudb-sigil-core/src/schema.rs` — annotations, validation, resolver
- `shroudb-sigil-core/src/credential.rs` — `PasswordPolicy` shape decision
- `shroudb-sigil-engine/src/credential.rs` — `CredentialManager` API change
- `shroudb-sigil-engine/src/engine.rs` — call-site wiring
- `shroudb-sigil-engine/src/write_coordinator.rs` — `set_credential` / `import_credential` length validation now needs schema context
- `shroudb-sigil-server/src/config.rs` — server-side schema config mirror
- `protocol.toml`, `README.md`, `DOCS.md`, `ABOUT.md`
