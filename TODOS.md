# TODOS

## Debt

Each item below is captured as a FAILING test in this repo. The test is the forcing function — this file only indexes them. When a test goes green, check its item off or delete the entry.

Rules:
- Do NOT `#[ignore]` a debt test to make CI pass.
- A visible ratchet (`#[ignore = "DEBT-X: <reason>"]`) requires a matching line in this file AND a clear reason on the attribute. Use sparingly.
- `cargo test -p <crate> debt_` is the live punch list.

### Cross-cutting root causes

Most items below stem from three systemic gaps. Fix these holistically and ~all the per-item entries resolve:

1. **`AuthContext` not threaded dispatch → engine.** Engine methods take no caller identity. Dispatch knows it (`shroudb_acl::AuthContext` with `actor`, `tenant`, `grants`) but never passes it through. That's why principal/actor are always the target entity, `""`, or `"system"`.
2. **Audit events are schemas, not audit trails.** `tenant_id: None`, `correlation_id: None`, `duration_ms: 0`, `metadata: {}`, `result: EventResult::Ok` hardcoded in `write_coordinator.rs::emit_audit_event`. Failure paths emit nothing.
3. **Server binary never populates `Capabilities::sentry` or `::chronicle`.** `SigilServerConfig` has no `[sentry]`/`[chronicle]` sections; `main.rs::run_server` only wires cipher/veil/keep.

### Open

- [x] **DEBT-F1** — `SigilServerConfig` must accept `[sentry]` / `[chronicle]` sections; `main.rs` must wire them into `Capabilities`. Test: `debt_f01_server_config_must_wire_sentry_and_chronicle` @ `shroudb-sigil-server/src/config.rs`.
- [x] **DEBT-F3** — `PolicyRequest.principal.id` must be the caller's actor, not the target entity. Test: `debt_f03_policy_principal_must_not_equal_target_entity` @ `shroudb-sigil-engine/src/write_coordinator.rs`.
- [x] **DEBT-F3b** — `PolicyRequest.principal` must carry roles or claims (ABAC currently blind). Test: `debt_f03b_policy_principal_must_carry_roles_or_claims` @ same file.
- [x] **DEBT-F4a** — audit `Event.actor` must be caller's actor, not target entity. Test: `debt_f04a_audit_event_actor_must_not_equal_target_entity` @ same file.
- [x] **DEBT-F4b** — audit `Event.tenant_id` must be populated from caller's tenant. Test: `debt_f04b_audit_event_tenant_must_be_populated` @ same file.
- [ ] **DEBT-F4c** — audit `Event.duration_ms` must be measured (currently hardcoded 0). Test: `debt_f04c_audit_event_duration_must_be_measured` @ same file.
- [x] **DEBT-F5** — `schema_register` / `schema_alter` must not hardcode actor `"system"`. Test: `debt_f05_schema_ops_audit_actor_must_not_be_literal_system` @ `shroudb-sigil-engine/src/engine.rs`.
- [x] **DEBT-F6** — `envelope_lookup` must not pass empty principal to `check_policy`. Test: `debt_f06_lookup_policy_principal_must_not_be_empty` @ same file.
- [ ] **DEBT-F8** — failed operations (duplicate create, auth failure, policy deny) must emit audit events with `result: EventResult::Error`. Test: `debt_f08_failed_operation_must_emit_audit_event` @ `shroudb-sigil-engine/src/write_coordinator.rs`.
- [ ] **DEBT-F10** — `SigilEngine::new` must reject or loudly warn on empty `Capabilities` in production mode. Test: `debt_f10_production_construction_must_reject_empty_capabilities` @ `shroudb-sigil-engine/src/engine.rs`.
