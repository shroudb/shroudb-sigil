use shroudb_acl::AuthContext;
use shroudb_protocol_wire::WIRE_PROTOCOL;
use shroudb_sigil_engine::engine::SigilEngine;
use shroudb_store::Store;

use crate::commands::SigilCommand;
use crate::response::SigilResponse;

const SUPPORTED_COMMANDS: &[&str] = &[
    "AUTH",
    "SCHEMA REGISTER",
    "SCHEMA GET",
    "SCHEMA LIST",
    "SCHEMA ALTER",
    "ENVELOPE CREATE",
    "ENVELOPE GET",
    "ENVELOPE IMPORT",
    "ENVELOPE UPDATE",
    "ENVELOPE DELETE",
    "ENVELOPE VERIFY",
    "ENVELOPE LOOKUP",
    "USER CREATE",
    "USER GET",
    "USER IMPORT",
    "USER UPDATE",
    "USER DELETE",
    "USER VERIFY",
    "USER LOOKUP",
    "SESSION CREATE",
    "SESSION LOGIN",
    "SESSION REFRESH",
    "SESSION REVOKE",
    "SESSION REVOKE ALL",
    "SESSION LIST",
    "CREDENTIAL CHANGE",
    "CREDENTIAL RESET",
    "CREDENTIAL IMPORT",
    "PASSWORD CHANGE",
    "PASSWORD RESET",
    "PASSWORD IMPORT",
    "JWKS",
    "HEALTH",
    "PING",
    "HELLO",
];

/// Dispatch a parsed command to the SigilEngine and produce a response.
///
/// `auth_context` is the authenticated identity for this connection/request.
/// `None` means auth is disabled (dev mode / no auth config).
/// AUTH commands are handled externally by the TCP/HTTP layer — dispatch
/// never sees them.
pub async fn dispatch<S: Store>(
    engine: &SigilEngine<S>,
    cmd: SigilCommand,
    auth_context: Option<&AuthContext>,
) -> SigilResponse {
    // Check ACL requirement before dispatch
    if let Err(e) = shroudb_acl::check_dispatch_acl(auth_context, &cmd.acl_requirement()) {
        return SigilResponse::error(e);
    }

    match cmd {
        // AUTH is handled at the connection layer, not here
        SigilCommand::Auth { .. } => SigilResponse::error("AUTH handled at connection layer"),

        // ── Schema ──────────────────────────────────────────────────
        SigilCommand::SchemaRegister { schema } => match engine.schema_register(schema).await {
            Ok(version) => SigilResponse::ok(serde_json::json!({
                "status": "ok",
                "version": version,
            })),
            Err(e) => SigilResponse::error(e.to_string()),
        },

        SigilCommand::SchemaGet { name } => match engine.schema_get(&name).await {
            Ok(schema) => SigilResponse::ok(serde_json::json!(schema)),
            Err(e) => SigilResponse::error(e.to_string()),
        },

        SigilCommand::SchemaList => match engine.schema_list().await {
            Ok(names) => SigilResponse::ok(serde_json::json!(names)),
            Err(e) => SigilResponse::error(e.to_string()),
        },

        SigilCommand::SchemaAlter {
            name,
            add_fields,
            remove_fields,
        } => match engine.schema_alter(&name, add_fields, remove_fields).await {
            Ok(schema) => SigilResponse::ok(serde_json::json!({
                "status": "ok",
                "name": schema.name,
                "version": schema.version,
                "fields": schema.fields.len(),
            })),
            Err(e) => SigilResponse::error(e.to_string()),
        },

        // ── Envelope (generic) ─────────────────────────────────────
        SigilCommand::EnvelopeCreate {
            schema,
            entity_id,
            fields,
        } => match engine.envelope_create(&schema, &entity_id, &fields).await {
            Ok(record) => SigilResponse::ok(serde_json::json!({
                "status": "ok",
                "entity_id": record.entity_id,
                "fields": record.fields,
                "created_at": record.created_at,
            })),
            Err(e) => SigilResponse::error(e.to_string()),
        },

        SigilCommand::EnvelopeImport {
            schema,
            entity_id,
            fields,
        } => match engine.envelope_import(&schema, &entity_id, &fields).await {
            Ok(record) => SigilResponse::ok(serde_json::json!({
                "status": "ok",
                "entity_id": record.entity_id,
                "fields": record.fields,
                "created_at": record.created_at,
            })),
            Err(e) => SigilResponse::error(e.to_string()),
        },

        SigilCommand::EnvelopeUpdate {
            schema,
            entity_id,
            fields,
        } => match engine.envelope_update(&schema, &entity_id, &fields).await {
            Ok(record) => SigilResponse::ok(serde_json::json!({
                "status": "ok",
                "entity_id": record.entity_id,
                "fields": record.fields,
                "updated_at": record.updated_at,
            })),
            Err(e) => SigilResponse::error(e.to_string()),
        },

        SigilCommand::EnvelopeGet { schema, entity_id } => {
            // Decrypt requires admin scope — regular Read callers get redacted PII
            let decrypt = auth_context.is_some_and(|ctx| ctx.is_platform);
            match engine.envelope_get(&schema, &entity_id, decrypt).await {
                Ok(record) => SigilResponse::ok(serde_json::json!({
                    "entity_id": record.entity_id,
                    "fields": record.fields,
                    "created_at": record.created_at,
                    "updated_at": record.updated_at,
                })),
                Err(e) => SigilResponse::error(e.to_string()),
            }
        }

        SigilCommand::EnvelopeDelete { schema, entity_id } => {
            match engine.envelope_delete(&schema, &entity_id).await {
                Ok(()) => SigilResponse::ok_simple(),
                Err(e) => SigilResponse::error(e.to_string()),
            }
        }

        SigilCommand::EnvelopeVerify {
            schema,
            entity_id,
            field,
            value,
        } => match engine
            .envelope_verify(&schema, &entity_id, &field, &value)
            .await
        {
            Ok(valid) => SigilResponse::ok(serde_json::json!({
                "status": "ok",
                "valid": valid,
            })),
            Err(e) => SigilResponse::error(e.to_string()),
        },

        SigilCommand::EnvelopeLookup {
            schema,
            field_name,
            field_value,
        } => match engine
            .envelope_lookup(&schema, &field_name, &field_value)
            .await
        {
            Ok(entity_id) => SigilResponse::ok(serde_json::json!({
                "status": "ok",
                "entity_id": entity_id,
            })),
            Err(e) => SigilResponse::error(e.to_string()),
        },

        // ── User (sugar) ───────────────────────────────────────────
        SigilCommand::UserCreate {
            schema,
            user_id,
            fields,
        } => match engine.user_create(&schema, &user_id, &fields).await {
            Ok(record) => SigilResponse::ok(serde_json::json!({
                "status": "ok",
                "entity_id": record.entity_id,
                "fields": record.fields,
                "created_at": record.created_at,
            })),
            Err(e) => SigilResponse::error(e.to_string()),
        },

        SigilCommand::UserImport {
            schema,
            user_id,
            fields,
        } => match engine.user_import(&schema, &user_id, &fields).await {
            Ok(record) => SigilResponse::ok(serde_json::json!({
                "status": "ok",
                "entity_id": record.entity_id,
                "fields": record.fields,
                "created_at": record.created_at,
            })),
            Err(e) => SigilResponse::error(e.to_string()),
        },

        SigilCommand::UserUpdate {
            schema,
            user_id,
            fields,
        } => match engine.user_update(&schema, &user_id, &fields).await {
            Ok(record) => SigilResponse::ok(serde_json::json!({
                "status": "ok",
                "entity_id": record.entity_id,
                "fields": record.fields,
                "updated_at": record.updated_at,
            })),
            Err(e) => SigilResponse::error(e.to_string()),
        },

        SigilCommand::UserGet { schema, user_id } => {
            let decrypt = auth_context.is_some_and(|ctx| ctx.is_platform);
            match engine.user_get(&schema, &user_id, decrypt).await {
                Ok(record) => SigilResponse::ok(serde_json::json!({
                    "entity_id": record.entity_id,
                    "fields": record.fields,
                    "created_at": record.created_at,
                    "updated_at": record.updated_at,
                })),
                Err(e) => SigilResponse::error(e.to_string()),
            }
        }

        SigilCommand::UserDelete { schema, user_id } => {
            match engine.user_delete(&schema, &user_id).await {
                Ok(()) => SigilResponse::ok_simple(),
                Err(e) => SigilResponse::error(e.to_string()),
            }
        }

        SigilCommand::UserVerify {
            schema,
            user_id,
            password,
        } => match engine.user_verify(&schema, &user_id, &password).await {
            Ok(valid) => SigilResponse::ok(serde_json::json!({
                "status": "ok",
                "valid": valid,
            })),
            Err(e) => SigilResponse::error(e.to_string()),
        },

        SigilCommand::UserLookup {
            schema,
            field_name,
            field_value,
        } => match engine.user_lookup(&schema, &field_name, &field_value).await {
            Ok(entity_id) => SigilResponse::ok(serde_json::json!({
                "status": "ok",
                "entity_id": entity_id,
            })),
            Err(e) => SigilResponse::error(e.to_string()),
        },

        // ── Session ─────────────────────────────────────────────────
        SigilCommand::SessionCreate {
            schema,
            entity_id,
            password,
            metadata,
        } => {
            match engine
                .session_create(&schema, &entity_id, &password, metadata.as_ref())
                .await
            {
                Ok(pair) => SigilResponse::ok(serde_json::json!({
                    "status": "ok",
                    "access_token": pair.access_token,
                    "refresh_token": pair.refresh_token,
                    "expires_in": pair.expires_in,
                })),
                Err(e) => SigilResponse::error(e.to_string()),
            }
        }

        SigilCommand::SessionCreateByField {
            schema,
            field_name,
            field_value,
            password,
            metadata,
        } => {
            match engine
                .session_create_by_field(
                    &schema,
                    &field_name,
                    &field_value,
                    &password,
                    metadata.as_ref(),
                )
                .await
            {
                Ok(pair) => SigilResponse::ok(serde_json::json!({
                    "status": "ok",
                    "access_token": pair.access_token,
                    "refresh_token": pair.refresh_token,
                    "expires_in": pair.expires_in,
                })),
                Err(e) => SigilResponse::error(e.to_string()),
            }
        }

        SigilCommand::SessionRefresh { schema, token } => {
            match engine.session_refresh(&schema, &token).await {
                Ok(pair) => SigilResponse::ok(serde_json::json!({
                    "status": "ok",
                    "access_token": pair.access_token,
                    "refresh_token": pair.refresh_token,
                    "expires_in": pair.expires_in,
                })),
                Err(e) => SigilResponse::error(e.to_string()),
            }
        }

        SigilCommand::SessionRevoke { schema, token } => {
            match engine.session_revoke(&schema, &token).await {
                Ok(()) => SigilResponse::ok_simple(),
                Err(e) => SigilResponse::error(e.to_string()),
            }
        }

        SigilCommand::SessionRevokeAll { schema, entity_id } => {
            match engine.session_revoke_all(&schema, &entity_id).await {
                Ok(count) => SigilResponse::ok(serde_json::json!({
                    "status": "ok",
                    "revoked": count,
                })),
                Err(e) => SigilResponse::error(e.to_string()),
            }
        }

        SigilCommand::SessionList { schema, entity_id } => {
            match engine.session_list(&schema, &entity_id).await {
                Ok(sessions) => {
                    let items: Vec<serde_json::Value> = sessions
                        .iter()
                        .map(|s| {
                            serde_json::json!({
                                "family_id": s.family_id,
                                "generation": s.generation,
                                "created_at": s.created_at,
                                "expires_at": s.expires_at,
                            })
                        })
                        .collect();
                    SigilResponse::ok(serde_json::json!(items))
                }
                Err(e) => SigilResponse::error(e.to_string()),
            }
        }

        // ── Credential (generic) ────────────────────────────────────
        SigilCommand::CredentialChange {
            schema,
            entity_id,
            field,
            old_value,
            new_value,
        } => {
            match engine
                .credential_change(&schema, &entity_id, &field, &old_value, &new_value)
                .await
            {
                Ok(()) => SigilResponse::ok_simple(),
                Err(e) => SigilResponse::error(e.to_string()),
            }
        }

        SigilCommand::CredentialReset {
            schema,
            entity_id,
            field,
            new_value,
        } => {
            match engine
                .credential_reset(&schema, &entity_id, &field, &new_value)
                .await
            {
                Ok(()) => SigilResponse::ok_simple(),
                Err(e) => SigilResponse::error(e.to_string()),
            }
        }

        SigilCommand::CredentialImport {
            schema,
            entity_id,
            field,
            hash,
            ..
        } => match engine
            .credential_import(&schema, &entity_id, &field, &hash)
            .await
        {
            Ok(algo) => SigilResponse::ok(serde_json::json!({
                "status": "ok",
                "algorithm": format!("{algo:?}").to_lowercase(),
            })),
            Err(e) => SigilResponse::error(e.to_string()),
        },

        // ── Password (sugar) ────────────────────────────────────────
        SigilCommand::PasswordChange {
            schema,
            user_id,
            old_password,
            new_password,
        } => {
            match engine
                .password_change(&schema, &user_id, &old_password, &new_password)
                .await
            {
                Ok(()) => SigilResponse::ok_simple(),
                Err(e) => SigilResponse::error(e.to_string()),
            }
        }

        SigilCommand::PasswordReset {
            schema,
            user_id,
            new_password,
        } => match engine
            .password_reset(&schema, &user_id, &new_password)
            .await
        {
            Ok(()) => SigilResponse::ok_simple(),
            Err(e) => SigilResponse::error(e.to_string()),
        },

        SigilCommand::PasswordImport {
            schema,
            user_id,
            hash,
            ..
        } => match engine.password_import(&schema, &user_id, &hash).await {
            Ok(algo) => SigilResponse::ok(serde_json::json!({
                "status": "ok",
                "algorithm": format!("{algo:?}").to_lowercase(),
            })),
            Err(e) => SigilResponse::error(e.to_string()),
        },

        // ── JWT ─────────────────────────────────────────────────────
        SigilCommand::Jwks { schema } => match engine.jwks(&schema).await {
            Ok(jwks) => SigilResponse::ok(jwks),
            Err(e) => SigilResponse::error(e.to_string()),
        },

        // ── Operational ─────────────────────────────────────────────
        SigilCommand::Health => SigilResponse::ok(serde_json::json!({
            "status": "ok",
        })),

        SigilCommand::Ping => SigilResponse::ok(serde_json::json!({
            "status": "pong",
        })),

        SigilCommand::Hello => SigilResponse::ok(serde_json::json!({
            "engine": "sigil",
            "version": env!("CARGO_PKG_VERSION"),
            "protocol": WIRE_PROTOCOL,
            "commands": SUPPORTED_COMMANDS,
            "capabilities": Vec::<&str>::new(),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::parse_command;
    use shroudb_sigil_engine::capabilities::Capabilities;
    use shroudb_sigil_engine::engine::SigilConfig;
    use shroudb_sigil_engine::jwt::JwtManager;

    async fn setup() -> SigilEngine<shroudb_storage::EmbeddedStore> {
        let store = shroudb_storage::test_util::create_test_store("sigil-test").await;
        SigilEngine::new(store, SigilConfig::default(), Capabilities::for_tests())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn full_flow_via_dispatch() {
        let engine = setup().await;

        // Register schema
        let cmd = parse_command(&[
            "SCHEMA",
            "REGISTER",
            "myapp",
            r#"{"fields":[{"name":"password","field_type":"string","kind":{"type":"credential","lockout":{"max_attempts":5,"duration_secs":900}}},{"name":"org","field_type":"string","kind":{"type":"index"}}]}"#,
        ])
        .unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());

        // Create user (USER sugar)
        let cmd = parse_command(&[
            "USER",
            "CREATE",
            "myapp",
            "user1",
            r#"{"password":"correcthorse","org":"acme"}"#,
        ])
        .unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());

        // Verify password (USER sugar)
        let cmd = parse_command(&["USER", "VERIFY", "myapp", "user1", "correcthorse"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());

        // Login (create session)
        let cmd = parse_command(&["SESSION", "CREATE", "myapp", "user1", "correcthorse"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok(), "session create failed: {resp:?}");

        // JWKS
        let cmd = parse_command(&["JWKS", "myapp"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());

        // Health
        let cmd = parse_command(&["HEALTH"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());
    }

    #[tokio::test]
    async fn envelope_flow_via_dispatch() {
        let engine = setup().await;

        // Register schema
        let cmd = parse_command(&[
            "SCHEMA",
            "REGISTER",
            "services",
            r#"{"fields":[{"name":"api_key","field_type":"string","kind":{"type":"credential","lockout":{"max_attempts":5,"duration_secs":900}}},{"name":"endpoint","field_type":"string","kind":{"type":"index"}}]}"#,
        ])
        .unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());

        // Create envelope
        let cmd = parse_command(&[
            "ENVELOPE",
            "CREATE",
            "services",
            "svc1",
            r#"{"api_key":"supersecretkey1","endpoint":"https://api.example.com"}"#,
        ])
        .unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());

        // Verify with explicit field
        let cmd = parse_command(&[
            "ENVELOPE",
            "VERIFY",
            "services",
            "svc1",
            "api_key",
            "supersecretkey1",
        ])
        .unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());
    }

    #[tokio::test]
    async fn error_on_bad_password() {
        let engine = setup().await;

        // Register + create user
        let cmd = parse_command(&[
            "SCHEMA", "REGISTER", "myapp",
            r#"{"fields":[{"name":"password","field_type":"string","kind":{"type":"credential","lockout":{"max_attempts":5,"duration_secs":900}}}]}"#,
        ]).unwrap();
        dispatch(&engine, cmd, None).await;

        let cmd = parse_command(&[
            "USER",
            "CREATE",
            "myapp",
            "user1",
            r#"{"password":"correcthorse"}"#,
        ])
        .unwrap();
        dispatch(&engine, cmd, None).await;

        // Wrong password
        let cmd = parse_command(&["USER", "VERIFY", "myapp", "user1", "wrongpassword"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(!resp.is_ok());
    }

    #[tokio::test]
    async fn schema_alter_add_field_via_dispatch() {
        let engine = setup().await;

        // Register schema
        let cmd = parse_command(&[
            "SCHEMA",
            "REGISTER",
            "evolve",
            r#"{"fields":[{"name":"password","field_type":"string","kind":{"type":"credential","lockout":{"max_attempts":5,"duration_secs":900}}},{"name":"org","field_type":"string","kind":{"type":"index"}}]}"#,
        ])
        .unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());

        // Alter: add optional field
        let cmd = parse_command(&[
            "SCHEMA",
            "ALTER",
            "evolve",
            "ADD",
            r#"{"name":"phone","field_type":"string","kind":{"type":"inert"}}"#,
        ])
        .unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok(), "schema alter failed: {resp:?}");

        // Get schema and verify version incremented
        let cmd = parse_command(&["SCHEMA", "GET", "evolve"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());
    }

    #[tokio::test]
    async fn create_envelope_with_optional_field_omitted() {
        let engine = setup().await;

        // Register schema
        let cmd = parse_command(&[
            "SCHEMA",
            "REGISTER",
            "optapp",
            r#"{"fields":[{"name":"password","field_type":"string","kind":{"type":"credential","lockout":{"max_attempts":5,"duration_secs":900}}},{"name":"org","field_type":"string","kind":{"type":"index"}}]}"#,
        ])
        .unwrap();
        dispatch(&engine, cmd, None).await;

        // ALTER: add optional field
        let cmd = parse_command(&[
            "SCHEMA",
            "ALTER",
            "optapp",
            "ADD",
            r#"{"name":"phone","field_type":"string","kind":{"type":"inert"}}"#,
        ])
        .unwrap();
        dispatch(&engine, cmd, None).await;

        // Create envelope without the optional phone field — should succeed
        let cmd = parse_command(&[
            "ENVELOPE",
            "CREATE",
            "optapp",
            "user1",
            r#"{"password":"correcthorse","org":"acme"}"#,
        ])
        .unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(
            resp.is_ok(),
            "create without optional field failed: {resp:?}"
        );

        // Create envelope WITH the optional phone field — should also succeed
        let cmd = parse_command(&[
            "ENVELOPE",
            "CREATE",
            "optapp",
            "user2",
            r#"{"password":"correcthorse","org":"acme","phone":"555-1234"}"#,
        ])
        .unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok(), "create with optional field failed: {resp:?}");
    }

    #[tokio::test]
    async fn existing_envelope_readable_after_schema_alter() {
        let engine = setup().await;

        // Register schema
        let cmd = parse_command(&[
            "SCHEMA",
            "REGISTER",
            "compat",
            r#"{"fields":[{"name":"password","field_type":"string","kind":{"type":"credential","lockout":{"max_attempts":5,"duration_secs":900}}},{"name":"org","field_type":"string","kind":{"type":"index"}}]}"#,
        ])
        .unwrap();
        dispatch(&engine, cmd, None).await;

        // Create envelope with v1 schema
        let cmd = parse_command(&[
            "ENVELOPE",
            "CREATE",
            "compat",
            "user1",
            r#"{"password":"correcthorse","org":"acme"}"#,
        ])
        .unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok(), "create envelope failed: {resp:?}");

        // ALTER: add optional field
        let cmd = parse_command(&[
            "SCHEMA",
            "ALTER",
            "compat",
            "ADD",
            r#"{"name":"phone","field_type":"string","kind":{"type":"inert"}}"#,
        ])
        .unwrap();
        dispatch(&engine, cmd, None).await;

        // Read the old envelope — should still work (backward compat)
        let cmd = parse_command(&["ENVELOPE", "GET", "compat", "user1"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(
            resp.is_ok(),
            "reading old envelope after ALTER failed: {resp:?}"
        );
    }

    // ── MED-27: Session claim enrichment ───────────────────────────

    #[tokio::test]
    async fn session_create_enriches_claim_fields() {
        let engine = setup().await;

        // Register schema with a claim-annotated field
        let cmd = parse_command(&[
            "SCHEMA",
            "REGISTER",
            "claimapp",
            r#"{"fields":[{"name":"password","field_type":"string","kind":{"type":"credential","lockout":{"max_attempts":5,"duration_secs":900}}},{"name":"role","field_type":"string","kind":{"type":"index","claim":{}}},{"name":"org","field_type":"string","kind":{"type":"index"}}]}"#,
        ])
        .unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok(), "schema register failed: {resp:?}");

        // Create user with role=admin, org=acme
        let cmd = parse_command(&[
            "USER",
            "CREATE",
            "claimapp",
            "user1",
            r#"{"password":"correcthorse","role":"admin","org":"acme"}"#,
        ])
        .unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok(), "user create failed: {resp:?}");

        // Login — should auto-enrich with role from envelope
        let cmd =
            parse_command(&["SESSION", "CREATE", "claimapp", "user1", "correcthorse"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok(), "session create failed: {resp:?}");

        // Verify access token has enriched role claim
        let body: serde_json::Value = serde_json::from_str(&resp.body()).unwrap();
        let access_token = body["access_token"].as_str().unwrap();
        let jwt = JwtManager::new(
            engine.jwt.store().clone(),
            shroudb_crypto::JwtAlgorithm::ES256,
            900,
        );
        let claims = jwt.verify("claimapp", access_token).await.unwrap();
        assert_eq!(claims["sub"], "user1");
        assert_eq!(claims["role"], "admin", "claim field 'role' not enriched");
        // org is NOT claim-annotated, should not be in JWT
        assert!(
            claims.get("org").is_none(),
            "non-claim field 'org' should not be in JWT"
        );
    }

    #[tokio::test]
    async fn session_create_enriched_overrides_caller_claims() {
        let engine = setup().await;

        // Register schema with claim-annotated role
        let cmd = parse_command(&[
            "SCHEMA",
            "REGISTER",
            "overrideapp",
            r#"{"fields":[{"name":"password","field_type":"string","kind":{"type":"credential","lockout":{"max_attempts":5,"duration_secs":900}}},{"name":"role","field_type":"string","kind":{"type":"index","claim":{}}}]}"#,
        ])
        .unwrap();
        dispatch(&engine, cmd, None).await;

        // Create user with role=viewer
        let cmd = parse_command(&[
            "USER",
            "CREATE",
            "overrideapp",
            "user1",
            r#"{"password":"correcthorse","role":"viewer"}"#,
        ])
        .unwrap();
        dispatch(&engine, cmd, None).await;

        // Login with META claiming role=admin — enrichment should override
        let cmd = parse_command(&[
            "SESSION",
            "CREATE",
            "overrideapp",
            "user1",
            "correcthorse",
            "META",
            r#"{"role":"admin","custom":"val"}"#,
        ])
        .unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok(), "session create failed: {resp:?}");

        let body: serde_json::Value = serde_json::from_str(&resp.body()).unwrap();
        let access_token = body["access_token"].as_str().unwrap();
        let jwt = JwtManager::new(
            engine.jwt.store().clone(),
            shroudb_crypto::JwtAlgorithm::ES256,
            900,
        );
        let claims = jwt.verify("overrideapp", access_token).await.unwrap();
        // Enriched role=viewer from envelope overrides caller role=admin
        assert_eq!(
            claims["role"], "viewer",
            "enriched claim should override caller"
        );
        // Non-enriched caller claims pass through
        assert_eq!(
            claims["custom"], "val",
            "non-enriched caller claim should pass through"
        );
    }

    #[tokio::test]
    async fn session_create_no_claim_fields_behaves_as_before() {
        let engine = setup().await;

        // Register schema with no claim-annotated fields
        let cmd = parse_command(&[
            "SCHEMA",
            "REGISTER",
            "noclaimapp",
            r#"{"fields":[{"name":"password","field_type":"string","kind":{"type":"credential","lockout":{"max_attempts":5,"duration_secs":900}}},{"name":"org","field_type":"string","kind":{"type":"index"}}]}"#,
        ])
        .unwrap();
        dispatch(&engine, cmd, None).await;

        let cmd = parse_command(&[
            "USER",
            "CREATE",
            "noclaimapp",
            "user1",
            r#"{"password":"correcthorse","org":"acme"}"#,
        ])
        .unwrap();
        dispatch(&engine, cmd, None).await;

        // Login with META — should be passed through as-is
        let cmd = parse_command(&[
            "SESSION",
            "CREATE",
            "noclaimapp",
            "user1",
            "correcthorse",
            "META",
            r#"{"custom":"val"}"#,
        ])
        .unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok(), "session create failed: {resp:?}");

        let body: serde_json::Value = serde_json::from_str(&resp.body()).unwrap();
        let access_token = body["access_token"].as_str().unwrap();
        let jwt = JwtManager::new(
            engine.jwt.store().clone(),
            shroudb_crypto::JwtAlgorithm::ES256,
            900,
        );
        let claims = jwt.verify("noclaimapp", access_token).await.unwrap();
        assert_eq!(claims["sub"], "user1");
        assert_eq!(claims["custom"], "val");
        // org should NOT be in JWT (no claim annotation)
        assert!(claims.get("org").is_none());
    }

    // ── MED-28: Session refresh preserves enrichment ───────────────

    #[tokio::test]
    async fn session_refresh_enriches_claims() {
        let engine = setup().await;

        // Register schema with claim-annotated role
        let cmd = parse_command(&[
            "SCHEMA",
            "REGISTER",
            "refreshapp",
            r#"{"fields":[{"name":"password","field_type":"string","kind":{"type":"credential","lockout":{"max_attempts":5,"duration_secs":900}}},{"name":"role","field_type":"string","kind":{"type":"index","claim":{}}}]}"#,
        ])
        .unwrap();
        dispatch(&engine, cmd, None).await;

        let cmd = parse_command(&[
            "USER",
            "CREATE",
            "refreshapp",
            "user1",
            r#"{"password":"correcthorse","role":"admin"}"#,
        ])
        .unwrap();
        dispatch(&engine, cmd, None).await;

        // Login
        let cmd =
            parse_command(&["SESSION", "CREATE", "refreshapp", "user1", "correcthorse"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        let body: serde_json::Value = serde_json::from_str(&resp.body()).unwrap();
        let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

        // Refresh — should auto-enrich with current role from envelope
        let cmd = parse_command(&["SESSION", "REFRESH", "refreshapp", &refresh_token]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok(), "session refresh failed: {resp:?}");

        let body: serde_json::Value = serde_json::from_str(&resp.body()).unwrap();
        let access_token = body["access_token"].as_str().unwrap();
        let jwt = JwtManager::new(
            engine.jwt.store().clone(),
            shroudb_crypto::JwtAlgorithm::ES256,
            900,
        );
        let claims = jwt.verify("refreshapp", access_token).await.unwrap();
        assert_eq!(claims["sub"], "user1");
        assert_eq!(
            claims["role"], "admin",
            "refreshed token should have enriched role"
        );
    }

    #[tokio::test]
    async fn session_refresh_reflects_role_change() {
        let engine = setup().await;

        // Register schema with claim-annotated role
        let cmd = parse_command(&[
            "SCHEMA",
            "REGISTER",
            "rolechangeapp",
            r#"{"fields":[{"name":"password","field_type":"string","kind":{"type":"credential","lockout":{"max_attempts":5,"duration_secs":900}}},{"name":"role","field_type":"string","kind":{"type":"index","claim":{}}}]}"#,
        ])
        .unwrap();
        dispatch(&engine, cmd, None).await;

        let cmd = parse_command(&[
            "USER",
            "CREATE",
            "rolechangeapp",
            "user1",
            r#"{"password":"correcthorse","role":"admin"}"#,
        ])
        .unwrap();
        dispatch(&engine, cmd, None).await;

        // Login
        let cmd = parse_command(&[
            "SESSION",
            "CREATE",
            "rolechangeapp",
            "user1",
            "correcthorse",
        ])
        .unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        let body: serde_json::Value = serde_json::from_str(&resp.body()).unwrap();
        let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

        // Change role via envelope update
        let cmd = parse_command(&[
            "ENVELOPE",
            "UPDATE",
            "rolechangeapp",
            "user1",
            r#"{"role":"viewer"}"#,
        ])
        .unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok(), "envelope update failed: {resp:?}");

        // Refresh — should pick up new role
        let cmd = parse_command(&["SESSION", "REFRESH", "rolechangeapp", &refresh_token]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok(), "session refresh failed: {resp:?}");

        let body: serde_json::Value = serde_json::from_str(&resp.body()).unwrap();
        let access_token = body["access_token"].as_str().unwrap();
        let jwt = JwtManager::new(
            engine.jwt.store().clone(),
            shroudb_crypto::JwtAlgorithm::ES256,
            900,
        );
        let claims = jwt.verify("rolechangeapp", access_token).await.unwrap();
        assert_eq!(
            claims["role"], "viewer",
            "refreshed token should reflect updated role"
        );
    }

    #[tokio::test]
    async fn session_refresh_no_claim_fields_has_sub_only() {
        let engine = setup().await;

        // Schema with no claim fields
        let cmd = parse_command(&[
            "SCHEMA",
            "REGISTER",
            "noclaimrefresh",
            r#"{"fields":[{"name":"password","field_type":"string","kind":{"type":"credential","lockout":{"max_attempts":5,"duration_secs":900}}},{"name":"org","field_type":"string","kind":{"type":"index"}}]}"#,
        ])
        .unwrap();
        dispatch(&engine, cmd, None).await;

        let cmd = parse_command(&[
            "USER",
            "CREATE",
            "noclaimrefresh",
            "user1",
            r#"{"password":"correcthorse","org":"acme"}"#,
        ])
        .unwrap();
        dispatch(&engine, cmd, None).await;

        // Login with no extra claims
        let cmd = parse_command(&[
            "SESSION",
            "CREATE",
            "noclaimrefresh",
            "user1",
            "correcthorse",
        ])
        .unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        let body: serde_json::Value = serde_json::from_str(&resp.body()).unwrap();
        let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

        // Refresh
        let cmd = parse_command(&["SESSION", "REFRESH", "noclaimrefresh", &refresh_token]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok(), "session refresh failed: {resp:?}");

        let body: serde_json::Value = serde_json::from_str(&resp.body()).unwrap();
        let access_token = body["access_token"].as_str().unwrap();
        let jwt = JwtManager::new(
            engine.jwt.store().clone(),
            shroudb_crypto::JwtAlgorithm::ES256,
            900,
        );
        let claims = jwt.verify("noclaimrefresh", access_token).await.unwrap();
        assert_eq!(claims["sub"], "user1");
        assert!(claims.get("org").is_none());
    }
}
