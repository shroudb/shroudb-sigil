use shroudb_acl::AuthContext;
use shroudb_sigil_engine::engine::SigilEngine;
use shroudb_store::Store;

use crate::commands::SigilCommand;
use crate::response::SigilResponse;

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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::parse_command;
    use shroudb_sigil_engine::capabilities::Capabilities;
    use shroudb_sigil_engine::engine::SigilConfig;

    async fn setup() -> SigilEngine<shroudb_storage::EmbeddedStore> {
        let store = shroudb_storage::test_util::create_test_store("sigil-test").await;
        SigilEngine::new(store, SigilConfig::default(), Capabilities::default())
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
            r#"{"fields":[{"name":"password","field_type":"string","annotations":{"credential":true}},{"name":"org","field_type":"string","annotations":{"index":true}}]}"#,
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
            r#"{"fields":[{"name":"api_key","field_type":"string","annotations":{"credential":true}},{"name":"endpoint","field_type":"string","annotations":{"index":true}}]}"#,
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
            r#"{"fields":[{"name":"password","field_type":"string","annotations":{"credential":true}}]}"#,
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
}
