use shroudb_sigil_engine::engine::SigilEngine;
use shroudb_store::Store;

use crate::commands::SigilCommand;
use crate::response::SigilResponse;

/// Dispatch a parsed command to the SigilEngine and produce a response.
pub async fn dispatch<S: Store>(engine: &SigilEngine<S>, cmd: SigilCommand) -> SigilResponse {
    match cmd {
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

        // ── User ────────────────────────────────────────────────────
        SigilCommand::UserCreate {
            schema,
            user_id,
            fields,
        } => match engine.user_create(&schema, &user_id, &fields).await {
            Ok(record) => SigilResponse::ok(serde_json::json!({
                "status": "ok",
                "user_id": record.user_id,
                "fields": record.fields,
                "created_at": record.created_at,
            })),
            Err(e) => SigilResponse::error(e.to_string()),
        },

        SigilCommand::UserGet { schema, user_id } => {
            match engine.user_get(&schema, &user_id).await {
                Ok(record) => SigilResponse::ok(serde_json::json!({
                    "user_id": record.user_id,
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

        // ── Session ─────────────────────────────────────────────────
        SigilCommand::SessionCreate {
            schema,
            user_id,
            password,
            metadata,
        } => {
            match engine
                .session_create(&schema, &user_id, &password, metadata.as_ref())
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

        SigilCommand::SessionRevokeAll { schema, user_id } => {
            match engine.session_revoke_all(&schema, &user_id).await {
                Ok(count) => SigilResponse::ok(serde_json::json!({
                    "status": "ok",
                    "revoked": count,
                })),
                Err(e) => SigilResponse::error(e.to_string()),
            }
        }

        SigilCommand::SessionList { schema, user_id } => {
            match engine.session_list(&schema, &user_id).await {
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

        // ── Password ────────────────────────────────────────────────
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
    use std::sync::Arc;

    use super::*;
    use crate::commands::parse_command;
    use shroudb_sigil_engine::capabilities::Capabilities;
    use shroudb_sigil_engine::engine::SigilConfig;

    async fn setup() -> SigilEngine<shroudb_storage::EmbeddedStore> {
        let store = create_test_store().await;
        SigilEngine::new(store, SigilConfig::default(), Capabilities::default())
            .await
            .unwrap()
    }

    async fn create_test_store() -> Arc<shroudb_storage::EmbeddedStore> {
        let dir = tempfile::tempdir().unwrap().keep();
        let config = shroudb_storage::StorageEngineConfig {
            data_dir: dir,
            ..Default::default()
        };
        let engine = shroudb_storage::StorageEngine::open(config, &EphemeralKey)
            .await
            .unwrap();
        Arc::new(shroudb_storage::EmbeddedStore::new(
            Arc::new(engine),
            "sigil-test",
        ))
    }

    struct EphemeralKey;
    impl shroudb_storage::MasterKeySource for EphemeralKey {
        fn source_name(&self) -> &str {
            "ephemeral-test"
        }
        fn load<'a>(
            &'a self,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<shroudb_crypto::SecretBytes, shroudb_storage::StorageError>,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Ok(shroudb_crypto::SecretBytes::new(vec![0x42u8; 32])) })
        }
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
        let resp = dispatch(&engine, cmd).await;
        assert!(resp.is_ok());

        // Create user
        let cmd = parse_command(&[
            "USER",
            "CREATE",
            "myapp",
            "user1",
            r#"{"password":"correcthorse","org":"acme"}"#,
        ])
        .unwrap();
        let resp = dispatch(&engine, cmd).await;
        assert!(resp.is_ok());

        // Verify password
        let cmd = parse_command(&["USER", "VERIFY", "myapp", "user1", "correcthorse"]).unwrap();
        let resp = dispatch(&engine, cmd).await;
        assert!(resp.is_ok());

        // Login (create session)
        let cmd = parse_command(&["SESSION", "CREATE", "myapp", "user1", "correcthorse"]).unwrap();
        let resp = dispatch(&engine, cmd).await;
        assert!(resp.is_ok(), "session create failed: {resp:?}");

        // JWKS
        let cmd = parse_command(&["JWKS", "myapp"]).unwrap();
        let resp = dispatch(&engine, cmd).await;
        assert!(resp.is_ok());

        // Health
        let cmd = parse_command(&["HEALTH"]).unwrap();
        let resp = dispatch(&engine, cmd).await;
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
        dispatch(&engine, cmd).await;

        let cmd = parse_command(&[
            "USER",
            "CREATE",
            "myapp",
            "user1",
            r#"{"password":"correcthorse"}"#,
        ])
        .unwrap();
        dispatch(&engine, cmd).await;

        // Wrong password
        let cmd = parse_command(&["USER", "VERIFY", "myapp", "user1", "wrongpassword"]).unwrap();
        let resp = dispatch(&engine, cmd).await;
        assert!(!resp.is_ok());
    }
}
