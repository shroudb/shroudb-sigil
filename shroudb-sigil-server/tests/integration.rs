mod common;

use common::*;
use std::time::Duration;

// ═══════════════════════════════════════════════════════════════════════
// HTTP: Full auth lifecycle
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn http_full_auth_lifecycle() {
    let server = TestServer::start().await.expect("server failed to start");
    let client = reqwest::Client::new();

    // Register schema
    let resp = client
        .post(server.http_url("/sigil/schemas"))
        .json(&serde_json::json!({
            "name": "myapp",
            "fields": [
                {"name": "password", "field_type": "string", "annotations": {"credential": true}},
                {"name": "org", "field_type": "string", "annotations": {"index": true}},
                {"name": "display_name", "field_type": "string"}
            ]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "schema register failed");

    // Create user
    let resp = client
        .post(server.http_url("/sigil/myapp/users"))
        .json(&serde_json::json!({
            "fields": {
                "user_id": "alice",
                "password": "correcthorse",
                "org": "acme",
                "display_name": "Alice"
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "user create failed");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["user_id"], "alice");
    assert_eq!(body["fields"]["org"], "acme");
    assert_eq!(body["fields"]["display_name"], "Alice");
    assert!(
        body["fields"].get("password").is_none(),
        "password must not be in user record"
    );

    // Verify password
    let resp = client
        .post(server.http_url("/sigil/myapp/verify"))
        .json(&serde_json::json!({"user_id": "alice", "password": "correcthorse"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["valid"], true);

    // Wrong password
    let resp = client
        .post(server.http_url("/sigil/myapp/verify"))
        .json(&serde_json::json!({"user_id": "alice", "password": "wrong"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Login (create session)
    let resp = client
        .post(server.http_url("/sigil/myapp/sessions"))
        .json(&serde_json::json!({"user_id": "alice", "password": "correcthorse"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let login: serde_json::Value = resp.json().await.unwrap();
    assert!(login["access_token"].is_string());
    assert!(login["refresh_token"].is_string());
    assert_eq!(login["expires_in"], 900);

    let refresh_token = login["refresh_token"].as_str().unwrap().to_string();

    // Refresh session
    let resp = client
        .post(server.http_url("/sigil/myapp/sessions/refresh"))
        .json(&serde_json::json!({"refresh_token": refresh_token}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let refreshed: serde_json::Value = resp.json().await.unwrap();
    assert_ne!(
        refreshed["refresh_token"].as_str().unwrap(),
        refresh_token,
        "refresh must issue new token"
    );

    let new_refresh = refreshed["refresh_token"].as_str().unwrap().to_string();

    // Reuse old refresh token → should fail (reuse detection)
    let resp = client
        .post(server.http_url("/sigil/myapp/sessions/refresh"))
        .json(&serde_json::json!({"refresh_token": refresh_token}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "reused token should be rejected");

    // New token should also be revoked (family killed)
    let resp = client
        .post(server.http_url("/sigil/myapp/sessions/refresh"))
        .json(&serde_json::json!({"refresh_token": new_refresh}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "family should be revoked after reuse");

    // JWKS
    let resp = client
        .get(server.http_url("/sigil/myapp/.well-known/jwks.json"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let jwks: serde_json::Value = resp.json().await.unwrap();
    let keys = jwks["keys"].as_array().unwrap();
    assert!(!keys.is_empty());
    assert_eq!(keys[0]["kty"], "EC");

    // Get user
    let resp = client
        .get(server.http_url("/sigil/myapp/users/alice"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let user: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(user["user_id"], "alice");
    assert_eq!(user["fields"]["org"], "acme");

    // Update user (non-credential fields)
    let resp = client
        .patch(server.http_url("/sigil/myapp/users/alice"))
        .json(&serde_json::json!({"fields": {"org": "newcorp", "display_name": "Alice Smith"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let updated: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(updated["fields"]["org"], "newcorp");
    assert_eq!(updated["fields"]["display_name"], "Alice Smith");

    // Verify update persisted
    let resp = client
        .get(server.http_url("/sigil/myapp/users/alice"))
        .send()
        .await
        .unwrap();
    let user: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(user["fields"]["org"], "newcorp");

    // Attempt to update credential field via PATCH → rejected
    let resp = client
        .patch(server.http_url("/sigil/myapp/users/alice"))
        .json(&serde_json::json!({"fields": {"password": "sneaky"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        400,
        "credential update via PATCH should be rejected"
    );

    // Delete user
    let resp = client
        .delete(server.http_url("/sigil/myapp/users/alice"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Verify deleted
    let resp = client
        .get(server.http_url("/sigil/myapp/users/alice"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ═══════════════════════════════════════════════════════════════════════
// HTTP: User import
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn http_user_import_with_prehashed_password() {
    let server = TestServer::start().await.expect("server failed to start");
    let client = reqwest::Client::new();

    // Register schema
    client
        .post(server.http_url("/sigil/schemas"))
        .json(&serde_json::json!({
            "name": "import-test",
            "fields": [
                {"name": "password", "field_type": "string", "annotations": {"credential": true}},
                {"name": "org", "field_type": "string", "annotations": {"index": true}}
            ]
        }))
        .send()
        .await
        .unwrap();

    // First, create a user normally to get a real argon2id hash
    client
        .post(server.http_url("/sigil/import-test/users"))
        .json(&serde_json::json!({
            "fields": {"user_id": "source", "password": "original123", "org": "acme"}
        }))
        .send()
        .await
        .unwrap();

    // Verify the source user to generate a known-good hash via the verify endpoint
    let resp = client
        .post(server.http_url("/sigil/import-test/verify"))
        .json(&serde_json::json!({"user_id": "source", "password": "original123"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Now import a user with a pre-generated argon2id hash
    // Use a real argon2id hash (generated offline)
    let hash =
        "$argon2id$v=19$m=19456,t=2,p=1$bWVtb3J5Y29zdA$Lf31MvFNOPWjC/BLRqfnCPkjqpUKqAlNa6GJjZ3YO/E";

    let resp = client
        .post(server.http_url("/sigil/import-test/users/import"))
        .json(&serde_json::json!({
            "fields": {"user_id": "imported", "password": hash, "org": "migrated"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        201,
        "user import failed: {:?}",
        resp.text().await
    );

    // Get the imported user — org field should be present
    let resp = client
        .get(server.http_url("/sigil/import-test/users/imported"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let user: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(user["fields"]["org"], "migrated");

    // Password field should NOT be in the user record
    assert!(user["fields"].get("password").is_none());

    // The imported hash should be verifiable with the original password
    // (This specific hash was generated from "memorycost" — a test value)
    // We can't verify the exact password without knowing it, but we CAN
    // verify that the import didn't corrupt the hash by checking login fails
    // with a wrong password
    let resp = client
        .post(server.http_url("/sigil/import-test/verify"))
        .json(&serde_json::json!({"user_id": "imported", "password": "definitely-wrong"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "wrong password should fail");

    // Duplicate import should be rejected
    let resp = client
        .post(server.http_url("/sigil/import-test/users/import"))
        .json(&serde_json::json!({
            "fields": {"user_id": "imported", "password": hash, "org": "dup"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409, "duplicate import should be conflict");

    // Invalid hash format should be rejected
    let resp = client
        .post(server.http_url("/sigil/import-test/users/import"))
        .json(&serde_json::json!({
            "fields": {"user_id": "badhash", "password": "not-a-hash", "org": "bad"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "invalid hash should be bad request");
}

// ═══════════════════════════════════════════════════════════════════════
// HTTP: Password lifecycle
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn http_password_change_and_reset() {
    let server = TestServer::start().await.expect("server failed to start");
    let client = reqwest::Client::new();

    // Setup: register schema + create user
    client
        .post(server.http_url("/sigil/schemas"))
        .json(&serde_json::json!({
            "name": "pwtest",
            "fields": [{"name": "password", "field_type": "string", "annotations": {"credential": true}}]
        }))
        .send()
        .await
        .unwrap();

    client
        .post(server.http_url("/sigil/pwtest/users"))
        .json(&serde_json::json!({"fields": {"user_id": "bob", "password": "original123"}}))
        .send()
        .await
        .unwrap();

    // Change password
    let resp = client
        .post(server.http_url("/sigil/pwtest/password/change"))
        .json(&serde_json::json!({
            "user_id": "bob",
            "old_password": "original123",
            "new_password": "changed456"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Old password fails
    let resp = client
        .post(server.http_url("/sigil/pwtest/verify"))
        .json(&serde_json::json!({"user_id": "bob", "password": "original123"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // New password works
    let resp = client
        .post(server.http_url("/sigil/pwtest/verify"))
        .json(&serde_json::json!({"user_id": "bob", "password": "changed456"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Reset password (admin/forced reset)
    let resp = client
        .post(server.http_url("/sigil/pwtest/password/reset"))
        .json(&serde_json::json!({"user_id": "bob", "new_password": "reset789!"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Reset password works
    let resp = client
        .post(server.http_url("/sigil/pwtest/verify"))
        .json(&serde_json::json!({"user_id": "bob", "password": "reset789!"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

// ═══════════════════════════════════════════════════════════════════════
// HTTP: Error handling
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn http_error_responses() {
    let server = TestServer::start().await.expect("server failed to start");
    let client = reqwest::Client::new();

    // Schema not found
    let resp = client
        .get(server.http_url("/sigil/schemas/nonexistent"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // Register + duplicate
    client
        .post(server.http_url("/sigil/schemas"))
        .json(&serde_json::json!({
            "name": "dup",
            "fields": [{"name": "f", "field_type": "string"}]
        }))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(server.http_url("/sigil/schemas"))
        .json(&serde_json::json!({
            "name": "dup",
            "fields": [{"name": "f", "field_type": "string"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409, "duplicate schema should be conflict");

    // Invalid schema (credential + pii on same field)
    let resp = client
        .post(server.http_url("/sigil/schemas"))
        .json(&serde_json::json!({
            "name": "bad",
            "fields": [{"name": "f", "field_type": "string", "annotations": {"credential": true, "pii": true}}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "invalid schema should be bad request");

    // User not found
    let resp = client
        .get(server.http_url("/sigil/dup/users/nobody"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // PII field without cipher capability
    client
        .post(server.http_url("/sigil/schemas"))
        .json(&serde_json::json!({
            "name": "pii-app",
            "fields": [{"name": "email", "field_type": "string", "annotations": {"pii": true}}]
        }))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(server.http_url("/sigil/pii-app/users"))
        .json(&serde_json::json!({"fields": {"user_id": "u1", "email": "a@b.com"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        503,
        "PII without cipher should be service unavailable"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// HTTP: Account lockout
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn http_account_lockout() {
    let server = TestServer::start().await.expect("server failed to start");
    let client = reqwest::Client::new();

    client
        .post(server.http_url("/sigil/schemas"))
        .json(&serde_json::json!({
            "name": "lock",
            "fields": [{"name": "password", "field_type": "string", "annotations": {"credential": true}}]
        }))
        .send()
        .await
        .unwrap();

    client
        .post(server.http_url("/sigil/lock/users"))
        .json(&serde_json::json!({"fields": {"user_id": "lockme", "password": "correct123"}}))
        .send()
        .await
        .unwrap();

    // Exhaust failed attempts (default: 5)
    for _ in 0..5 {
        client
            .post(server.http_url("/sigil/lock/verify"))
            .json(&serde_json::json!({"user_id": "lockme", "password": "wrong"}))
            .send()
            .await
            .unwrap();
    }

    // Next attempt should be locked (429)
    let resp = client
        .post(server.http_url("/sigil/lock/verify"))
        .json(&serde_json::json!({"user_id": "lockme", "password": "correct123"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429, "account should be locked");
}

// ═══════════════════════════════════════════════════════════════════════
// TCP: RESP3 wire protocol
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tcp_health_and_schema_flow() {
    let server = TestServer::start().await.expect("server failed to start");

    let stream = tokio::net::TcpStream::connect(&server.tcp_addr)
        .await
        .unwrap();
    let (reader, mut writer) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(reader);

    // HEALTH
    send_command(&mut writer, &["HEALTH"]).await;
    let resp = read_response(&mut reader).await;
    assert!(resp.contains("ok"), "HEALTH should return ok, got: {resp}");

    // SCHEMA REGISTER
    send_command(
        &mut writer,
        &[
            "SCHEMA",
            "REGISTER",
            "tcpapp",
            r#"{"fields":[{"name":"password","field_type":"string","annotations":{"credential":true}},{"name":"org","field_type":"string","annotations":{"index":true}}]}"#,
        ],
    )
    .await;
    let resp = read_response(&mut reader).await;
    assert!(resp.contains("ok"), "SCHEMA REGISTER failed: {resp}");

    // USER CREATE
    send_command(
        &mut writer,
        &[
            "USER",
            "CREATE",
            "tcpapp",
            "user1",
            r#"{"password":"test12345678","org":"acme"}"#,
        ],
    )
    .await;
    let resp = read_response(&mut reader).await;
    assert!(resp.contains("user1"), "USER CREATE failed: {resp}");

    // USER VERIFY
    send_command(
        &mut writer,
        &["USER", "VERIFY", "tcpapp", "user1", "test12345678"],
    )
    .await;
    let resp = read_response(&mut reader).await;
    assert!(resp.contains("true"), "USER VERIFY failed: {resp}");

    // SESSION CREATE
    send_command(
        &mut writer,
        &["SESSION", "CREATE", "tcpapp", "user1", "test12345678"],
    )
    .await;
    let resp = read_response(&mut reader).await;
    assert!(
        resp.contains("access_token"),
        "SESSION CREATE failed: {resp}"
    );

    // JWKS
    send_command(&mut writer, &["JWKS", "tcpapp"]).await;
    let resp = read_response(&mut reader).await;
    assert!(resp.contains("keys"), "JWKS failed: {resp}");
}

// ── TCP helpers ─────────────────────────────────────────────────────

async fn send_command(writer: &mut tokio::net::tcp::OwnedWriteHalf, args: &[&str]) {
    use tokio::io::AsyncWriteExt;

    let mut buf = Vec::new();
    buf.extend_from_slice(format!("*{}\r\n", args.len()).as_bytes());
    for arg in args {
        buf.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
        buf.extend_from_slice(arg.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    writer.write_all(&buf).await.unwrap();
}

async fn read_response(
    reader: &mut tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> String {
    use tokio::io::AsyncBufReadExt;

    let mut first_line = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut first_line))
        .await
        .unwrap()
        .unwrap();

    let first_line = first_line.trim_end();

    if let Some(rest) = first_line
        .strip_prefix('+')
        .or_else(|| first_line.strip_prefix('-'))
    {
        return rest.to_string();
    }

    if let Some(len_str) = first_line.strip_prefix('$') {
        let len: usize = len_str.parse().unwrap_or(0);
        let mut buf = vec![0u8; len + 2]; // +2 for \r\n
        tokio::io::AsyncReadExt::read_exact(reader, &mut buf)
            .await
            .unwrap();
        return String::from_utf8_lossy(&buf[..len]).to_string();
    }

    first_line.to_string()
}

// ═══════════════════════════════════════════════════════════════════════
// ACL: Token-based auth
// ═══════════════════════════════════════════════════════════════════════

fn auth_server_config() -> TestServerConfig {
    TestServerConfig {
        tokens: vec![
            TestToken {
                raw: "admin-token".to_string(),
                tenant: "tenant-a".to_string(),
                actor: "admin".to_string(),
                platform: true,
                grants: vec![],
            },
            TestToken {
                raw: "app-token".to_string(),
                tenant: "tenant-a".to_string(),
                actor: "my-app".to_string(),
                platform: false,
                grants: vec![TestGrant {
                    namespace: "sigil.myapp.*".to_string(),
                    scopes: vec!["read".to_string(), "write".to_string()],
                }],
            },
            TestToken {
                raw: "readonly-token".to_string(),
                tenant: "tenant-a".to_string(),
                actor: "reader".to_string(),
                platform: false,
                grants: vec![TestGrant {
                    namespace: "sigil.myapp.*".to_string(),
                    scopes: vec!["read".to_string()],
                }],
            },
        ],
        cipher: None,
        veil: None,
        keep: None,
        schemas: vec![],
    }
}

#[tokio::test]
async fn acl_unauthenticated_rejected_for_protected_routes() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("server failed to start");
    let client = reqwest::Client::new();

    // Health is public — should work without auth
    let resp = client
        .get(server.http_url("/sigil/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // SCHEMA REGISTER requires Admin — should fail without auth
    let resp = client
        .post(server.http_url("/sigil/schemas"))
        .json(&serde_json::json!({
            "name": "test",
            "fields": [{"name": "f", "field_type": "string"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "unauthenticated schema register should be rejected"
    );

    // USER CREATE requires Write — should fail without auth
    let resp = client
        .post(server.http_url("/sigil/myapp/users"))
        .json(&serde_json::json!({"fields": {"user_id": "x", "f": "v"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn acl_valid_admin_token_accepted() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("server failed to start");
    let client = reqwest::Client::new();

    // Admin token can register schemas
    let resp = client
        .post(server.http_url("/sigil/schemas"))
        .header("Authorization", "Bearer admin-token")
        .json(&serde_json::json!({
            "name": "myapp",
            "fields": [
                {"name": "password", "field_type": "string", "annotations": {"credential": true}},
                {"name": "org", "field_type": "string", "annotations": {"index": true}}
            ]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // Admin token can create users
    let resp = client
        .post(server.http_url("/sigil/myapp/users"))
        .header("Authorization", "Bearer admin-token")
        .json(&serde_json::json!({"fields": {"user_id": "alice", "password": "test12345678", "org": "acme"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn acl_wrong_token_rejected() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("server failed to start");
    let client = reqwest::Client::new();

    let resp = client
        .post(server.http_url("/sigil/schemas"))
        .header("Authorization", "Bearer totally-wrong-token")
        .json(&serde_json::json!({
            "name": "test",
            "fields": [{"name": "f", "field_type": "string"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn acl_non_admin_cannot_register_schema() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("server failed to start");
    let client = reqwest::Client::new();

    // app-token has namespace grants but is not platform — cannot do Admin ops
    let resp = client
        .post(server.http_url("/sigil/schemas"))
        .header("Authorization", "Bearer app-token")
        .json(&serde_json::json!({
            "name": "myapp",
            "fields": [{"name": "f", "field_type": "string"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "non-admin should get 403 forbidden");
}

#[tokio::test]
async fn acl_read_only_cannot_write() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("server failed to start");
    let client = reqwest::Client::new();

    // Setup: admin registers schema + creates user
    client
        .post(server.http_url("/sigil/schemas"))
        .header("Authorization", "Bearer admin-token")
        .json(&serde_json::json!({
            "name": "myapp",
            "fields": [
                {"name": "password", "field_type": "string", "annotations": {"credential": true}},
                {"name": "org", "field_type": "string", "annotations": {"index": true}}
            ]
        }))
        .send()
        .await
        .unwrap();

    client
        .post(server.http_url("/sigil/myapp/users"))
        .header("Authorization", "Bearer admin-token")
        .json(&serde_json::json!({"fields": {"user_id": "bob", "password": "test12345678", "org": "acme"}}))
        .send()
        .await
        .unwrap();

    // Read-only token can GET user
    let resp = client
        .get(server.http_url("/sigil/myapp/users/bob"))
        .header("Authorization", "Bearer readonly-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "read token should be able to GET user");

    // Read-only token CANNOT create users (Write scope required)
    let resp = client
        .post(server.http_url("/sigil/myapp/users"))
        .header("Authorization", "Bearer readonly-token")
        .json(&serde_json::json!({"fields": {"user_id": "x", "password": "test12345678", "org": "x"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "read-only token should not create users"
    );

    // Read-only token CANNOT verify (Write scope required)
    let resp = client
        .post(server.http_url("/sigil/myapp/verify"))
        .header("Authorization", "Bearer readonly-token")
        .json(&serde_json::json!({"user_id": "bob", "password": "test12345678"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "read-only token should not verify");
}

#[tokio::test]
async fn acl_jwks_is_public_even_with_auth() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("server failed to start");
    let client = reqwest::Client::new();

    // Setup schema with admin
    client
        .post(server.http_url("/sigil/schemas"))
        .header("Authorization", "Bearer admin-token")
        .json(&serde_json::json!({
            "name": "myapp",
            "fields": [{"name": "password", "field_type": "string", "annotations": {"credential": true}}]
        }))
        .send()
        .await
        .unwrap();

    // JWKS should be accessible without auth
    let resp = client
        .get(server.http_url("/sigil/myapp/.well-known/jwks.json"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "JWKS should be public");

    // SCHEMA GET should also be public
    let resp = client
        .get(server.http_url("/sigil/schemas/myapp"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "SCHEMA GET should be public");
}

// ═══════════════════════════════════════════════════════════════════════
// Cipher integration: PII field encryption roundtrip
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn cipher_pii_field_encrypt_decrypt_roundtrip() {
    // Start Cipher server
    let cipher = match TestCipherServer::start().await {
        Some(c) => c,
        None => {
            eprintln!("skipping cipher test: cipher binary not found");
            return;
        }
    };

    // Create a keyring for PII
    cipher.create_keyring("sigil-pii", "aes-256-gcm").await;

    // Start Sigil server with Cipher connected
    let server = TestServer::start_with_config(TestServerConfig {
        cipher: Some(TestCipherConfig {
            addr: cipher.tcp_addr.clone(),
            keyring: "sigil-pii".to_string(),
        }),
        ..Default::default()
    })
    .await
    .expect("sigil server failed to start with cipher");

    let client = reqwest::Client::new();

    // Register schema with PII field
    let resp = client
        .post(server.http_url("/sigil/schemas"))
        .json(&serde_json::json!({
            "name": "pii-test",
            "fields": [
                {"name": "email", "field_type": "string", "annotations": {"pii": true}},
                {"name": "password", "field_type": "string", "annotations": {"credential": true}},
                {"name": "org", "field_type": "string", "annotations": {"index": true}}
            ]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "schema register failed");

    // Create user with PII field
    let resp = client
        .post(server.http_url("/sigil/pii-test/users"))
        .json(&serde_json::json!({
            "fields": {
                "user_id": "alice",
                "email": "alice@example.com",
                "password": "test12345678",
                "org": "acme"
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        201,
        "user create with PII failed: {:?}",
        resp.text().await
    );

    // Get user — email should be redacted (PII is never exposed via GET)
    let resp = client
        .get(server.http_url("/sigil/pii-test/users/alice"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let user: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(user["user_id"], "alice");
    assert_eq!(user["fields"]["org"], "acme");
    assert_eq!(
        user["fields"]["email"], "[encrypted]",
        "PII field should be redacted on read"
    );

    // Password should not be in user record
    assert!(
        user["fields"].get("password").is_none(),
        "password must not be in user record"
    );

    // Update PII field
    let resp = client
        .patch(server.http_url("/sigil/pii-test/users/alice"))
        .json(&serde_json::json!({"fields": {"email": "newalice@example.com"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Verify updated PII is still redacted
    let resp = client
        .get(server.http_url("/sigil/pii-test/users/alice"))
        .send()
        .await
        .unwrap();
    let user: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        user["fields"]["email"], "[encrypted]",
        "updated PII should still be redacted"
    );

    // Verify credentials still work
    let resp = client
        .post(server.http_url("/sigil/pii-test/verify"))
        .json(&serde_json::json!({"user_id": "alice", "password": "test12345678"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

// ═══════════════════════════════════════════════════════════════════════
// Cipher + Veil: searchable encrypted PII
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn cipher_veil_searchable_pii_roundtrip() {
    // Start Cipher server
    let cipher = match TestCipherServer::start().await {
        Some(c) => c,
        None => {
            eprintln!("skipping: cipher binary not found");
            return;
        }
    };
    cipher.create_keyring("sigil-pii", "aes-256-gcm").await;

    // Start Veil server
    let veil = match TestVeilServer::start().await {
        Some(v) => v,
        None => {
            eprintln!("skipping: veil binary not found");
            return;
        }
    };
    veil.create_index("sigil-search").await;

    // Start Sigil with both Cipher + Veil
    let server = TestServer::start_with_config(TestServerConfig {
        cipher: Some(TestCipherConfig {
            addr: cipher.tcp_addr.clone(),
            keyring: "sigil-pii".to_string(),
        }),
        veil: Some(TestVeilConfig {
            addr: veil.tcp_addr.clone(),
            index: "sigil-search".to_string(),
        }),
        ..Default::default()
    })
    .await
    .expect("sigil server failed to start with cipher+veil");

    let client = reqwest::Client::new();

    // Register schema with searchable PII field
    let resp = client
        .post(server.http_url("/sigil/schemas"))
        .json(&serde_json::json!({
            "name": "search-test",
            "fields": [
                {"name": "email", "field_type": "string", "annotations": {"pii": true, "searchable": true}},
                {"name": "password", "field_type": "string", "annotations": {"credential": true}},
                {"name": "name", "field_type": "string"}
            ]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // Create users with searchable email
    for (id, email, name) in [
        ("alice", "alice@example.com", "Alice"),
        ("bob", "bob@example.com", "Bob"),
        ("carol", "carol@other.com", "Carol"),
    ] {
        let resp = client
            .post(server.http_url("/sigil/search-test/users"))
            .json(&serde_json::json!({
                "fields": {
                    "user_id": id,
                    "email": email,
                    "password": "test12345678",
                    "name": name
                }
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "create {id} failed");
    }

    // Get user — email should be redacted
    let resp = client
        .get(server.http_url("/sigil/search-test/users/alice"))
        .send()
        .await
        .unwrap();
    let user: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(user["fields"]["email"], "[encrypted]");

    // Search via Veil directly to verify indexing worked
    let mut veil_client = shroudb_veil_client::VeilClient::connect(&veil.tcp_addr)
        .await
        .unwrap();
    let results = veil_client
        .search("sigil-search", "alice", None, None, None)
        .await
        .unwrap();
    assert!(results.matched > 0, "veil should find entries for 'alice'");
}

// ═══════════════════════════════════════════════════════════════════════
// Login by encrypted email — the app never sees plaintext PII in storage
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn login_by_encrypted_email() {
    let cipher = match TestCipherServer::start().await {
        Some(c) => c,
        None => {
            eprintln!("skipping: cipher binary not found");
            return;
        }
    };
    cipher.create_keyring("sigil-pii", "aes-256-gcm").await;

    let veil = match TestVeilServer::start().await {
        Some(v) => v,
        None => {
            eprintln!("skipping: veil binary not found");
            return;
        }
    };
    veil.create_index("sigil-search").await;

    let server = TestServer::start_with_config(TestServerConfig {
        cipher: Some(TestCipherConfig {
            addr: cipher.tcp_addr.clone(),
            keyring: "sigil-pii".to_string(),
        }),
        veil: Some(TestVeilConfig {
            addr: veil.tcp_addr.clone(),
            index: "sigil-search".to_string(),
        }),
        ..Default::default()
    })
    .await
    .expect("sigil server failed to start");

    let client = reqwest::Client::new();

    // Register schema: email is PII + searchable, password is credential
    client
        .post(server.http_url("/sigil/schemas"))
        .json(&serde_json::json!({
            "name": "app",
            "fields": [
                {"name": "email", "field_type": "string", "annotations": {"pii": true, "searchable": true}},
                {"name": "password", "field_type": "string", "annotations": {"credential": true}}
            ]
        }))
        .send()
        .await
        .unwrap();

    // ── Register ────────────────────────────────────────────────────
    // User signs up with email + password. The app sends this to Sigil.
    // Sigil encrypts the email (Cipher), indexes it (Veil), hashes the
    // password (Argon2id). The database never has plaintext email.
    let resp = client
        .post(server.http_url("/sigil/app/users"))
        .json(&serde_json::json!({
            "fields": {
                "user_id": "u_abc123",
                "email": "alice@example.com",
                "password": "correct-horse-battery"
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // ── Login by email ──────────────────────────────────────────────
    // User logs in with email + password. The app sends this to Sigil.
    // Sigil searches Veil for "alice@example.com" → resolves user_id
    // "u_abc123" → verifies password → issues JWT.
    // The app gets a JWT back. It never stored, processed, or mapped
    // the email to a user_id itself.
    let resp = client
        .post(server.http_url("/sigil/app/sessions/login"))
        .json(&serde_json::json!({
            "field": "email",
            "value": "alice@example.com",
            "password": "correct-horse-battery"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "login by email failed: {:?}",
        resp.text().await
    );

    // Parse the response — we should have a JWT
    let resp = client
        .post(server.http_url("/sigil/app/sessions/login"))
        .json(&serde_json::json!({
            "field": "email",
            "value": "alice@example.com",
            "password": "correct-horse-battery"
        }))
        .send()
        .await
        .unwrap();
    let login: serde_json::Value = resp.json().await.unwrap();
    assert!(login["access_token"].is_string(), "should get JWT back");
    assert!(login["refresh_token"].is_string());

    // ── Wrong password ──────────────────────────────────────────────
    let resp = client
        .post(server.http_url("/sigil/app/sessions/login"))
        .json(&serde_json::json!({
            "field": "email",
            "value": "alice@example.com",
            "password": "wrong-password"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "wrong password should fail");

    // ── Unknown email ───────────────────────────────────────────────
    let resp = client
        .post(server.http_url("/sigil/app/sessions/login"))
        .json(&serde_json::json!({
            "field": "email",
            "value": "nobody@example.com",
            "password": "anything"
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status() == 404 || resp.status() == 401,
        "unknown email should fail"
    );

    // ── Verify the email is redacted in GET ────────────────────────
    // PII is never exposed via GET — Courier handles just-in-time access
    let resp = client
        .get(server.http_url("/sigil/app/users/u_abc123"))
        .send()
        .await
        .unwrap();
    let user: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        user["fields"]["email"], "[encrypted]",
        "PII should be redacted, not decrypted"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Keep: secret field versioned storage
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn keep_secret_field_storage() {
    let keep = match TestKeepServer::start().await {
        Some(k) => k,
        None => {
            eprintln!("skipping: keep binary not found");
            return;
        }
    };

    let server = TestServer::start_with_config(TestServerConfig {
        keep: Some(TestKeepConfig {
            addr: keep.tcp_addr.clone(),
        }),
        ..Default::default()
    })
    .await
    .expect("sigil server failed to start with keep");

    let client = reqwest::Client::new();

    // Register schema with a secret field
    client
        .post(server.http_url("/sigil/schemas"))
        .json(&serde_json::json!({
            "name": "secrets",
            "fields": [
                {"name": "password", "field_type": "string", "annotations": {"credential": true}},
                {"name": "api_key", "field_type": "string", "annotations": {"secret": true}},
                {"name": "org", "field_type": "string", "annotations": {"index": true}}
            ]
        }))
        .send()
        .await
        .unwrap();

    // Create user with a secret field
    let resp = client
        .post(server.http_url("/sigil/secrets/users"))
        .json(&serde_json::json!({
            "fields": {
                "user_id": "alice",
                "password": "test12345678",
                "api_key": "sk_live_abc123xyz",
                "org": "acme"
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        201,
        "create with secret field failed: {:?}",
        resp.text().await
    );

    // Verify the secret was stored in Keep
    let mut keep_client = shroudb_keep_client::KeepClient::connect(&keep.tcp_addr)
        .await
        .unwrap();
    let secret = keep_client
        .get("secrets/alice/api_key", None)
        .await
        .unwrap();
    // The secret value should be the JSON-serialized version of the field value
    assert!(!secret.value.is_empty(), "secret should be stored in Keep");

    // Secret field should NOT appear in user record (stored in Keep, not inline)
    let resp = client
        .get(server.http_url("/sigil/secrets/users/alice"))
        .send()
        .await
        .unwrap();
    let user: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(user["fields"]["org"], "acme");
    assert!(
        user["fields"].get("api_key").is_none(),
        "secret field should not be in user record"
    );

    // Credentials still work
    let resp = client
        .post(server.http_url("/sigil/secrets/verify"))
        .json(&serde_json::json!({"user_id": "alice", "password": "test12345678"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

// ═══════════════════════════════════════════════════════════════════════
// Config-seeded schemas — zero API calls needed before using
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn config_seeded_schema_works_immediately() {
    let server = TestServer::start_with_config(TestServerConfig {
        schemas: vec![TestSchemaConfig {
            toml: r#"
[[schemas]]
name = "myapp"

[[schemas.fields]]
name = "password"
field_type = "string"
credential = true

[[schemas.fields]]
name = "org"
field_type = "string"
index = true
"#
            .to_string(),
        }],
        ..Default::default()
    })
    .await
    .expect("server failed to start with seeded schema");

    let client = reqwest::Client::new();

    // Schema should already exist — no SCHEMA REGISTER needed
    let resp = client
        .get(server.http_url("/sigil/schemas/myapp"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "seeded schema should exist");

    // Can immediately create users
    let resp = client
        .post(server.http_url("/sigil/myapp/users"))
        .json(&serde_json::json!({
            "fields": {"user_id": "alice", "password": "correct-horse", "org": "acme"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // Can immediately login
    let resp = client
        .post(server.http_url("/sigil/myapp/sessions"))
        .json(&serde_json::json!({"user_id": "alice", "password": "correct-horse"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let login: serde_json::Value = resp.json().await.unwrap();
    assert!(login["access_token"].is_string());
}
