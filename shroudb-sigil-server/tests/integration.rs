mod common;

use common::TestServer;
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
