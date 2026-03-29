//! Typed Rust client library for Sigil.
//!
//! Provides a high-level async API for interacting with a Sigil server
//! over TCP (RESP3 wire protocol).
//!
//! # Example
//!
//! ```no_run
//! use shroudb_sigil_client::SigilClient;
//!
//! # async fn example() -> Result<(), shroudb_sigil_client::ClientError> {
//! let mut client = SigilClient::connect("127.0.0.1:6499").await?;
//!
//! // Register a schema
//! client.schema_register("myapp", serde_json::json!({
//!     "fields": [
//!         {"name": "password", "field_type": "string", "annotations": {"credential": true}},
//!         {"name": "org", "field_type": "string", "annotations": {"index": true}}
//!     ]
//! })).await?;
//!
//! // Create a user
//! client.user_create("myapp", "alice", serde_json::json!({
//!     "password": "correct-horse",
//!     "org": "acme"
//! })).await?;
//!
//! // Login
//! let tokens = client.session_create("myapp", "alice", "correct-horse", None).await?;
//! println!("access_token: {}", tokens.access_token);
//! # Ok(())
//! # }
//! ```

mod connection;
mod error;

pub use error::ClientError;

use connection::Connection;

/// Response from a login or refresh operation.
#[derive(Debug, Clone)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

/// Response from a user create or get operation.
#[derive(Debug, Clone)]
pub struct UserRecord {
    pub user_id: String,
    pub fields: serde_json::Value,
    pub created_at: Option<u64>,
    pub updated_at: Option<u64>,
}

/// A Sigil client connected via TCP.
pub struct SigilClient {
    conn: Connection,
}

impl SigilClient {
    /// Connect to a Sigil server.
    pub async fn connect(addr: &str) -> Result<Self, ClientError> {
        let conn = Connection::connect(addr).await?;
        Ok(Self { conn })
    }

    /// Health check.
    pub async fn health(&mut self) -> Result<(), ClientError> {
        let resp = self.command(&["HEALTH"]).await?;
        check_status(&resp)
    }

    // ── Schema ──────────────────────────────────────────────────────

    /// Register a credential envelope schema.
    pub async fn schema_register(
        &mut self,
        name: &str,
        definition: serde_json::Value,
    ) -> Result<u64, ClientError> {
        let json = serde_json::to_string(&definition)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;
        let resp = self.command(&["SCHEMA", "REGISTER", name, &json]).await?;
        check_status(&resp)?;
        resp["version"]
            .as_u64()
            .ok_or_else(|| ClientError::ResponseFormat("missing version".into()))
    }

    /// Get a schema by name.
    pub async fn schema_get(&mut self, name: &str) -> Result<serde_json::Value, ClientError> {
        self.command(&["SCHEMA", "GET", name]).await
    }

    /// List all schema names.
    pub async fn schema_list(&mut self) -> Result<Vec<String>, ClientError> {
        let resp = self.command(&["SCHEMA", "LIST"]).await?;
        resp.as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .ok_or_else(|| ClientError::ResponseFormat("expected array".into()))
    }

    // ── User ────────────────────────────────────────────────────────

    /// Create a user.
    pub async fn user_create(
        &mut self,
        schema: &str,
        user_id: &str,
        fields: serde_json::Value,
    ) -> Result<UserRecord, ClientError> {
        let json = serde_json::to_string(&fields)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;
        let resp = self
            .command(&["USER", "CREATE", schema, user_id, &json])
            .await?;
        check_status(&resp)?;
        parse_user_record(&resp)
    }

    /// Import a user with pre-hashed credential fields.
    /// Credential field values are treated as hashes (not plaintext).
    pub async fn user_import(
        &mut self,
        schema: &str,
        user_id: &str,
        fields: serde_json::Value,
    ) -> Result<UserRecord, ClientError> {
        let json = serde_json::to_string(&fields)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;
        let resp = self
            .command(&["USER", "IMPORT", schema, user_id, &json])
            .await?;
        check_status(&resp)?;
        parse_user_record(&resp)
    }

    /// Get a user record.
    pub async fn user_get(
        &mut self,
        schema: &str,
        user_id: &str,
    ) -> Result<UserRecord, ClientError> {
        let resp = self.command(&["USER", "GET", schema, user_id]).await?;
        parse_user_record(&resp)
    }

    /// Update non-credential fields.
    pub async fn user_update(
        &mut self,
        schema: &str,
        user_id: &str,
        fields: serde_json::Value,
    ) -> Result<UserRecord, ClientError> {
        let json = serde_json::to_string(&fields)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;
        let resp = self
            .command(&["USER", "UPDATE", schema, user_id, &json])
            .await?;
        check_status(&resp)?;
        parse_user_record(&resp)
    }

    /// Delete a user.
    pub async fn user_delete(&mut self, schema: &str, user_id: &str) -> Result<(), ClientError> {
        let resp = self.command(&["USER", "DELETE", schema, user_id]).await?;
        check_status(&resp)
    }

    /// Verify a user's credentials.
    pub async fn user_verify(
        &mut self,
        schema: &str,
        user_id: &str,
        password: &str,
    ) -> Result<bool, ClientError> {
        let resp = self
            .command(&["USER", "VERIFY", schema, user_id, password])
            .await?;
        check_status(&resp)?;
        Ok(resp["valid"].as_bool().unwrap_or(false))
    }

    // ── Session ─────────────────────────────────────────────────────

    /// Login: verify credentials and issue tokens.
    pub async fn session_create(
        &mut self,
        schema: &str,
        user_id: &str,
        password: &str,
        metadata: Option<&serde_json::Value>,
    ) -> Result<TokenPair, ClientError> {
        let mut args = vec!["SESSION", "CREATE", schema, user_id, password];
        let meta_str;
        if let Some(meta) = metadata {
            meta_str = serde_json::to_string(meta)
                .map_err(|e| ClientError::Serialization(e.to_string()))?;
            args.push("META");
            args.push(&meta_str);
        }
        let resp = self.command(&args).await?;
        check_status(&resp)?;
        parse_token_pair(&resp)
    }

    /// Refresh: rotate refresh token and issue new access token.
    pub async fn session_refresh(
        &mut self,
        schema: &str,
        refresh_token: &str,
    ) -> Result<TokenPair, ClientError> {
        let resp = self
            .command(&["SESSION", "REFRESH", schema, refresh_token])
            .await?;
        check_status(&resp)?;
        parse_token_pair(&resp)
    }

    /// Revoke a single session.
    pub async fn session_revoke(
        &mut self,
        schema: &str,
        refresh_token: &str,
    ) -> Result<(), ClientError> {
        let resp = self
            .command(&["SESSION", "REVOKE", schema, refresh_token])
            .await?;
        check_status(&resp)
    }

    /// Revoke all sessions for a user.
    pub async fn session_revoke_all(
        &mut self,
        schema: &str,
        user_id: &str,
    ) -> Result<u64, ClientError> {
        let resp = self
            .command(&["SESSION", "REVOKE", "ALL", schema, user_id])
            .await?;
        check_status(&resp)?;
        resp["revoked"]
            .as_u64()
            .ok_or_else(|| ClientError::ResponseFormat("missing revoked count".into()))
    }

    /// List active sessions for a user.
    pub async fn session_list(
        &mut self,
        schema: &str,
        user_id: &str,
    ) -> Result<serde_json::Value, ClientError> {
        self.command(&["SESSION", "LIST", schema, user_id]).await
    }

    // ── Password ────────────────────────────────────────────────────

    /// Change password (requires old password).
    pub async fn password_change(
        &mut self,
        schema: &str,
        user_id: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), ClientError> {
        let resp = self
            .command(&[
                "PASSWORD",
                "CHANGE",
                schema,
                user_id,
                old_password,
                new_password,
            ])
            .await?;
        check_status(&resp)
    }

    /// Reset password (admin/forced).
    pub async fn password_reset(
        &mut self,
        schema: &str,
        user_id: &str,
        new_password: &str,
    ) -> Result<(), ClientError> {
        let resp = self
            .command(&["PASSWORD", "RESET", schema, user_id, new_password])
            .await?;
        check_status(&resp)
    }

    /// Import a pre-hashed password.
    pub async fn password_import(
        &mut self,
        schema: &str,
        user_id: &str,
        hash: &str,
    ) -> Result<String, ClientError> {
        let resp = self
            .command(&["PASSWORD", "IMPORT", schema, user_id, hash])
            .await?;
        check_status(&resp)?;
        resp["algorithm"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| ClientError::ResponseFormat("missing algorithm".into()))
    }

    // ── JWT ─────────────────────────────────────────────────────────

    /// Get the JWKS.
    pub async fn jwks(&mut self, schema: &str) -> Result<serde_json::Value, ClientError> {
        self.command(&["JWKS", schema]).await
    }

    // ── Internal ────────────────────────────────────────────────────

    async fn command(&mut self, args: &[&str]) -> Result<serde_json::Value, ClientError> {
        self.conn.send_command(args).await
    }
}

fn check_status(resp: &serde_json::Value) -> Result<(), ClientError> {
    if let Some(status) = resp.get("status").and_then(|s| s.as_str())
        && status == "ok"
    {
        return Ok(());
    }
    // If no status field, check if it's an object at all (some responses are arrays)
    if resp.is_array() || resp.is_object() {
        return Ok(());
    }
    Err(ClientError::ResponseFormat("unexpected response".into()))
}

fn parse_token_pair(resp: &serde_json::Value) -> Result<TokenPair, ClientError> {
    Ok(TokenPair {
        access_token: resp["access_token"]
            .as_str()
            .ok_or_else(|| ClientError::ResponseFormat("missing access_token".into()))?
            .to_string(),
        refresh_token: resp["refresh_token"]
            .as_str()
            .ok_or_else(|| ClientError::ResponseFormat("missing refresh_token".into()))?
            .to_string(),
        expires_in: resp["expires_in"]
            .as_u64()
            .ok_or_else(|| ClientError::ResponseFormat("missing expires_in".into()))?,
    })
}

fn parse_user_record(resp: &serde_json::Value) -> Result<UserRecord, ClientError> {
    Ok(UserRecord {
        user_id: resp["user_id"]
            .as_str()
            .ok_or_else(|| ClientError::ResponseFormat("missing user_id".into()))?
            .to_string(),
        fields: resp["fields"].clone(),
        created_at: resp["created_at"].as_u64(),
        updated_at: resp["updated_at"].as_u64(),
    })
}
