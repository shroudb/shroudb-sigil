use crate::error::ClientError;

/// TCP connection to a Sigil server speaking RESP3.
pub struct Connection(shroudb_client_common::Connection);

impl Connection {
    /// Connect directly to a standalone Sigil server.
    pub async fn connect(addr: &str) -> Result<Self, ClientError> {
        Ok(Self(
            shroudb_client_common::Connection::connect(addr).await?,
        ))
    }

    /// Connect to a Sigil engine through a Moat gateway.
    pub async fn connect_moat(addr: &str) -> Result<Self, ClientError> {
        Ok(Self(
            shroudb_client_common::Connection::connect_with_prefix(addr, "SIGIL").await?,
        ))
    }

    /// Send an engine command (prefixed in Moat mode).
    pub async fn send_command(&mut self, args: &[&str]) -> Result<serde_json::Value, ClientError> {
        Ok(self.0.send_command(args).await?)
    }

    /// Send a meta-command (AUTH, HEALTH, PING) without engine prefix.
    pub async fn send_meta_command(
        &mut self,
        args: &[&str],
    ) -> Result<serde_json::Value, ClientError> {
        Ok(self.0.send_meta_command(args).await?)
    }
}
