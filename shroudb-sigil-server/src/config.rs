use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;
use shroudb_acl::ServerAuthConfig;

#[derive(Debug, Deserialize, Default)]
pub struct SigilServerConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub store: StoreConfig,
    #[serde(default)]
    pub auth: ServerAuthConfig,
    #[serde(default)]
    pub jwt: JwtConfig,
    #[serde(default)]
    pub cipher: Option<CipherConfig>,
    #[serde(default)]
    pub veil: Option<VeilConfig>,
    #[serde(default)]
    pub keep: Option<KeepConfig>,
    #[serde(default)]
    pub schemas: Vec<SchemaConfig>,
}

/// Schema definition in config — registered at startup if not already present.
#[derive(Debug, Deserialize)]
pub struct SchemaConfig {
    pub name: String,
    pub fields: Vec<SchemaFieldConfig>,
}

#[derive(Debug, Deserialize)]
pub struct SchemaFieldConfig {
    pub name: String,
    pub field_type: String,
    #[serde(default)]
    pub credential: bool,
    #[serde(default)]
    pub pii: bool,
    #[serde(default)]
    pub searchable: bool,
    #[serde(default)]
    pub secret: bool,
    #[serde(default)]
    pub index: bool,
    #[serde(default)]
    pub claim: bool,
}

impl SchemaConfig {
    /// Convert to the core Schema type for registration.
    pub fn to_schema(&self) -> shroudb_sigil_core::schema::Schema {
        shroudb_sigil_core::schema::Schema {
            name: self.name.clone(),
            version: 1,
            fields: self
                .fields
                .iter()
                .map(|f| shroudb_sigil_core::schema::FieldDef {
                    name: f.name.clone(),
                    field_type: match f.field_type.as_str() {
                        "integer" => shroudb_sigil_core::schema::FieldType::Integer,
                        "boolean" => shroudb_sigil_core::schema::FieldType::Boolean,
                        "bytes" => shroudb_sigil_core::schema::FieldType::Bytes,
                        _ => shroudb_sigil_core::schema::FieldType::String,
                    },
                    annotations: shroudb_sigil_core::schema::FieldAnnotations {
                        credential: f.credential,
                        pii: f.pii,
                        searchable: f.searchable,
                        secret: f.secret,
                        index: f.index,
                        claim: f.claim,
                    },
                    required: true,
                })
                .collect(),
        }
    }
}

/// Cipher engine connection for PII field encryption.
#[derive(Debug, Deserialize)]
pub struct CipherConfig {
    /// Cipher server address (e.g., "127.0.0.1:6599").
    pub addr: String,
    /// Keyring name for PII field encryption.
    pub keyring: String,
    /// Auth token for Cipher server (optional).
    #[serde(default)]
    pub auth_token: Option<String>,
    /// Connection pool size (default: 8).
    #[serde(default)]
    pub pool_size: Option<usize>,
}

/// Veil engine connection for searchable encrypted field indexing.
#[derive(Debug, Deserialize)]
pub struct VeilConfig {
    /// Veil server address (e.g., "127.0.0.1:6799").
    pub addr: String,
    /// Index name for searchable PII fields.
    pub index: String,
    /// Auth token for Veil server (optional).
    #[serde(default)]
    pub auth_token: Option<String>,
    /// Connection pool size (default: 8).
    #[serde(default)]
    pub pool_size: Option<usize>,
}

/// Keep engine connection for versioned secret storage.
#[derive(Debug, Deserialize)]
pub struct KeepConfig {
    /// Keep server address (e.g., "127.0.0.1:6699").
    pub addr: String,
    /// Auth token for Keep server (optional).
    #[serde(default)]
    pub auth_token: Option<String>,
    /// Connection pool size (default: 8).
    #[serde(default)]
    pub pool_size: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_tcp_bind")]
    pub tcp_bind: SocketAddr,
    #[serde(default = "default_http_bind")]
    pub http_bind: SocketAddr,
    #[serde(default)]
    pub log_level: Option<String>,
    #[serde(default)]
    pub tls: Option<shroudb_server_tcp::TlsConfig>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            tcp_bind: default_tcp_bind(),
            http_bind: default_http_bind(),
            log_level: None,
            tls: None,
        }
    }
}

fn default_tcp_bind() -> SocketAddr {
    "0.0.0.0:6499".parse().expect("valid hardcoded address")
}

fn default_http_bind() -> SocketAddr {
    "0.0.0.0:6500".parse().expect("valid hardcoded address")
}

#[derive(Debug, Deserialize)]
pub struct StoreConfig {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    #[serde(default)]
    pub uri: Option<String>,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            data_dir: default_data_dir(),
            uri: None,
        }
    }
}

fn default_mode() -> String {
    "embedded".to_string()
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("./sigil-data")
}

#[derive(Debug, Deserialize)]
pub struct JwtConfig {
    #[serde(default = "default_access_ttl")]
    pub access_ttl: String,
    #[serde(default = "default_refresh_ttl")]
    pub refresh_ttl: String,
    #[serde(default = "default_jwt_algorithm")]
    pub jwt_algorithm: String,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            access_ttl: default_access_ttl(),
            refresh_ttl: default_refresh_ttl(),
            jwt_algorithm: default_jwt_algorithm(),
        }
    }
}

fn default_access_ttl() -> String {
    "15m".to_string()
}

fn default_refresh_ttl() -> String {
    "30d".to_string()
}

fn default_jwt_algorithm() -> String {
    "ES256".to_string()
}

/// Parse a duration string (e.g., "15m", "30d", "1h", "3600") into seconds.
pub fn parse_duration_secs(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix('s') {
        Ok(n.parse()?)
    } else if let Some(n) = s.strip_suffix('m') {
        Ok(n.parse::<u64>()? * 60)
    } else if let Some(n) = s.strip_suffix('h') {
        Ok(n.parse::<u64>()? * 3600)
    } else if let Some(n) = s.strip_suffix('d') {
        Ok(n.parse::<u64>()? * 86400)
    } else {
        Ok(s.parse()?)
    }
}

/// Load config from a TOML file, or return defaults.
pub fn load_config(path: Option<&str>) -> anyhow::Result<SigilServerConfig> {
    match path {
        Some(p) => {
            let raw = std::fs::read_to_string(p)
                .map_err(|e| anyhow::anyhow!("failed to read config: {e}"))?;
            let config: SigilServerConfig =
                toml::from_str(&raw).map_err(|e| anyhow::anyhow!("failed to parse config: {e}"))?;
            Ok(config)
        }
        None => Ok(SigilServerConfig::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_to_embedded_mode() {
        let cfg = SigilServerConfig::default();
        assert_eq!(cfg.store.mode, "embedded");
        assert!(cfg.store.uri.is_none());
    }

    #[test]
    fn config_parses_remote_mode_with_uri() {
        let toml = r#"
[store]
mode = "remote"
uri = "shroudb://token@127.0.0.1:6399"
"#;
        let cfg: SigilServerConfig = toml::from_str(toml).expect("parse failed");
        assert_eq!(cfg.store.mode, "remote");
        assert_eq!(
            cfg.store.uri.as_deref(),
            Some("shroudb://token@127.0.0.1:6399")
        );
    }

    #[test]
    fn config_parses_remote_mode_tls_uri() {
        let toml = r#"
[store]
mode = "remote"
uri = "shroudb+tls://token@store.example.com:6399"
"#;
        let cfg: SigilServerConfig = toml::from_str(toml).expect("parse failed");
        assert_eq!(cfg.store.mode, "remote");
        assert_eq!(
            cfg.store.uri.as_deref(),
            Some("shroudb+tls://token@store.example.com:6399")
        );
    }
}
