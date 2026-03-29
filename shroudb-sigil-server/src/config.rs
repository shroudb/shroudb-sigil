use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
pub struct SigilServerConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub store: StoreConfig,
    #[serde(default)]
    pub auth: AuthConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_tcp_bind")]
    pub tcp_bind: SocketAddr,
    #[serde(default = "default_http_bind")]
    pub http_bind: SocketAddr,
    #[serde(default)]
    pub log_level: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            tcp_bind: default_tcp_bind(),
            http_bind: default_http_bind(),
            log_level: None,
        }
    }
}

fn default_tcp_bind() -> SocketAddr {
    "0.0.0.0:6499".parse().unwrap()
}

fn default_http_bind() -> SocketAddr {
    "0.0.0.0:6500".parse().unwrap()
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
pub struct AuthConfig {
    #[serde(default = "default_access_ttl")]
    pub access_ttl: String,
    #[serde(default = "default_refresh_ttl")]
    pub refresh_ttl: String,
    #[serde(default = "default_jwt_algorithm")]
    pub jwt_algorithm: String,
}

impl Default for AuthConfig {
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
