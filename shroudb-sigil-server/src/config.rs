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
    #[serde(default)]
    pub cipher: Option<CipherConfig>,
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
    /// Auth method. When set to "token", clients must authenticate.
    #[serde(default)]
    pub method: Option<String>,
    /// Token definitions keyed by the raw token string.
    #[serde(default)]
    pub tokens: std::collections::HashMap<String, TokenConfig>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            access_ttl: default_access_ttl(),
            refresh_ttl: default_refresh_ttl(),
            jwt_algorithm: default_jwt_algorithm(),
            method: None,
            tokens: std::collections::HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TokenConfig {
    pub tenant: String,
    #[serde(default = "default_actor")]
    pub actor: String,
    #[serde(default)]
    pub platform: bool,
    #[serde(default)]
    pub grants: Vec<GrantConfig>,
}

fn default_actor() -> String {
    "anonymous".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct GrantConfig {
    pub namespace: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// Build a StaticTokenValidator from the auth config.
pub fn build_token_validator(
    config: &AuthConfig,
) -> Option<std::sync::Arc<dyn shroudb_acl::TokenValidator>> {
    if config.method.as_deref() != Some("token") || config.tokens.is_empty() {
        return None;
    }

    let mut validator = shroudb_acl::StaticTokenValidator::new();

    for (raw_token, token_config) in &config.tokens {
        let grants: Vec<shroudb_acl::TokenGrant> = token_config
            .grants
            .iter()
            .map(|g| {
                let scopes: Vec<shroudb_acl::Scope> = g
                    .scopes
                    .iter()
                    .filter_map(|s| match s.to_lowercase().as_str() {
                        "read" => Some(shroudb_acl::Scope::Read),
                        "write" => Some(shroudb_acl::Scope::Write),
                        _ => None,
                    })
                    .collect();
                shroudb_acl::TokenGrant {
                    namespace: g.namespace.clone(),
                    scopes,
                }
            })
            .collect();

        let token = shroudb_acl::Token {
            tenant: token_config.tenant.clone(),
            actor: token_config.actor.clone(),
            is_platform: token_config.platform,
            grants,
            expires_at: None,
        };

        validator.register(raw_token.clone(), token);
    }

    Some(std::sync::Arc::new(validator))
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
