use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;
use shroudb_acl::ServerAuthConfig;
use shroudb_engine_bootstrap::{AuditConfig, PolicyConfig};
use shroudb_sigil_core::field_kind::FieldKind;

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
    /// Chronicle (audit) capability slot.
    ///
    /// Absent defaults to `AuditConfig::default()` from `shroudb-engine-bootstrap`
    /// (embedded mode as of 0.3.0). Operators who want a remote Chronicle server
    /// or an explicit `disabled` posture must declare `[chronicle]` and set
    /// `mode` accordingly. Embedded initialization failures fail-closed at startup.
    #[serde(default)]
    pub chronicle: Option<AuditConfig>,
    /// Sentry (policy) capability slot.
    ///
    /// Absent defaults to `PolicyConfig::default()` from `shroudb-engine-bootstrap`
    /// (embedded mode as of 0.3.0). Operators who want a remote Sentry server
    /// or an explicit `disabled` posture must declare `[sentry]` and set `mode`
    /// accordingly. Embedded initialization failures fail-closed at startup.
    #[serde(default)]
    pub sentry: Option<PolicyConfig>,
}

/// Schema definition in config — registered at startup if not already present.
#[derive(Debug, Deserialize)]
pub struct SchemaConfig {
    pub name: String,
    pub fields: Vec<SchemaFieldConfig>,
}

/// Field entry in a schema config.
///
/// v2.0 shape: cryptographic treatment lives in a nested `[schemas.fields.kind]`
/// table (the core `FieldKind` tagged enum). The flat `credential = true` /
/// `pii = true` / etc. keys from v1.x are explicitly detected and rejected in
/// `validate_v2_shape` with a pointer to the migration tool.
#[derive(Debug, Deserialize)]
pub struct SchemaFieldConfig {
    pub name: String,
    pub field_type: String,
    pub kind: FieldKind,
    #[serde(default = "default_true")]
    pub required: bool,

    // --- v1 legacy-key detectors ---
    // These fields exist purely to surface a helpful error when someone loads
    // a v1-format config against a v2.0 server. They are not part of the v2
    // schema shape. Phase 6 keeps them as the v1-rejection barrier.
    #[serde(default)]
    credential: Option<bool>,
    #[serde(default)]
    pii: Option<bool>,
    #[serde(default)]
    searchable: Option<bool>,
    #[serde(default)]
    secret: Option<bool>,
    #[serde(default)]
    index: Option<bool>,
    #[serde(default)]
    claim: Option<bool>,
    #[serde(default)]
    lockout: Option<bool>,
}

fn default_true() -> bool {
    true
}

impl SchemaFieldConfig {
    /// Detect v1 annotation keys at the field level and error with a clear
    /// pointer to the migration tool. Called from `SchemaConfig::to_schema`.
    fn validate_v2_shape(&self) -> anyhow::Result<()> {
        let legacy: Vec<&str> = [
            ("credential", self.credential.is_some()),
            ("pii", self.pii.is_some()),
            ("searchable", self.searchable.is_some()),
            ("secret", self.secret.is_some()),
            ("index", self.index.is_some()),
            ("claim", self.claim.is_some()),
            ("lockout", self.lockout.is_some()),
        ]
        .into_iter()
        .filter_map(|(k, present)| if present { Some(k) } else { None })
        .collect();
        if !legacy.is_empty() {
            anyhow::bail!(
                "schema field '{}' uses v1 annotation keys ({}); v2.0 replaced these with a `[schemas.fields.kind]` table. \
                 See CHANGELOG v2.0 migration notes, and run `shroudb-sigil-cli SCHEMA MIGRATE` for persisted schemas in the store.",
                self.name,
                legacy.join(", ")
            );
        }
        Ok(())
    }
}

impl SchemaConfig {
    /// Convert to the core Schema type for registration. Fails with a helpful
    /// error when any field uses the legacy v1 annotation keys.
    pub fn to_schema(&self) -> anyhow::Result<shroudb_sigil_core::schema::Schema> {
        let mut fields = Vec::with_capacity(self.fields.len());
        for f in &self.fields {
            f.validate_v2_shape()?;
            fields.push(shroudb_sigil_core::schema::FieldDef::with_kind(
                f.name.clone(),
                match f.field_type.as_str() {
                    "integer" => shroudb_sigil_core::schema::FieldType::Integer,
                    "boolean" => shroudb_sigil_core::schema::FieldType::Boolean,
                    "bytes" => shroudb_sigil_core::schema::FieldType::Bytes,
                    _ => shroudb_sigil_core::schema::FieldType::String,
                },
                f.kind.clone(),
                f.required,
            ));
        }
        Ok(shroudb_sigil_core::schema::Schema {
            name: self.name.clone(),
            version: 1,
            fields,
        })
    }
}

/// Cipher capability slot for PII field encryption.
///
/// Two modes:
/// - `mode = "remote"` (default when omitted): connect to external
///   `shroudb-cipher` server at `addr`.
/// - `mode = "embedded"`: bundle an in-process `CipherEngine` on the same
///   `StorageEngine` as Sigil's metadata (distinct namespace). Requires
///   `store.mode = "embedded"`.
#[derive(Debug, Deserialize)]
pub struct CipherConfig {
    #[serde(default = "default_slot_mode")]
    pub mode: String,
    /// Keyring name for PII field encryption.
    #[serde(default = "default_cipher_keyring")]
    pub keyring: String,

    // Remote mode
    #[serde(default)]
    pub addr: Option<String>,
    #[serde(default)]
    pub auth_token: Option<String>,
    #[serde(default)]
    pub pool_size: Option<usize>,

    // Embedded mode
    #[serde(default = "default_rotation_days")]
    pub rotation_days: u32,
    #[serde(default = "default_drain_days")]
    pub drain_days: u32,
    #[serde(default = "default_scheduler_interval_secs")]
    pub scheduler_interval_secs: u64,
    #[serde(default = "default_cipher_algorithm")]
    pub algorithm: String,
}

impl CipherConfig {
    pub fn is_embedded(&self) -> bool {
        self.mode == "embedded"
    }
    pub fn is_remote(&self) -> bool {
        self.mode == "remote"
    }
    pub fn validate(&self, store_mode: &str) -> anyhow::Result<()> {
        match self.mode.as_str() {
            "remote" => {
                if self.addr.is_none() {
                    anyhow::bail!("cipher.mode = \"remote\" requires cipher.addr");
                }
            }
            "embedded" => {
                if store_mode != "embedded" {
                    anyhow::bail!(
                        "cipher.mode = \"embedded\" requires store.mode = \"embedded\" \
                         (embedded Cipher shares the StorageEngine with Sigil)"
                    );
                }
            }
            other => anyhow::bail!(
                "unknown cipher.mode: {other:?} (expected \"remote\" or \"embedded\")"
            ),
        }
        Ok(())
    }
}

/// Veil capability slot for searchable encrypted field indexing.
///
/// Two modes:
/// - `mode = "remote"` (default when omitted): connect to external
///   `shroudb-veil` server at `addr`.
/// - `mode = "embedded"`: bundle an in-process `VeilEngine` on the same
///   `StorageEngine` as Sigil's metadata (distinct namespace). Requires
///   `store.mode = "embedded"`.
#[derive(Debug, Deserialize)]
pub struct VeilConfig {
    #[serde(default = "default_slot_mode")]
    pub mode: String,
    /// Index name for searchable PII fields.
    #[serde(default = "default_veil_index")]
    pub index: String,

    // Remote mode
    #[serde(default)]
    pub addr: Option<String>,
    #[serde(default)]
    pub auth_token: Option<String>,
    #[serde(default)]
    pub pool_size: Option<usize>,
}

impl VeilConfig {
    pub fn is_embedded(&self) -> bool {
        self.mode == "embedded"
    }
    pub fn is_remote(&self) -> bool {
        self.mode == "remote"
    }
    pub fn validate(&self, store_mode: &str) -> anyhow::Result<()> {
        match self.mode.as_str() {
            "remote" => {
                if self.addr.is_none() {
                    anyhow::bail!("veil.mode = \"remote\" requires veil.addr");
                }
            }
            "embedded" => {
                if store_mode != "embedded" {
                    anyhow::bail!(
                        "veil.mode = \"embedded\" requires store.mode = \"embedded\" \
                         (embedded Veil shares the StorageEngine with Sigil)"
                    );
                }
            }
            other => {
                anyhow::bail!("unknown veil.mode: {other:?} (expected \"remote\" or \"embedded\")")
            }
        }
        Ok(())
    }
}

/// Keep capability slot for versioned secret storage.
///
/// Two modes:
/// - `mode = "remote"` (default when omitted): connect to external
///   `shroudb-keep` server at `addr`.
/// - `mode = "embedded"`: bundle an in-process `KeepEngine` on the same
///   `StorageEngine` as Sigil's metadata (distinct namespace). Requires
///   `store.mode = "embedded"`.
#[derive(Debug, Deserialize)]
pub struct KeepConfig {
    #[serde(default = "default_slot_mode")]
    pub mode: String,

    // Remote mode
    #[serde(default)]
    pub addr: Option<String>,
    #[serde(default)]
    pub auth_token: Option<String>,
    #[serde(default)]
    pub pool_size: Option<usize>,

    // Embedded mode
    #[serde(default = "default_keep_max_versions")]
    pub max_versions: u32,
}

impl KeepConfig {
    pub fn is_embedded(&self) -> bool {
        self.mode == "embedded"
    }
    pub fn is_remote(&self) -> bool {
        self.mode == "remote"
    }
    pub fn validate(&self, store_mode: &str) -> anyhow::Result<()> {
        match self.mode.as_str() {
            "remote" => {
                if self.addr.is_none() {
                    anyhow::bail!("keep.mode = \"remote\" requires keep.addr");
                }
            }
            "embedded" => {
                if store_mode != "embedded" {
                    anyhow::bail!(
                        "keep.mode = \"embedded\" requires store.mode = \"embedded\" \
                         (embedded Keep shares the StorageEngine with Sigil)"
                    );
                }
            }
            other => {
                anyhow::bail!("unknown keep.mode: {other:?} (expected \"remote\" or \"embedded\")")
            }
        }
        Ok(())
    }
}

fn default_slot_mode() -> String {
    "remote".into()
}
fn default_cipher_keyring() -> String {
    "sigil-pii".into()
}
fn default_veil_index() -> String {
    "sigil-searchable".into()
}
fn default_rotation_days() -> u32 {
    90
}
fn default_drain_days() -> u32 {
    30
}
fn default_scheduler_interval_secs() -> u64 {
    3600
}
fn default_cipher_algorithm() -> String {
    "aes-256-gcm".into()
}
fn default_keep_max_versions() -> u32 {
    10
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

    // --- Phase 5: v2-only schema config ---

    #[test]
    fn config_parses_v2_credential_with_lockout() {
        let toml = r#"
[[schemas]]
name = "users"

[[schemas.fields]]
name = "password"
field_type = "string"
kind = { type = "credential", lockout = { max_attempts = 5, duration_secs = 900 } }
"#;
        let cfg: SigilServerConfig = toml::from_str(toml).expect("parse failed");
        let schema = cfg.schemas[0].to_schema().expect("to_schema failed");
        let policy = schema.credential_policy("password").unwrap();
        let lockout = policy.lockout.as_ref().unwrap();
        assert_eq!(lockout.max_attempts, 5);
        assert_eq!(lockout.duration_secs, 900);
    }

    #[test]
    fn config_parses_v2_credential_sha256_no_lockout() {
        let toml = r#"
[[schemas]]
name = "api_clients"

[[schemas.fields]]
name = "key_secret"
field_type = "string"
kind = { type = "credential", algorithm = "sha256" }
"#;
        let cfg: SigilServerConfig = toml::from_str(toml).expect("parse failed");
        let schema = cfg.schemas[0].to_schema().expect("to_schema failed");
        let policy = schema.credential_policy("key_secret").unwrap();
        assert!(policy.lockout.is_none());
        assert_eq!(
            policy.algorithm,
            shroudb_sigil_core::credential::PasswordAlgorithm::Sha256
        );
    }

    #[test]
    fn config_parses_v2_pii_searchable() {
        let toml = r#"
[[schemas]]
name = "users"

[[schemas.fields]]
name = "email"
field_type = "string"
kind = { type = "pii", searchable = true }
"#;
        let cfg: SigilServerConfig = toml::from_str(toml).expect("parse failed");
        let schema = cfg.schemas[0].to_schema().expect("to_schema failed");
        let kind = &schema.fields[0].kind;
        match kind {
            FieldKind::Pii(p) => assert!(p.searchable),
            _ => panic!("expected Pii variant"),
        }
    }

    #[test]
    fn config_parses_v2_index_with_claim() {
        let toml = r#"
[[schemas]]
name = "accounts"

[[schemas.fields]]
name = "client_id"
field_type = "string"
kind = { type = "index", claim = { as_name = "sub" } }
"#;
        let cfg: SigilServerConfig = toml::from_str(toml).expect("parse failed");
        let schema = cfg.schemas[0].to_schema().expect("to_schema failed");
        let kind = &schema.fields[0].kind;
        let claim = kind.claim().expect("claim present");
        assert_eq!(claim.as_name.as_deref(), Some("sub"));
    }

    #[test]
    fn config_rejects_v1_credential_key() {
        let toml = r#"
[[schemas]]
name = "legacy"

[[schemas.fields]]
name = "password"
field_type = "string"
credential = true
kind = { type = "inert" }
"#;
        // Parses (the extra key is deserialized), but to_schema fails with
        // an actionable error.
        let cfg: SigilServerConfig = toml::from_str(toml).expect("parse failed");
        let err = cfg.schemas[0].to_schema().unwrap_err().to_string();
        assert!(err.contains("v1 annotation keys"), "error was: {err}");
        assert!(err.contains("SCHEMA MIGRATE"), "error was: {err}");
        assert!(err.contains("credential"), "error was: {err}");
    }

    #[test]
    fn config_rejects_multiple_v1_keys() {
        let toml = r#"
[[schemas]]
name = "legacy"

[[schemas.fields]]
name = "email"
field_type = "string"
pii = true
searchable = true
kind = { type = "inert" }
"#;
        let cfg: SigilServerConfig = toml::from_str(toml).expect("parse failed");
        let err = cfg.schemas[0].to_schema().unwrap_err().to_string();
        assert!(err.contains("pii"), "error was: {err}");
        assert!(err.contains("searchable"), "error was: {err}");
    }

    // ── DEBT TESTS ────────────────────────────────────────────────────
    //
    // Hard ratchet (AUDIT_2026-04-17). Do NOT add #[ignore] to pass CI.

    /// DEBT-F1 (AUDIT_2026-04-17): `SigilServerConfig` has no `[sentry]`
    /// or `[chronicle]` section. `main.rs` never populates
    /// `Capabilities::sentry` or `Capabilities::chronicle`. Deploying the
    /// standalone Sigil server means running without policy enforcement
    /// and without audit — silently. Fix: add `SentryConfig` and
    /// `ChronicleConfig` fields mirroring `CipherConfig`/`VeilConfig`/
    /// `KeepConfig`, wire their remote Ops impls in `main.rs::run_server`.
    #[test]
    fn debt_f01_server_config_must_wire_sentry_and_chronicle() {
        let toml = r#"
[sentry]
addr = "127.0.0.1:6499"
auth_token = "test"

[chronicle]
addr = "127.0.0.1:6899"
auth_token = "test"
"#;
        let cfg: SigilServerConfig = toml::from_str(toml)
            .expect("DEBT-F1: config must accept [sentry] and [chronicle] sections");

        let sentry_addr = format!("{:?}", cfg_sentry_addr(&cfg));
        let chronicle_addr = format!("{:?}", cfg_chronicle_addr(&cfg));
        assert!(
            sentry_addr.contains("6499"),
            "DEBT-F1: [sentry].addr not exposed on SigilServerConfig ({sentry_addr})"
        );
        assert!(
            chronicle_addr.contains("6899"),
            "DEBT-F1: [chronicle].addr not exposed on SigilServerConfig ({chronicle_addr})"
        );
    }

    fn cfg_sentry_addr(cfg: &SigilServerConfig) -> Option<String> {
        cfg.sentry.as_ref().and_then(|s| s.addr.clone())
    }
    fn cfg_chronicle_addr(cfg: &SigilServerConfig) -> Option<String> {
        cfg.chronicle.as_ref().and_then(|c| c.addr.clone())
    }
}
