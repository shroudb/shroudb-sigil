mod config;
mod tcp;

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use shroudb_crypto::JwtAlgorithm;
use shroudb_sigil_engine::capabilities::Capabilities;
use shroudb_sigil_engine::engine::{SigilConfig, SigilEngine};
use shroudb_storage::{
    ChainedMasterKeySource, EnvMasterKey, EphemeralKey, FileMasterKey, MasterKeySource,
    StorageEngineConfig,
};
use shroudb_store::Store;

use crate::config::{SigilServerConfig, load_config, parse_duration_secs};

#[derive(Parser)]
#[command(name = "shroudb-sigil", about = "Sigil credential envelope engine")]
struct Cli {
    /// Path to config file.
    #[arg(short, long, env = "SIGIL_CONFIG")]
    config: Option<String>,

    /// Data directory (overrides config).
    #[arg(long, env = "SIGIL_DATA_DIR")]
    data_dir: Option<String>,

    /// TCP bind address (overrides config).
    #[arg(long, env = "SIGIL_TCP_BIND")]
    tcp_bind: Option<String>,

    /// HTTP bind address (overrides config).
    #[arg(long, env = "SIGIL_HTTP_BIND")]
    http_bind: Option<String>,

    /// Log level.
    #[arg(long, env = "SIGIL_LOG_LEVEL", default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Load config
    let mut cfg = load_config(cli.config.as_deref())?;

    // Logging — CLI overrides config
    let log_level = if cli.log_level != "info" {
        cli.log_level.clone()
    } else {
        cfg.server
            .log_level
            .take()
            .unwrap_or_else(|| "info".to_string())
    };
    let filter = tracing_subscriber::EnvFilter::try_new(&log_level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .init();

    // Disable core dumps — sensitive key material must not leak to disk.
    shroudb_crypto::disable_core_dumps();

    // CLI overrides
    if let Some(ref dir) = cli.data_dir {
        cfg.store.data_dir = dir.into();
    }
    if let Some(ref bind) = cli.tcp_bind {
        cfg.server.tcp_bind = bind.parse().context("invalid TCP bind address")?;
    }
    if let Some(ref bind) = cli.http_bind {
        cfg.server.http_bind = bind.parse().context("invalid HTTP bind address")?;
    }

    // Store: embedded or remote
    match cfg.store.mode.as_str() {
        "embedded" => {
            // Master key
            let key_source: Box<dyn MasterKeySource> = Box::new(ChainedMasterKeySource::new(vec![
                Box::new(EnvMasterKey::new()),
                Box::new(FileMasterKey::new()),
                Box::new(EphemeralKey),
            ]));

            // Storage engine
            let engine_config = StorageEngineConfig {
                data_dir: cfg.store.data_dir.clone(),
                ..Default::default()
            };
            let storage_engine = Arc::new(
                shroudb_storage::StorageEngine::open(engine_config, key_source.as_ref())
                    .await
                    .context("failed to open storage engine")?,
            );
            let store = Arc::new(shroudb_storage::EmbeddedStore::new(
                storage_engine.clone(),
                "sigil",
            ));
            run_server(cfg, store, Some(storage_engine)).await
        }
        "remote" => {
            let uri = cfg
                .store
                .uri
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("remote mode requires store.uri"))?;
            tracing::info!(uri, "connecting to remote store");
            let store = Arc::new(
                shroudb_client::RemoteStore::connect(uri)
                    .await
                    .context("failed to connect to remote store")?,
            );
            run_server(cfg, store, None).await
        }
        other => anyhow::bail!("unknown store mode: {other}"),
    }
}

async fn run_server<S: Store + 'static>(
    cfg: SigilServerConfig,
    store: Arc<S>,
    storage: Option<Arc<shroudb_storage::StorageEngine>>,
) -> anyhow::Result<()> {
    // Sigil engine
    let jwt_algorithm = parse_jwt_algorithm(&cfg.jwt.jwt_algorithm)?;
    let sigil_config = SigilConfig {
        jwt_algorithm,
        access_ttl_secs: parse_duration_secs(&cfg.jwt.access_ttl)?,
        refresh_ttl_secs: parse_duration_secs(&cfg.jwt.refresh_ttl)?,
        ..Default::default()
    };

    // Capabilities: connect to external engines / resolve audit+policy
    use shroudb_server_bootstrap::Capability;

    let cipher_cap: Capability<Box<dyn shroudb_sigil_engine::capabilities::CipherOps>> =
        if let Some(ref cipher_cfg) = cfg.cipher {
            let cipher_ops = shroudb_sigil_engine::cipher_remote::RemoteCipherOps::connect(
                &cipher_cfg.addr,
                cipher_cfg.keyring.clone(),
                cipher_cfg.auth_token.as_deref(),
                cipher_cfg.pool_size,
            )
            .await
            .context("failed to connect to cipher server")?;
            tracing::info!(addr = %cipher_cfg.addr, keyring = %cipher_cfg.keyring, "cipher connected");
            Capability::Enabled(Box::new(cipher_ops))
        } else {
            Capability::disabled(
                "no [cipher] section in sigil config — PII fields cannot be encrypted/decrypted",
            )
        };

    let veil_cap: Capability<Box<dyn shroudb_sigil_engine::capabilities::VeilOps>> =
        if let Some(ref veil_cfg) = cfg.veil {
            let veil_ops = shroudb_sigil_engine::veil_remote::RemoteVeilOps::connect(
                &veil_cfg.addr,
                veil_cfg.index.clone(),
                veil_cfg.auth_token.as_deref(),
                veil_cfg.pool_size,
            )
            .await
            .context("failed to connect to veil server")?;
            tracing::info!(addr = %veil_cfg.addr, index = %veil_cfg.index, "veil connected");
            Capability::Enabled(Box::new(veil_ops))
        } else {
            Capability::disabled(
                "no [veil] section in sigil config — searchable blind-index fields disabled",
            )
        };

    let keep_cap: Capability<Box<dyn shroudb_sigil_engine::capabilities::KeepOps>> =
        if let Some(ref keep_cfg) = cfg.keep {
            let keep_ops = shroudb_sigil_engine::keep_remote::RemoteKeepOps::connect(
                &keep_cfg.addr,
                keep_cfg.auth_token.as_deref(),
                keep_cfg.pool_size,
            )
            .await
            .context("failed to connect to keep server")?;
            tracing::info!(addr = %keep_cfg.addr, "keep connected");
            Capability::Enabled(Box::new(keep_ops))
        } else {
            Capability::disabled(
                "no [keep] section in sigil config — secret-annotated fields cannot be stored",
            )
        };

    // Resolve [audit] and [policy] via engine-bootstrap — no silent None.
    let audit_cfg = cfg.audit.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "missing [audit] config section. Pick one:\n  \
             [audit] mode = \"remote\" addr = \"chronicle.internal:7300\"\n  \
             [audit] mode = \"embedded\"\n  \
             [audit] mode = \"disabled\" justification = \"<reason>\""
        )
    })?;
    let audit_cap = audit_cfg
        .resolve(storage.clone())
        .await
        .context("failed to resolve [audit] capability")?;
    let policy_cfg = cfg.policy.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "missing [policy] config section. Pick one:\n  \
             [policy] mode = \"remote\" addr = \"sentry.internal:7100\"\n  \
             [policy] mode = \"embedded\"\n  \
             [policy] mode = \"disabled\" justification = \"<reason>\""
        )
    })?;
    let policy_cap = policy_cfg
        .resolve(storage.clone(), audit_cap.as_ref().cloned())
        .await
        .context("failed to resolve [policy] capability")?;

    let capabilities = Capabilities::new(cipher_cap, veil_cap, keep_cap, policy_cap, audit_cap);

    let engine = Arc::new(
        SigilEngine::new(store, sigil_config, capabilities)
            .await
            .context("failed to initialize sigil engine")?,
    );

    // Seed schemas from config (idempotent — skips if already registered)
    for schema_cfg in &cfg.schemas {
        let schema = schema_cfg
            .to_schema()
            .map_err(|e| anyhow::anyhow!("schema '{}' in config: {e}", schema_cfg.name))?;
        match engine.schema_register(schema).await {
            Ok(version) => {
                tracing::info!(schema = %schema_cfg.name, version, "schema registered from config");
            }
            Err(shroudb_sigil_core::error::SigilError::SchemaExists(_)) => {
                tracing::debug!(schema = %schema_cfg.name, "schema already exists, skipping");
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "failed to register schema '{}': {e}",
                    schema_cfg.name
                ));
            }
        }
    }

    // Shutdown signal
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Auth: build token validator from config
    let token_validator = cfg.auth.build_validator();
    if token_validator.is_some() {
        tracing::info!(tokens = cfg.auth.tokens.len(), "token-based auth enabled");
    }

    // TCP server
    let tcp_listener = tokio::net::TcpListener::bind(cfg.server.tcp_bind)
        .await
        .context("failed to bind TCP")?;

    let tls_acceptor = cfg
        .server
        .tls
        .as_ref()
        .map(shroudb_server_tcp::build_tls_acceptor)
        .transpose()
        .context("failed to build TLS acceptor")?;

    let tcp_engine = engine.clone();
    let tcp_validator = token_validator.clone();
    let tcp_shutdown = shutdown_rx.clone();
    let tcp_handle = tokio::spawn(async move {
        tcp::run_tcp(
            tcp_listener,
            tcp_engine,
            tcp_validator,
            tcp_shutdown,
            tls_acceptor,
        )
        .await;
    });

    // HTTP server
    let http_listener = tokio::net::TcpListener::bind(cfg.server.http_bind)
        .await
        .context("failed to bind HTTP")?;

    let http_router = shroudb_sigil_http::router(
        engine.clone(),
        token_validator,
        shroudb_sigil_http::HttpConfig::default(),
    );
    let http_handle = tokio::spawn(async move {
        axum::serve(http_listener, http_router)
            .await
            .unwrap_or_else(|e| tracing::error!(error = %e, "HTTP server error"));
    });

    // Banner
    eprintln!();
    eprintln!("Sigil v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("├─ tcp:     {}", cfg.server.tcp_bind);
    eprintln!("├─ http:    {}", cfg.server.http_bind);
    eprintln!("├─ data:    {}", cfg.store.data_dir.display());
    eprintln!(
        "└─ key:     {}",
        if std::env::var("SHROUDB_MASTER_KEY").is_ok()
            || std::env::var("SHROUDB_MASTER_KEY_FILE").is_ok()
        {
            "configured"
        } else {
            "ephemeral (dev mode)"
        }
    );
    eprintln!();
    eprintln!("Ready.");

    // Wait for shutdown
    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for ctrl-c")?;
    tracing::info!("shutting down");
    let _ = shutdown_tx.send(true);
    let _ = tcp_handle.await;
    http_handle.abort();

    Ok(())
}

fn parse_jwt_algorithm(s: &str) -> anyhow::Result<JwtAlgorithm> {
    match s.to_uppercase().as_str() {
        "ES256" => Ok(JwtAlgorithm::ES256),
        "ES384" => Ok(JwtAlgorithm::ES384),
        "RS256" => Ok(JwtAlgorithm::RS256),
        "RS384" => Ok(JwtAlgorithm::RS384),
        "RS512" => Ok(JwtAlgorithm::RS512),
        "EDDSA" => Ok(JwtAlgorithm::EdDSA),
        _ => anyhow::bail!("unsupported JWT algorithm: {s}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_jwt_algorithm_accepts_known_values() {
        assert!(matches!(
            parse_jwt_algorithm("ES256"),
            Ok(JwtAlgorithm::ES256)
        ));
        assert!(matches!(
            parse_jwt_algorithm("es256"),
            Ok(JwtAlgorithm::ES256)
        ));
        assert!(matches!(
            parse_jwt_algorithm("EDDSA"),
            Ok(JwtAlgorithm::EdDSA)
        ));
    }

    #[test]
    fn parse_jwt_algorithm_rejects_unknown() {
        assert!(parse_jwt_algorithm("HS256").is_err());
    }
}
