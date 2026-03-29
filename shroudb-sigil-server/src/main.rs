mod config;
mod http;
mod tcp;

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use shroudb_crypto::JwtAlgorithm;
use shroudb_sigil_engine::capabilities::Capabilities;
use shroudb_sigil_engine::engine::{SigilConfig, SigilEngine};
use shroudb_storage::{
    ChainedMasterKeySource, EnvMasterKey, FileMasterKey, MasterKeySource, StorageEngineConfig,
};

use crate::config::{load_config, parse_duration_secs};

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

    // Disable core dumps on Linux
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }

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

    // Store mode validation
    if cfg.store.mode == "remote" {
        anyhow::bail!(
            "remote store mode not yet implemented (uri: {:?})",
            cfg.store.uri
        );
    }

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
    let storage_engine = shroudb_storage::StorageEngine::open(engine_config, key_source.as_ref())
        .await
        .context("failed to open storage engine")?;
    let store = Arc::new(shroudb_storage::EmbeddedStore::new(
        Arc::new(storage_engine),
        "sigil",
    ));

    // Sigil engine
    let jwt_algorithm = parse_jwt_algorithm(&cfg.auth.jwt_algorithm)?;
    let sigil_config = SigilConfig {
        jwt_algorithm,
        access_ttl_secs: parse_duration_secs(&cfg.auth.access_ttl)?,
        refresh_ttl_secs: parse_duration_secs(&cfg.auth.refresh_ttl)?,
        ..Default::default()
    };
    let engine = Arc::new(
        SigilEngine::new(store, sigil_config, Capabilities::default())
            .await
            .context("failed to initialize sigil engine")?,
    );

    // Shutdown signal
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // TCP server
    let tcp_listener = tokio::net::TcpListener::bind(cfg.server.tcp_bind)
        .await
        .context("failed to bind TCP")?;

    let tcp_engine = engine.clone();
    let tcp_shutdown = shutdown_rx.clone();
    let tcp_handle = tokio::spawn(async move {
        tcp::run_tcp(tcp_listener, tcp_engine, tcp_shutdown).await;
    });

    // HTTP server
    let http_listener = tokio::net::TcpListener::bind(cfg.server.http_bind)
        .await
        .context("failed to bind HTTP")?;

    let http_router = http::router(engine.clone());
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

/// Ephemeral master key for dev mode (data won't survive restarts).
struct EphemeralKey;

impl MasterKeySource for EphemeralKey {
    fn source_name(&self) -> &str {
        "ephemeral"
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
        Box::pin(async {
            tracing::warn!("using ephemeral master key — data will not survive restart");
            let key = ring::rand::SystemRandom::new();
            let mut bytes = vec![0u8; 32];
            ring::rand::SecureRandom::fill(&key, &mut bytes)
                .map_err(|_| shroudb_storage::StorageError::Internal("RNG failed".into()))?;
            Ok(shroudb_crypto::SecretBytes::new(bytes))
        })
    }
}
