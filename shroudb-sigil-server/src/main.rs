mod cipher_embedded;
mod config;
mod keep_embedded;
mod tcp;
mod veil_embedded;

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use shroudb_cipher_engine::engine::{CipherConfig as CipherEngineConfig, CipherEngine};
use shroudb_crypto::{JwtAlgorithm, SecretBytes};
use shroudb_keep_engine::engine::{KeepConfig as KeepEngineConfig, KeepEngine};
use shroudb_sigil_engine::capabilities::Capabilities;
use shroudb_sigil_engine::engine::{SigilConfig, SigilEngine};
use shroudb_storage::{
    ChainedMasterKeySource, EnvMasterKey, EphemeralKey, FileMasterKey, MasterKeySource,
    StorageEngineConfig,
};
use shroudb_store::Store;
use shroudb_veil_engine::engine::{VeilConfig as VeilEngineConfig, VeilEngine};

use crate::config::{SigilServerConfig, load_config, parse_duration_secs};

struct EmbeddedHandles {
    cipher: Option<Arc<CipherEngine<shroudb_storage::EmbeddedStore>>>,
    veil: Option<Arc<VeilEngine<shroudb_storage::EmbeddedStore>>>,
    keep: Option<Arc<KeepEngine<shroudb_storage::EmbeddedStore>>>,
}

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

            // Embedded Keep needs the same master key the storage opens with.
            let master_key = key_source
                .load()
                .await
                .context("failed to load master key")?;

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
            let handles = build_embedded_handles(&cfg, storage_engine.clone(), master_key).await?;
            run_server(cfg, store, Some(storage_engine), handles).await
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
            for (name, cfg_is_embedded) in [
                (
                    "cipher",
                    cfg.cipher.as_ref().is_some_and(|c| c.is_embedded()),
                ),
                ("veil", cfg.veil.as_ref().is_some_and(|v| v.is_embedded())),
                ("keep", cfg.keep.as_ref().is_some_and(|k| k.is_embedded())),
            ] {
                if cfg_is_embedded {
                    anyhow::bail!(
                        "{name}.mode = \"embedded\" requires store.mode = \"embedded\" \
                         (embedded engines need a co-located StorageEngine)"
                    );
                }
            }
            run_server(
                cfg,
                store,
                None,
                EmbeddedHandles {
                    cipher: None,
                    veil: None,
                    keep: None,
                },
            )
            .await
        }
        other => anyhow::bail!("unknown store mode: {other}"),
    }
}

/// Build in-process `CipherEngine` / `VeilEngine` / `KeepEngine` instances on
/// dedicated namespaces of the same storage engine Sigil uses, for any slot
/// that was configured `mode = "embedded"`. Returns `None` per slot when the
/// slot is absent or points at a remote server.
async fn build_embedded_handles(
    cfg: &SigilServerConfig,
    storage: Arc<shroudb_storage::StorageEngine>,
    master_key: SecretBytes,
) -> anyhow::Result<EmbeddedHandles> {
    use shroudb_cipher_core::keyring::KeyringAlgorithm;
    use shroudb_cipher_engine::keyring_manager::KeyringCreateOpts;
    use shroudb_server_bootstrap::Capability;

    let cipher = if let Some(ref c) = cfg.cipher {
        c.validate(&cfg.store.mode)
            .context("invalid [cipher] config")?;
        if c.is_embedded() {
            let store = Arc::new(shroudb_storage::EmbeddedStore::new(
                storage.clone(),
                "cipher",
            ));
            let engine_cfg = CipherEngineConfig {
                default_rotation_days: c.rotation_days,
                default_drain_days: c.drain_days,
                scheduler_interval_secs: c.scheduler_interval_secs,
            };
            let engine = CipherEngine::new(
                store,
                engine_cfg,
                Capability::disabled(
                    "sigil-server embedded Cipher: policy routed through Sigil's own sentry slot",
                ),
                Capability::disabled(
                    "sigil-server embedded Cipher: audit routed through Sigil's own chronicle slot",
                ),
            )
            .await
            .context("failed to initialize embedded Cipher engine")?;

            let algorithm: KeyringAlgorithm = c
                .algorithm
                .parse()
                .map_err(|e: String| anyhow::anyhow!("invalid cipher.algorithm: {e}"))?;
            match engine
                .keyring_manager()
                .create(
                    &c.keyring,
                    algorithm,
                    KeyringCreateOpts {
                        rotation_days: c.rotation_days,
                        drain_days: c.drain_days,
                        ..Default::default()
                    },
                )
                .await
            {
                Ok(_) | Err(shroudb_cipher_core::error::CipherError::KeyringExists(_)) => {}
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "failed to seed embedded cipher keyring '{}': {e}",
                        c.keyring
                    ));
                }
            }
            tracing::info!(keyring = %c.keyring, "embedded Cipher engine initialized on 'cipher' namespace");
            Some(Arc::new(engine))
        } else {
            None
        }
    } else {
        None
    };

    let veil = if let Some(ref v) = cfg.veil {
        v.validate(&cfg.store.mode)
            .context("invalid [veil] config")?;
        if v.is_embedded() {
            let store = Arc::new(shroudb_storage::EmbeddedStore::new(storage.clone(), "veil"));
            let engine = VeilEngine::new(
                store,
                VeilEngineConfig::default(),
                Capability::disabled(
                    "sigil-server embedded Veil: policy routed through Sigil's own sentry slot",
                ),
                Capability::disabled(
                    "sigil-server embedded Veil: audit routed through Sigil's own chronicle slot",
                ),
            )
            .await
            .context("failed to initialize embedded Veil engine")?;

            match engine.index_manager().create(&v.index).await {
                Ok(_) | Err(shroudb_veil_core::error::VeilError::IndexExists(_)) => {}
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "failed to seed embedded veil index '{}': {e}",
                        v.index
                    ));
                }
            }
            tracing::info!(index = %v.index, "embedded Veil engine initialized on 'veil' namespace");
            Some(Arc::new(engine))
        } else {
            None
        }
    } else {
        None
    };

    let keep = if let Some(ref k) = cfg.keep {
        k.validate(&cfg.store.mode)
            .context("invalid [keep] config")?;
        if k.is_embedded() {
            let store = Arc::new(shroudb_storage::EmbeddedStore::new(storage, "keep"));
            let engine_cfg = KeepEngineConfig {
                max_versions: k.max_versions,
            };
            let engine = KeepEngine::new(
                store,
                engine_cfg,
                master_key,
                Capability::disabled(
                    "sigil-server embedded Keep: policy routed through Sigil's own sentry slot",
                ),
                Capability::disabled(
                    "sigil-server embedded Keep: audit routed through Sigil's own chronicle slot",
                ),
            )
            .await
            .context("failed to initialize embedded Keep engine")?;
            tracing::info!("embedded Keep engine initialized on 'keep' namespace");
            Some(Arc::new(engine))
        } else {
            None
        }
    } else {
        None
    };

    Ok(EmbeddedHandles { cipher, veil, keep })
}

async fn run_server<S: Store + 'static>(
    cfg: SigilServerConfig,
    store: Arc<S>,
    storage: Option<Arc<shroudb_storage::StorageEngine>>,
    embedded: EmbeddedHandles,
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

    let cipher_cap: Capability<Box<dyn shroudb_sigil_engine::capabilities::CipherOps>> = match (
        cfg.cipher.as_ref(),
        embedded.cipher,
    ) {
        (Some(cfg_c), Some(engine)) if cfg_c.is_embedded() => {
            tracing::info!(keyring = %cfg_c.keyring, "cipher: using embedded in-process CipherEngine");
            Capability::Enabled(Box::new(cipher_embedded::EmbeddedCipherOps::new(
                engine,
                cfg_c.keyring.clone(),
            )))
        }
        (Some(cfg_c), _) if cfg_c.is_remote() => {
            let addr = cfg_c
                .addr
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("cipher.mode = \"remote\" requires cipher.addr"))?;
            let cipher_ops = shroudb_sigil_engine::cipher_remote::RemoteCipherOps::connect(
                addr,
                cfg_c.keyring.clone(),
                cfg_c.auth_token.as_deref(),
                cfg_c.pool_size,
            )
            .await
            .context("failed to connect to cipher server")?;
            tracing::info!(addr, keyring = %cfg_c.keyring, "cipher connected");
            Capability::Enabled(Box::new(cipher_ops))
        }
        _ => Capability::disabled(
            "no [cipher] section in sigil config — PII fields cannot be encrypted/decrypted",
        ),
    };

    let veil_cap: Capability<Box<dyn shroudb_sigil_engine::capabilities::VeilOps>> =
        match (cfg.veil.as_ref(), embedded.veil) {
            (Some(cfg_v), Some(engine)) if cfg_v.is_embedded() => {
                tracing::info!(index = %cfg_v.index, "veil: using embedded in-process VeilEngine");
                Capability::Enabled(Box::new(veil_embedded::EmbeddedVeilOps::new(
                    engine,
                    cfg_v.index.clone(),
                )))
            }
            (Some(cfg_v), _) if cfg_v.is_remote() => {
                let addr = cfg_v
                    .addr
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("veil.mode = \"remote\" requires veil.addr"))?;
                let veil_ops = shroudb_sigil_engine::veil_remote::RemoteVeilOps::connect(
                    addr,
                    cfg_v.index.clone(),
                    cfg_v.auth_token.as_deref(),
                    cfg_v.pool_size,
                )
                .await
                .context("failed to connect to veil server")?;
                tracing::info!(addr, index = %cfg_v.index, "veil connected");
                Capability::Enabled(Box::new(veil_ops))
            }
            _ => Capability::disabled(
                "no [veil] section in sigil config — searchable blind-index fields disabled",
            ),
        };

    let keep_cap: Capability<Box<dyn shroudb_sigil_engine::capabilities::KeepOps>> =
        match (cfg.keep.as_ref(), embedded.keep) {
            (Some(cfg_k), Some(engine)) if cfg_k.is_embedded() => {
                tracing::info!("keep: using embedded in-process KeepEngine");
                Capability::Enabled(Box::new(keep_embedded::EmbeddedKeepOps::new(engine)))
            }
            (Some(cfg_k), _) if cfg_k.is_remote() => {
                let addr = cfg_k
                    .addr
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("keep.mode = \"remote\" requires keep.addr"))?;
                let keep_ops = shroudb_sigil_engine::keep_remote::RemoteKeepOps::connect(
                    addr,
                    cfg_k.auth_token.as_deref(),
                    cfg_k.pool_size,
                )
                .await
                .context("failed to connect to keep server")?;
                tracing::info!(addr, "keep connected");
                Capability::Enabled(Box::new(keep_ops))
            }
            _ => Capability::disabled(
                "no [keep] section in sigil config — secret-annotated fields cannot be stored",
            ),
        };

    // Resolve [chronicle] and [sentry] via engine-bootstrap. Omitting either
    // section now yields the bootstrap default (embedded mode) instead of
    // failing at startup — operators who want remote or disabled must say so
    // explicitly. Embedded init failures still surface as hard errors.
    let chronicle_cfg = cfg.chronicle.clone().unwrap_or_default();
    let chronicle_cap = chronicle_cfg
        .resolve(storage.clone())
        .await
        .context("failed to resolve [chronicle] capability")?;
    let sentry_cfg = cfg.sentry.clone().unwrap_or_default();
    let sentry_cap = sentry_cfg
        .resolve(storage.clone(), chronicle_cap.as_ref().cloned())
        .await
        .context("failed to resolve [sentry] capability")?;

    let capabilities = Capabilities::new(cipher_cap, veil_cap, keep_cap, sentry_cap, chronicle_cap);

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
