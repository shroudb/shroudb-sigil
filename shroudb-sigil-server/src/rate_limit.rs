//! Per-IP rate limiting for login and signup endpoints.
//!
//! Token bucket algorithm keyed by client IP address. Applied as axum
//! middleware on routes that are expensive (argon2id hashing) or
//! security-sensitive (credential stuffing).
//!
//! **X-Forwarded-For** is only trusted when `trust_xff` is explicitly enabled
//! in configuration; otherwise only the direct TCP peer address is used.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Rate limiter state shared across requests.
#[derive(Clone)]
pub struct RateLimitState {
    inner: std::sync::Arc<Mutex<RateLimitInner>>,
    config: RateLimitConfig,
    /// Whether to trust X-Forwarded-For for client IP extraction.
    trust_xff: bool,
}

#[derive(Clone, Copy)]
pub struct RateLimitConfig {
    /// Maximum burst size (tokens).
    pub max_tokens: f64,
    /// Tokens added per second.
    pub refill_rate: f64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_tokens: 10.0,
            refill_rate: 1.0,
        }
    }
}

struct RateLimitInner {
    buckets: HashMap<IpAddr, TokenBucket>,
    last_prune: Instant,
}

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimitState {
    pub fn new(config: RateLimitConfig, trust_xff: bool) -> Self {
        Self {
            inner: std::sync::Arc::new(Mutex::new(RateLimitInner {
                buckets: HashMap::new(),
                last_prune: Instant::now(),
            })),
            config,
            trust_xff,
        }
    }

    /// Try to acquire one token for the given IP. Returns true if allowed.
    fn try_acquire(&self, ip: IpAddr) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let now = Instant::now();

        // Prune stale buckets every 60 seconds.
        if now.duration_since(inner.last_prune).as_secs() > 60 {
            let stale_threshold = now - std::time::Duration::from_secs(120);
            inner.buckets.retain(|_, b| b.last_refill > stale_threshold);
            inner.last_prune = now;
        }

        let bucket = inner.buckets.entry(ip).or_insert(TokenBucket {
            tokens: self.config.max_tokens,
            last_refill: now,
        });

        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens =
            (bucket.tokens + elapsed * self.config.refill_rate).min(self.config.max_tokens);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Axum middleware that enforces per-IP rate limits.
pub async fn rate_limit_middleware(
    State(state): State<RateLimitState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let ip = extract_client_ip(&request, state.trust_xff);

    if let Some(ip) = ip
        && !state.try_acquire(ip)
    {
        metrics::counter!("sigil_rate_limit_rejected_total").increment(1);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            axum::Json(serde_json::json!({"error": "rate limit exceeded"})),
        )
            .into_response();
    }

    next.run(request).await
}

/// Extract the client IP. X-Forwarded-For is only consulted when `trust_xff`
/// is true; otherwise we always use the direct TCP peer address.
fn extract_client_ip(request: &Request<Body>, trust_xff: bool) -> Option<IpAddr> {
    if trust_xff
        && let Some(xff) = request
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
        && let Some(first) = xff.split(',').next()
        && let Ok(ip) = first.trim().parse::<IpAddr>()
    {
        return Some(ip);
    }

    request
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip())
}
