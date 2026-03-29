//! CSRF protection via Origin header validation.
//!
//! For state-changing requests (POST), validates that the Origin header
//! matches the configured allowed origins. If no Origin is present,
//! falls back to the Referer header. Requests from non-browser clients
//! (no Origin, no Referer) are allowed through — they can't carry cookies
//! from a browser context.
//!
//! This complements SameSite=Lax cookies. SameSite=Lax blocks cross-site
//! POST cookies in modern browsers, but Origin validation catches edge cases
//! (older browsers, plugin-initiated requests).

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Origins allowed for CSRF validation.
#[derive(Clone)]
pub struct CsrfConfig {
    /// Parsed allowed origins (e.g., "https://example.com").
    /// Empty = allow all (dev mode).
    pub allowed_origins: Arc<Vec<String>>,
}

impl CsrfConfig {
    pub fn new(origins: &[String]) -> Self {
        let is_wildcard = origins.iter().any(|o| o == "*");
        Self {
            allowed_origins: Arc::new(if is_wildcard {
                Vec::new() // empty = skip validation (dev mode)
            } else {
                origins.to_vec()
            }),
        }
    }
}

/// Axum middleware that validates Origin/Referer on state-changing requests.
pub async fn csrf_middleware(
    State(config): State<CsrfConfig>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Only validate state-changing methods
    if request.method() != Method::POST {
        return next.run(request).await;
    }

    // Skip validation in dev mode (wildcard origins → empty list)
    if config.allowed_origins.is_empty() {
        return next.run(request).await;
    }

    // Check Origin header first
    if let Some(origin) = request
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok())
    {
        if origin_matches(origin, &config.allowed_origins) {
            return next.run(request).await;
        }
        tracing::warn!(origin, "CSRF: Origin header rejected");
        return (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({"error": "CSRF: origin not allowed"})),
        )
            .into_response();
    }

    // Fall back to Referer header
    if let Some(referer) = request
        .headers()
        .get("referer")
        .and_then(|v| v.to_str().ok())
    {
        // Extract origin from referer URL (scheme + host)
        if let Some(referer_origin) = extract_origin_from_url(referer) {
            if origin_matches(&referer_origin, &config.allowed_origins) {
                return next.run(request).await;
            }
            tracing::warn!(referer, "CSRF: Referer header rejected");
            return (
                StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({"error": "CSRF: origin not allowed"})),
            )
                .into_response();
        }
    }

    // No Origin and no Referer — non-browser client (curl, SDK, mobile).
    // These can't carry browser cookies cross-origin, so allow through.
    next.run(request).await
}

/// Check if an origin matches the allowed list.
fn origin_matches(origin: &str, allowed: &[String]) -> bool {
    allowed.iter().any(|a| a == origin)
}

/// Extract "scheme://host[:port]" from a full URL.
fn extract_origin_from_url(url: &str) -> Option<String> {
    // Find "://" to split scheme from rest
    let scheme_end = url.find("://")?;
    let after_scheme = &url[scheme_end + 3..];
    // Host ends at first "/" or end of string
    let host_end = after_scheme.find('/').unwrap_or(after_scheme.len());
    Some(format!(
        "{}://{}",
        &url[..scheme_end],
        &after_scheme[..host_end]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_origin_from_url() {
        assert_eq!(
            extract_origin_from_url("https://example.com/path"),
            Some("https://example.com".to_string())
        );
        assert_eq!(
            extract_origin_from_url("http://localhost:3000/auth/login"),
            Some("http://localhost:3000".to_string())
        );
        assert_eq!(
            extract_origin_from_url("https://app.example.com"),
            Some("https://app.example.com".to_string())
        );
    }

    #[test]
    fn test_origin_matches() {
        let allowed = vec![
            "https://example.com".to_string(),
            "http://localhost:3000".to_string(),
        ];
        assert!(origin_matches("https://example.com", &allowed));
        assert!(origin_matches("http://localhost:3000", &allowed));
        assert!(!origin_matches("https://evil.com", &allowed));
    }
}
