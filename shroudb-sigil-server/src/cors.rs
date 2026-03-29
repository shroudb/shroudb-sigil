//! CORS middleware configuration.

use axum::http::{Method, header};
use tower_http::cors::{AllowOrigin, CorsLayer};

pub fn cors_layer(origins: &[String]) -> CorsLayer {
    let base = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, header::COOKIE]);

    if origins.iter().any(|o| o == "*") {
        tracing::warn!(
            "CORS allow_origin(*) — credentials disabled (browsers reject Access-Control-Allow-Credentials with wildcard origin). \
             Specify exact origins in config for cross-origin cookie support."
        );
        base.allow_origin(AllowOrigin::any())
    } else {
        let parsed: Vec<_> = origins.iter().filter_map(|o| o.parse().ok()).collect();
        base.allow_credentials(true).allow_origin(parsed)
    }
}
