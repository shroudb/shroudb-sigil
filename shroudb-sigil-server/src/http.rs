use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};

use shroudb_sigil_engine::engine::SigilEngine;
use shroudb_storage::EmbeddedStore;

use crate::cors;
use crate::csrf::{CsrfConfig, csrf_middleware};
use crate::rate_limit::{RateLimitConfig, RateLimitState, rate_limit_middleware};

type AppState = Arc<SigilEngine<EmbeddedStore>>;

/// HTTP router configuration.
pub struct HttpConfig {
    pub cors_origins: Vec<String>,
    pub rate_limit_burst: f64,
    pub rate_limit_per_sec: f64,
    pub trust_xff: bool,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            cors_origins: vec!["*".to_string()],
            rate_limit_burst: 10.0,
            rate_limit_per_sec: 2.0,
            trust_xff: false,
        }
    }
}

pub fn router(engine: AppState, http_config: HttpConfig) -> Router {
    let csrf_config = CsrfConfig::new(&http_config.cors_origins);
    let rate_state = RateLimitState::new(
        RateLimitConfig {
            max_tokens: http_config.rate_limit_burst,
            refill_rate: http_config.rate_limit_per_sec,
        },
        http_config.trust_xff,
    );

    // Rate-limited routes (expensive argon2 + credential stuffing targets)
    let rate_limited = Router::new()
        .route("/sigil/{schema}/users", post(user_create))
        .route("/sigil/{schema}/users/import", post(user_import))
        .route("/sigil/{schema}/verify", post(verify))
        .route("/sigil/{schema}/sessions", post(session_create))
        .route("/sigil/{schema}/password/change", post(password_change))
        .route("/sigil/{schema}/password/reset", post(password_reset))
        .route("/sigil/{schema}/password/import", post(password_import))
        .route_layer(middleware::from_fn_with_state(
            rate_state,
            rate_limit_middleware,
        ))
        .with_state(engine.clone());

    // Non-rate-limited routes
    let open = Router::new()
        .route("/sigil/schemas", post(schema_register))
        .route("/sigil/schemas/{name}", get(schema_get))
        .route("/sigil/{schema}/users/{id}", get(user_get))
        .route(
            "/sigil/{schema}/users/{id}",
            axum::routing::patch(user_update),
        )
        .route("/sigil/{schema}/users/{id}", delete(user_delete))
        .route("/sigil/{schema}/sessions", delete(session_revoke_body))
        .route("/sigil/{schema}/sessions/refresh", post(session_refresh))
        .route("/sigil/{schema}/sessions/{user_id}", get(session_list))
        .route("/sigil/{schema}/.well-known/jwks.json", get(jwks))
        .route("/sigil/health", get(health))
        .with_state(engine);

    Router::new()
        .merge(rate_limited)
        .merge(open)
        .layer(middleware::from_fn_with_state(csrf_config, csrf_middleware))
        .layer(cors::cors_layer(&http_config.cors_origins))
}

// ── Helpers ─────────────────────────────────────────────────────────

fn ok_json(data: serde_json::Value) -> Response {
    (StatusCode::OK, Json(data)).into_response()
}

fn created_json(data: serde_json::Value) -> Response {
    (StatusCode::CREATED, Json(data)).into_response()
}

fn err_response(status: StatusCode, msg: &str) -> Response {
    (status, Json(serde_json::json!({"error": msg}))).into_response()
}

fn map_err(e: shroudb_sigil_core::error::SigilError) -> Response {
    use shroudb_sigil_core::error::SigilError;
    match &e {
        SigilError::SchemaNotFound(_) | SigilError::UserNotFound => {
            err_response(StatusCode::NOT_FOUND, &e.to_string())
        }
        SigilError::SchemaExists(_) | SigilError::UserExists => {
            err_response(StatusCode::CONFLICT, &e.to_string())
        }
        SigilError::VerificationFailed => err_response(StatusCode::UNAUTHORIZED, &e.to_string()),
        SigilError::AccountLocked { .. } => {
            err_response(StatusCode::TOO_MANY_REQUESTS, &e.to_string())
        }
        SigilError::InvalidToken | SigilError::TokenExpired | SigilError::TokenReuse => {
            err_response(StatusCode::UNAUTHORIZED, &e.to_string())
        }
        SigilError::SchemaValidation(_)
        | SigilError::MissingField(_)
        | SigilError::InvalidField { .. }
        | SigilError::ImportFailed(_) => err_response(StatusCode::BAD_REQUEST, &e.to_string()),
        SigilError::CapabilityMissing(_) => {
            err_response(StatusCode::SERVICE_UNAVAILABLE, &e.to_string())
        }
        _ => err_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

// ── Schema ──────────────────────────────────────────────────────────

async fn schema_register(
    State(engine): State<AppState>,
    Json(schema): Json<shroudb_sigil_core::schema::Schema>,
) -> Response {
    match engine.schema_register(schema).await {
        Ok(version) => created_json(serde_json::json!({"status": "ok", "version": version})),
        Err(e) => map_err(e),
    }
}

async fn schema_get(State(engine): State<AppState>, Path(name): Path<String>) -> Response {
    match engine.schema_get(&name).await {
        Ok(schema) => ok_json(serde_json::json!(schema)),
        Err(e) => map_err(e),
    }
}

// ── User ────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct CreateUserBody {
    fields: std::collections::HashMap<String, serde_json::Value>,
}

async fn user_create(
    State(engine): State<AppState>,
    Path(schema): Path<String>,
    Json(body): Json<CreateUserBody>,
) -> Response {
    // user_id must be in the fields or as a separate field
    let user_id = body
        .fields
        .get("user_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if user_id.is_empty() {
        return err_response(StatusCode::BAD_REQUEST, "user_id required in fields");
    }

    let mut fields = body.fields;
    fields.remove("user_id");

    match engine.user_create(&schema, &user_id, &fields).await {
        Ok(record) => created_json(serde_json::json!({
            "user_id": record.user_id,
            "fields": record.fields,
            "created_at": record.created_at,
        })),
        Err(e) => map_err(e),
    }
}

async fn user_import(
    State(engine): State<AppState>,
    Path(schema): Path<String>,
    Json(body): Json<CreateUserBody>,
) -> Response {
    let user_id = body
        .fields
        .get("user_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if user_id.is_empty() {
        return err_response(StatusCode::BAD_REQUEST, "user_id required in fields");
    }

    let mut fields = body.fields;
    fields.remove("user_id");

    match engine.user_import(&schema, &user_id, &fields).await {
        Ok(record) => created_json(serde_json::json!({
            "user_id": record.user_id,
            "fields": record.fields,
            "created_at": record.created_at,
        })),
        Err(e) => map_err(e),
    }
}

#[derive(serde::Deserialize)]
struct UserPath {
    schema: String,
    id: String,
}

async fn user_get(State(engine): State<AppState>, Path(path): Path<UserPath>) -> Response {
    match engine.user_get(&path.schema, &path.id).await {
        Ok(record) => ok_json(serde_json::json!({
            "user_id": record.user_id,
            "fields": record.fields,
            "created_at": record.created_at,
            "updated_at": record.updated_at,
        })),
        Err(e) => map_err(e),
    }
}

#[derive(serde::Deserialize)]
struct UpdateUserBody {
    fields: std::collections::HashMap<String, serde_json::Value>,
}

async fn user_update(
    State(engine): State<AppState>,
    Path(path): Path<UserPath>,
    Json(body): Json<UpdateUserBody>,
) -> Response {
    match engine
        .user_update(&path.schema, &path.id, &body.fields)
        .await
    {
        Ok(record) => ok_json(serde_json::json!({
            "user_id": record.user_id,
            "fields": record.fields,
            "updated_at": record.updated_at,
        })),
        Err(e) => map_err(e),
    }
}

async fn user_delete(State(engine): State<AppState>, Path(path): Path<UserPath>) -> Response {
    match engine.user_delete(&path.schema, &path.id).await {
        Ok(()) => ok_json(serde_json::json!({"status": "ok"})),
        Err(e) => map_err(e),
    }
}

// ── Verify ──────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct VerifyBody {
    user_id: String,
    password: String,
}

async fn verify(
    State(engine): State<AppState>,
    Path(schema): Path<String>,
    Json(body): Json<VerifyBody>,
) -> Response {
    match engine
        .user_verify(&schema, &body.user_id, &body.password)
        .await
    {
        Ok(_) => ok_json(serde_json::json!({"status": "ok", "valid": true})),
        Err(e) => map_err(e),
    }
}

// ── Sessions ────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct LoginBody {
    user_id: String,
    password: String,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
}

async fn session_create(
    State(engine): State<AppState>,
    Path(schema): Path<String>,
    Json(body): Json<LoginBody>,
) -> Response {
    match engine
        .session_create(
            &schema,
            &body.user_id,
            &body.password,
            body.metadata.as_ref(),
        )
        .await
    {
        Ok(pair) => ok_json(serde_json::json!({
            "access_token": pair.access_token,
            "refresh_token": pair.refresh_token,
            "expires_in": pair.expires_in,
        })),
        Err(e) => map_err(e),
    }
}

#[derive(serde::Deserialize)]
struct RefreshBody {
    refresh_token: String,
}

async fn session_refresh(
    State(engine): State<AppState>,
    Path(schema): Path<String>,
    Json(body): Json<RefreshBody>,
) -> Response {
    match engine.session_refresh(&schema, &body.refresh_token).await {
        Ok(pair) => ok_json(serde_json::json!({
            "access_token": pair.access_token,
            "refresh_token": pair.refresh_token,
            "expires_in": pair.expires_in,
        })),
        Err(e) => map_err(e),
    }
}

#[derive(serde::Deserialize)]
struct RevokeBody {
    refresh_token: Option<String>,
    user_id: Option<String>,
}

async fn session_revoke_body(
    State(engine): State<AppState>,
    Path(schema): Path<String>,
    Json(body): Json<RevokeBody>,
) -> Response {
    if let Some(ref token) = body.refresh_token {
        match engine.session_revoke(&schema, token).await {
            Ok(()) => ok_json(serde_json::json!({"status": "ok"})),
            Err(e) => map_err(e),
        }
    } else if let Some(ref user_id) = body.user_id {
        match engine.session_revoke_all(&schema, user_id).await {
            Ok(count) => ok_json(serde_json::json!({"status": "ok", "revoked": count})),
            Err(e) => map_err(e),
        }
    } else {
        err_response(StatusCode::BAD_REQUEST, "refresh_token or user_id required")
    }
}

#[derive(serde::Deserialize)]
struct SessionListPath {
    schema: String,
    user_id: String,
}

async fn session_list(
    State(engine): State<AppState>,
    Path(path): Path<SessionListPath>,
) -> Response {
    match engine.session_list(&path.schema, &path.user_id).await {
        Ok(sessions) => {
            let items: Vec<serde_json::Value> = sessions
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "family_id": s.family_id,
                        "generation": s.generation,
                        "created_at": s.created_at,
                        "expires_at": s.expires_at,
                    })
                })
                .collect();
            ok_json(serde_json::json!(items))
        }
        Err(e) => map_err(e),
    }
}

// ── Password ────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct ChangePasswordBody {
    user_id: String,
    old_password: String,
    new_password: String,
}

async fn password_change(
    State(engine): State<AppState>,
    Path(schema): Path<String>,
    Json(body): Json<ChangePasswordBody>,
) -> Response {
    match engine
        .password_change(
            &schema,
            &body.user_id,
            &body.old_password,
            &body.new_password,
        )
        .await
    {
        Ok(()) => ok_json(serde_json::json!({"status": "ok"})),
        Err(e) => map_err(e),
    }
}

#[derive(serde::Deserialize)]
struct ResetPasswordBody {
    user_id: String,
    new_password: String,
}

async fn password_reset(
    State(engine): State<AppState>,
    Path(schema): Path<String>,
    Json(body): Json<ResetPasswordBody>,
) -> Response {
    match engine
        .password_reset(&schema, &body.user_id, &body.new_password)
        .await
    {
        Ok(()) => ok_json(serde_json::json!({"status": "ok"})),
        Err(e) => map_err(e),
    }
}

#[derive(serde::Deserialize)]
struct ImportPasswordBody {
    user_id: String,
    hash: String,
}

async fn password_import(
    State(engine): State<AppState>,
    Path(schema): Path<String>,
    Json(body): Json<ImportPasswordBody>,
) -> Response {
    match engine
        .password_import(&schema, &body.user_id, &body.hash)
        .await
    {
        Ok(algo) => ok_json(serde_json::json!({
            "status": "ok",
            "algorithm": format!("{algo:?}").to_lowercase(),
        })),
        Err(e) => map_err(e),
    }
}

// ── JWT ─────────────────────────────────────────────────────────────

async fn jwks(State(engine): State<AppState>, Path(schema): Path<String>) -> Response {
    match engine.jwks(&schema).await {
        Ok(jwks) => ok_json(jwks),
        Err(e) => map_err(e),
    }
}

// ── Health ──────────────────────────────────────────────────────────

async fn health() -> Response {
    ok_json(serde_json::json!({"status": "ok"}))
}
