use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};

use shroudb_acl::{AuthContext, TokenValidator};
use shroudb_sigil_engine::engine::SigilEngine;
use shroudb_sigil_protocol::commands::SigilCommand;
use shroudb_sigil_protocol::dispatch::dispatch;
use shroudb_sigil_protocol::response::SigilResponse;
use shroudb_store::Store;

use crate::cors;
use crate::csrf::{CsrfConfig, csrf_middleware};
use crate::rate_limit::{RateLimitConfig, RateLimitState, rate_limit_middleware};

/// Shared state for HTTP handlers.
struct AppState<S: Store> {
    engine: Arc<SigilEngine<S>>,
    token_validator: Option<Arc<dyn TokenValidator>>,
}

impl<S: Store> Clone for AppState<S> {
    fn clone(&self) -> Self {
        Self {
            engine: self.engine.clone(),
            token_validator: self.token_validator.clone(),
        }
    }
}

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

pub fn router<S: Store + 'static>(
    engine: Arc<SigilEngine<S>>,
    token_validator: Option<Arc<dyn TokenValidator>>,
    http_config: HttpConfig,
) -> Router {
    let state = AppState {
        engine,
        token_validator,
    };
    let csrf_config = CsrfConfig::new(&http_config.cors_origins);
    let rate_state = RateLimitState::new(
        RateLimitConfig {
            max_tokens: http_config.rate_limit_burst,
            refill_rate: http_config.rate_limit_per_sec,
        },
        http_config.trust_xff,
    );

    let rate_limited = Router::new()
        .route("/sigil/{schema}/users", post(user_create::<S>))
        .route("/sigil/{schema}/users/import", post(user_import::<S>))
        .route("/sigil/{schema}/verify", post(verify::<S>))
        .route("/sigil/{schema}/lookup", post(user_lookup::<S>))
        .route("/sigil/{schema}/sessions", post(session_create::<S>))
        .route("/sigil/{schema}/sessions/login", post(session_login::<S>))
        .route(
            "/sigil/{schema}/password/change",
            post(password_change::<S>),
        )
        .route("/sigil/{schema}/password/reset", post(password_reset::<S>))
        .route(
            "/sigil/{schema}/password/import",
            post(password_import::<S>),
        )
        .route_layer(middleware::from_fn_with_state(
            rate_state,
            rate_limit_middleware,
        ))
        .with_state(state.clone());

    let open = Router::new()
        .route("/sigil/schemas", post(schema_register::<S>))
        .route("/sigil/schemas/{name}", get(schema_get::<S>))
        .route("/sigil/{schema}/users/{id}", get(user_get::<S>))
        .route(
            "/sigil/{schema}/users/{id}",
            axum::routing::patch(user_update::<S>),
        )
        .route("/sigil/{schema}/users/{id}", delete(user_delete::<S>))
        .route("/sigil/{schema}/sessions", delete(session_revoke_body::<S>))
        .route(
            "/sigil/{schema}/sessions/refresh",
            post(session_refresh::<S>),
        )
        .route(
            "/sigil/{schema}/sessions/{entity_id}",
            get(session_list::<S>),
        )
        .route("/sigil/{schema}/.well-known/jwks.json", get(jwks::<S>))
        .route("/sigil/health", get(health))
        .with_state(state);

    Router::new()
        .merge(rate_limited)
        .merge(open)
        .layer(middleware::from_fn_with_state(csrf_config, csrf_middleware))
        .layer(cors::cors_layer(&http_config.cors_origins))
}

// ── Auth helper ─────────────────────────────────────────────────────

/// Extract the AuthContext from the Bearer token in the Authorization header.
fn extract_auth_context<S: Store>(
    state: &AppState<S>,
    headers: &HeaderMap,
) -> Result<Option<AuthContext>, Box<Response>> {
    let Some(ref validator) = state.token_validator else {
        return Ok(None);
    };

    let Some(auth_header) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
        return Ok(None);
    };

    let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        Box::new(err_response(
            StatusCode::UNAUTHORIZED,
            "expected Bearer token",
        ))
    })?;

    match validator.validate(token) {
        Ok(tok) => Ok(Some(tok.into_context())),
        Err(e) => Err(Box::new(err_response(
            StatusCode::UNAUTHORIZED,
            &format!("invalid token: {e}"),
        ))),
    }
}

/// Run a SigilCommand through dispatch with ACL checks.
/// This is the single code path for both TCP and HTTP — ACL is in dispatch.
async fn run_command<S: Store + 'static>(
    state: &AppState<S>,
    headers: &HeaderMap,
    cmd: SigilCommand,
) -> Result<SigilResponse, Response> {
    let auth = extract_auth_context(state, headers).map_err(|e| *e)?;

    if state.token_validator.is_some()
        && auth.is_none()
        && cmd.acl_requirement() != shroudb_acl::AclRequirement::None
    {
        return Err(err_response(
            StatusCode::UNAUTHORIZED,
            "authentication required — provide Authorization: Bearer <token>",
        ));
    }

    Ok(dispatch(&state.engine, cmd, auth.as_ref()).await)
}

/// Convert a SigilResponse to an HTTP response.
fn sigil_to_http(resp: SigilResponse, success_status: StatusCode) -> Response {
    match resp {
        SigilResponse::Ok(data) => (success_status, Json(data)).into_response(),
        SigilResponse::Error(msg) => {
            // Map error messages to HTTP status codes
            let status = if msg.contains("not found") {
                StatusCode::NOT_FOUND
            } else if msg.contains("already exists") {
                StatusCode::CONFLICT
            } else if msg.contains("access denied") {
                StatusCode::FORBIDDEN
            } else if msg.contains("verification failed")
                || msg.contains("invalid token")
                || msg.contains("expired")
                || msg.contains("reuse")
            {
                StatusCode::UNAUTHORIZED
            } else if msg.contains("locked") {
                StatusCode::TOO_MANY_REQUESTS
            } else if msg.contains("capability") {
                StatusCode::SERVICE_UNAVAILABLE
            } else if msg.contains("validation")
                || msg.contains("missing")
                || msg.contains("invalid")
                || msg.contains("import failed")
            {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (status, Json(serde_json::json!({"error": msg}))).into_response()
        }
    }
}

fn err_response(status: StatusCode, msg: &str) -> Response {
    (status, Json(serde_json::json!({"error": msg}))).into_response()
}

// ── Handlers ────────────────────────────────────────────────────────
// Each handler builds a SigilCommand and routes through run_command.
// ACL checks happen in dispatch — handlers don't check auth themselves.

async fn schema_register<S: Store + 'static>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    Json(schema): Json<shroudb_sigil_core::schema::Schema>,
) -> Response {
    let cmd = SigilCommand::SchemaRegister { schema };
    match run_command(&state, &headers, cmd).await {
        Ok(resp) => sigil_to_http(resp, StatusCode::CREATED),
        Err(r) => r,
    }
}

async fn schema_get<S: Store + 'static>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    let cmd = SigilCommand::SchemaGet { name };
    match run_command(&state, &headers, cmd).await {
        Ok(resp) => sigil_to_http(resp, StatusCode::OK),
        Err(r) => r,
    }
}

#[derive(serde::Deserialize)]
struct CreateUserBody {
    fields: std::collections::HashMap<String, serde_json::Value>,
}

async fn user_create<S: Store + 'static>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    Path(schema): Path<String>,
    Json(body): Json<CreateUserBody>,
) -> Response {
    let entity_id = body
        .fields
        .get("entity_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if entity_id.is_empty() {
        return err_response(StatusCode::BAD_REQUEST, "entity_id required in fields");
    }
    let mut fields = body.fields;
    fields.remove("entity_id");

    let cmd = SigilCommand::UserCreate {
        schema,
        user_id: entity_id,
        fields,
    };
    match run_command(&state, &headers, cmd).await {
        Ok(resp) => sigil_to_http(resp, StatusCode::CREATED),
        Err(r) => r,
    }
}

async fn user_import<S: Store + 'static>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    Path(schema): Path<String>,
    Json(body): Json<CreateUserBody>,
) -> Response {
    let entity_id = body
        .fields
        .get("entity_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if entity_id.is_empty() {
        return err_response(StatusCode::BAD_REQUEST, "entity_id required in fields");
    }
    let mut fields = body.fields;
    fields.remove("entity_id");

    let cmd = SigilCommand::UserImport {
        schema,
        user_id: entity_id,
        fields,
    };
    match run_command(&state, &headers, cmd).await {
        Ok(resp) => sigil_to_http(resp, StatusCode::CREATED),
        Err(r) => r,
    }
}

#[derive(serde::Deserialize)]
struct UserPath {
    schema: String,
    id: String,
}

async fn user_get<S: Store + 'static>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    Path(path): Path<UserPath>,
) -> Response {
    let cmd = SigilCommand::UserGet {
        schema: path.schema,
        user_id: path.id,
    };
    match run_command(&state, &headers, cmd).await {
        Ok(resp) => sigil_to_http(resp, StatusCode::OK),
        Err(r) => r,
    }
}

#[derive(serde::Deserialize)]
struct UpdateUserBody {
    fields: std::collections::HashMap<String, serde_json::Value>,
}

async fn user_update<S: Store + 'static>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    Path(path): Path<UserPath>,
    Json(body): Json<UpdateUserBody>,
) -> Response {
    let cmd = SigilCommand::UserUpdate {
        schema: path.schema,
        user_id: path.id,
        fields: body.fields,
    };
    match run_command(&state, &headers, cmd).await {
        Ok(resp) => sigil_to_http(resp, StatusCode::OK),
        Err(r) => r,
    }
}

async fn user_delete<S: Store + 'static>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    Path(path): Path<UserPath>,
) -> Response {
    let cmd = SigilCommand::UserDelete {
        schema: path.schema,
        user_id: path.id,
    };
    match run_command(&state, &headers, cmd).await {
        Ok(resp) => sigil_to_http(resp, StatusCode::OK),
        Err(r) => r,
    }
}

#[derive(serde::Deserialize)]
struct VerifyBody {
    entity_id: String,
    password: String,
}

async fn verify<S: Store + 'static>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    Path(schema): Path<String>,
    Json(body): Json<VerifyBody>,
) -> Response {
    let cmd = SigilCommand::UserVerify {
        schema,
        user_id: body.entity_id,
        password: body.password,
    };
    match run_command(&state, &headers, cmd).await {
        Ok(resp) => sigil_to_http(resp, StatusCode::OK),
        Err(r) => r,
    }
}

#[derive(serde::Deserialize)]
struct LookupBody {
    field: String,
    value: String,
}

async fn user_lookup<S: Store + 'static>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    Path(schema): Path<String>,
    Json(body): Json<LookupBody>,
) -> Response {
    let cmd = SigilCommand::UserLookup {
        schema,
        field_name: body.field,
        field_value: body.value,
    };
    match run_command(&state, &headers, cmd).await {
        Ok(resp) => sigil_to_http(resp, StatusCode::OK),
        Err(r) => r,
    }
}

#[derive(serde::Deserialize)]
struct FieldLoginBody {
    field: String,
    value: String,
    password: String,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
}

async fn session_login<S: Store + 'static>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    Path(schema): Path<String>,
    Json(body): Json<FieldLoginBody>,
) -> Response {
    let cmd = SigilCommand::SessionCreateByField {
        schema,
        field_name: body.field,
        field_value: body.value,
        password: body.password,
        metadata: body.metadata,
    };
    match run_command(&state, &headers, cmd).await {
        Ok(resp) => sigil_to_http(resp, StatusCode::OK),
        Err(r) => r,
    }
}

#[derive(serde::Deserialize)]
struct LoginBody {
    entity_id: String,
    password: String,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
}

async fn session_create<S: Store + 'static>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    Path(schema): Path<String>,
    Json(body): Json<LoginBody>,
) -> Response {
    let cmd = SigilCommand::SessionCreate {
        schema,
        entity_id: body.entity_id,
        password: body.password,
        metadata: body.metadata,
    };
    match run_command(&state, &headers, cmd).await {
        Ok(resp) => sigil_to_http(resp, StatusCode::OK),
        Err(r) => r,
    }
}

#[derive(serde::Deserialize)]
struct RefreshBody {
    refresh_token: String,
}

async fn session_refresh<S: Store + 'static>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    Path(schema): Path<String>,
    Json(body): Json<RefreshBody>,
) -> Response {
    let cmd = SigilCommand::SessionRefresh {
        schema,
        token: body.refresh_token,
    };
    match run_command(&state, &headers, cmd).await {
        Ok(resp) => sigil_to_http(resp, StatusCode::OK),
        Err(r) => r,
    }
}

#[derive(serde::Deserialize)]
struct RevokeBody {
    refresh_token: Option<String>,
    entity_id: Option<String>,
}

async fn session_revoke_body<S: Store + 'static>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    Path(schema): Path<String>,
    Json(body): Json<RevokeBody>,
) -> Response {
    let cmd = if let Some(token) = body.refresh_token {
        SigilCommand::SessionRevoke { schema, token }
    } else if let Some(entity_id) = body.entity_id {
        SigilCommand::SessionRevokeAll { schema, entity_id }
    } else {
        return err_response(
            StatusCode::BAD_REQUEST,
            "refresh_token or entity_id required",
        );
    };
    match run_command(&state, &headers, cmd).await {
        Ok(resp) => sigil_to_http(resp, StatusCode::OK),
        Err(r) => r,
    }
}

#[derive(serde::Deserialize)]
struct SessionListPath {
    schema: String,
    entity_id: String,
}

async fn session_list<S: Store + 'static>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    Path(path): Path<SessionListPath>,
) -> Response {
    let cmd = SigilCommand::SessionList {
        schema: path.schema,
        entity_id: path.entity_id,
    };
    match run_command(&state, &headers, cmd).await {
        Ok(resp) => sigil_to_http(resp, StatusCode::OK),
        Err(r) => r,
    }
}

#[derive(serde::Deserialize)]
struct ChangePasswordBody {
    entity_id: String,
    old_password: String,
    new_password: String,
}

async fn password_change<S: Store + 'static>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    Path(schema): Path<String>,
    Json(body): Json<ChangePasswordBody>,
) -> Response {
    let cmd = SigilCommand::PasswordChange {
        schema,
        user_id: body.entity_id,
        old_password: body.old_password,
        new_password: body.new_password,
    };
    match run_command(&state, &headers, cmd).await {
        Ok(resp) => sigil_to_http(resp, StatusCode::OK),
        Err(r) => r,
    }
}

#[derive(serde::Deserialize)]
struct ResetPasswordBody {
    entity_id: String,
    new_password: String,
}

async fn password_reset<S: Store + 'static>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    Path(schema): Path<String>,
    Json(body): Json<ResetPasswordBody>,
) -> Response {
    let cmd = SigilCommand::PasswordReset {
        schema,
        user_id: body.entity_id,
        new_password: body.new_password,
    };
    match run_command(&state, &headers, cmd).await {
        Ok(resp) => sigil_to_http(resp, StatusCode::OK),
        Err(r) => r,
    }
}

#[derive(serde::Deserialize)]
struct ImportPasswordBody {
    entity_id: String,
    hash: String,
}

async fn password_import<S: Store + 'static>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    Path(schema): Path<String>,
    Json(body): Json<ImportPasswordBody>,
) -> Response {
    let cmd = SigilCommand::PasswordImport {
        schema,
        user_id: body.entity_id,
        hash: body.hash,
        metadata: None,
    };
    match run_command(&state, &headers, cmd).await {
        Ok(resp) => sigil_to_http(resp, StatusCode::OK),
        Err(r) => r,
    }
}

async fn jwks<S: Store + 'static>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    Path(schema): Path<String>,
) -> Response {
    let cmd = SigilCommand::Jwks { schema };
    match run_command(&state, &headers, cmd).await {
        Ok(resp) => sigil_to_http(resp, StatusCode::OK),
        Err(r) => r,
    }
}

async fn health() -> Response {
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"}))).into_response()
}
