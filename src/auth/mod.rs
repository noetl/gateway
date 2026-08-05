pub mod middleware;
pub mod types;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::time::{timeout, Duration};

use crate::callbacks::CallbackManager;
use crate::config::AuthPlaybooksConfig;
use crate::noetl_client::{NoetlClient, ValidatedSession};
use crate::session_cache::SessionCache;

/// Combined state for auth handlers
#[derive(Clone)]
pub struct AuthState {
    pub noetl: Arc<NoetlClient>,
    pub callbacks: Arc<CallbackManager>,
    /// Configurable playbook paths for authentication
    pub playbook_config: AuthPlaybooksConfig,
    /// Session cache backed by NATS K/V
    pub session_cache: Arc<SessionCache>,
}

/// Authentication error responses
#[derive(Debug)]
pub enum AuthError {
    InvalidCredentials,
    InvalidCredentialsWithReason(String),
    InvalidSession,
    Unauthorized,
    AuthBackendUnavailable(String),
    NoetlError(String),
    InternalError(String),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()),
            AuthError::InvalidCredentialsWithReason(msg) => (StatusCode::UNAUTHORIZED, msg),
            AuthError::InvalidSession => (StatusCode::UNAUTHORIZED, "Invalid or expired session".to_string()),
            AuthError::Unauthorized => (StatusCode::FORBIDDEN, "Unauthorized access".to_string()),
            AuthError::AuthBackendUnavailable(msg) => (StatusCode::SERVICE_UNAVAILABLE, msg),
            AuthError::NoetlError(msg) => (StatusCode::BAD_GATEWAY, msg),
            AuthError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        (status, Json(serde_json::json!({"error": message}))).into_response()
    }
}

/// Login request body
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    /// Auth0 access token
    pub auth0_token: String,
    /// Auth0 refresh token (optional)
    pub auth0_refresh_token: Option<String>,
    /// Auth0 domain (e.g., "your-tenant.auth0.com") - optional, defaults to configured domain
    #[serde(default)]
    pub auth0_domain: Option<String>,
    /// Session duration in hours (default: 8)
    #[serde(default = "default_session_duration")]
    pub session_duration_hours: i32,
    /// Client IP address (optional - will use request IP if not provided)
    pub client_ip: Option<String>,
    /// Client user agent (optional - will use request header if not provided)
    pub client_user_agent: Option<String>,
}

fn default_session_duration() -> i32 {
    8
}

fn parse_roles(value: Option<&serde_json::Value>) -> Vec<String> {
    match value {
        Some(serde_json::Value::Array(items)) => {
            items.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()
        }
        Some(serde_json::Value::String(s)) => parse_roles_from_string(s),
        _ => Vec::new(),
    }
}

fn parse_roles_from_string(value: &str) -> Vec<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if let Ok(list) = serde_json::from_str::<Vec<String>>(trimmed) {
        return list;
    }
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        let inner = &trimmed[1..trimmed.len() - 1];
        if inner.trim().is_empty() {
            return Vec::new();
        }
        return inner
            .split(',')
            .map(|part| part.trim().trim_matches('"').to_string())
            .filter(|role| !role.is_empty())
            .collect();
    }
    vec![trimmed.to_string()]
}

fn callback_data_keys(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&str> = map.keys().map(std::string::String::as_str).collect();
            keys.sort_unstable();
            let preview: Vec<&str> = keys.into_iter().take(8).collect();
            if preview.is_empty() {
                "[]".to_string()
            } else {
                format!("[{}]", preview.join(","))
            }
        }
        _ => "[]".to_string(),
    }
}

fn extract_callback_error(value: &serde_json::Value) -> Option<String> {
    let message = value.get("message").and_then(|v| v.as_str()).unwrap_or("").trim();
    let error = value.get("error").and_then(|v| v.as_str()).unwrap_or("").trim();

    match (message.is_empty(), error.is_empty()) {
        (true, true) => None,
        (false, true) => Some(message.to_string()),
        (true, false) => Some(error.to_string()),
        (false, false) => Some(format!("{}: {}", message, error)),
    }
}

fn cancel_pending_callback(callbacks: Arc<CallbackManager>, request_id: String) {
    tokio::spawn(async move { callbacks.cancel(&request_id).await });
}

fn cancel_auth_execution(noetl: Arc<NoetlClient>, execution_id: String, reason: String) {
    tokio::spawn(async move {
        if let Err(error) = noetl.cancel_execution(&execution_id, &reason).await {
            crate::ingress::record_auth_cancel_failed();
            tracing::warn!(
                "Failed to cancel auth execution {} after gateway timeout: {}",
                execution_id,
                error
            );
        }
    });
}

fn auth_backend_timeout(operation: &str, timeout_secs: u64) -> AuthError {
    AuthError::AuthBackendUnavailable(format!(
        "{} auth playbook did not complete within {}s; auth backend is busy. Please retry.",
        operation, timeout_secs
    ))
}

/// Whether cache-missed sessions are validated by executing the
/// ``auth0_validate_session`` playbook (default) instead of the legacy
/// ``POST /api/auth/session/validate`` REST call.
///
/// The legacy REST route only existed on the retired Python server; the Rust
/// control plane has no ``/api/auth`` routes, so the REST path 404s in
/// production.  The playbook path mirrors the live ``check_access`` flow
/// (execute a catalog playbook, receive ``{valid, user, expires_at}`` via the
/// worker NATS callback).  Set ``GATEWAY_SESSION_VALIDATE_VIA_PLAYBOOK=false``
/// to fall back to the legacy REST path.
fn session_validate_via_playbook_enabled() -> bool {
    std::env::var("GATEWAY_SESSION_VALIDATE_VIA_PLAYBOOK")
        .map(|v| !(v == "false" || v == "0"))
        .unwrap_or(true)
}

/// Whether the synchronous in-process auth fast-path (noetl/ai-meta#167) is
/// enabled.
///
/// The recurring Muno login lockout (`Gateway auth request timed out after
/// 15s`) has one structural cause: `auth0_login` / `auth0_validate_session` run
/// as a **multi-hop off-server orchestration drive** on the system worker pool,
/// where each hop can fall to the server's ~8s reconcile tick under load
/// (noetl/ai-meta#130 / #156).  Two slow hops blow the gateway's hard ~15s auth
/// deadline even though the drive completes ~24-38s later.  Session validation,
/// though, is a plain session-store lookup that never needed to run as a
/// deadline-gated distributed workflow.
///
/// When this flag is `true`, the gateway validates sessions (and logs in) by
/// calling the server's synchronous `/api/auth/*` endpoints — a direct auth-DB
/// lookup that returns in milliseconds regardless of the drive state, so a
/// wedged/paused system-pool (NATS bounce, OOM, index churn) can no longer lock
/// users out.  The validation *decisions* are identical to the playbook path
/// (same SQL, same token/expiry checks); only the execution shape changes.
///
/// Default OFF — today's playbook-drive behaviour, so flipping the flag is the
/// whole rollout and reverting it is the whole rollback.  Takes precedence over
/// [`session_validate_via_playbook_enabled`] for the validate path.
fn auth_sync_enabled() -> bool {
    std::env::var("NOETL_AUTH_SYNC")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}

/// Whether the synchronous in-process **authorization** gate (noetl/ai-meta#168)
/// is enabled.
///
/// The per-turn access gate (`check_playbook_access`) has the same structural
/// fragility login had: it authorizes the user for the target playbook before
/// the planner runs, and today it executes as a multi-hop off-server drive
/// (~7s under load).  Stacked in front of the planner turn it blows the
/// SPA/gateway request budget and the turn is dropped before the planner
/// execution is even created → the SPA shows "Load failed" with no execution.
/// The authorization decision, though, is a plain auth-DB lookup (session row +
/// role/grant rows) that never needed a deadline-gated distributed workflow.
///
/// This is a **sibling** of [`auth_sync_enabled`] rather than the same flag on
/// purpose: login/validate sync (`NOETL_AUTH_SYNC`) is already live in prod, so
/// a shared flag would activate authz-sync the instant the new image rolls,
/// forfeiting the gated "deploy neutral → verify → flip" rollout and
/// independent rollback.  With its own flag the authz gate ships inert
/// (byte-identical to today's drive path), is flipped on independently, and
/// rolls back with `NOETL_AUTHZ_SYNC=false` without disturbing login.  Default
/// OFF.
fn authz_sync_enabled() -> bool {
    std::env::var("NOETL_AUTHZ_SYNC")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}

/// Validate a session token by executing the configured ``validate_session``
/// playbook through the worker pool and consuming the ``{valid, user,
/// expires_at}`` callback.  Mirrors [`check_access`]'s execute-playbook-via-NATS
/// callback mechanism.
async fn validate_session_via_playbook(
    state: &AuthState,
    session_token: &str,
) -> Result<Option<ValidatedSession>, AuthError> {
    // Register callback to receive result via NATS
    let (request_id, nats_subject, rx) = state.callbacks.register().await;

    let variables = serde_json::json!({
        "session_token": session_token,
        "db_credential": state.playbook_config.session_db_credential,
        "callback_subject": nats_subject,
        "request_id": request_id.clone(),
    });

    let playbook_path = &state.playbook_config.validate_session;
    tracing::debug!("Using validate_session playbook: {}", playbook_path);
    let timeout_secs = state.playbook_config.timeout_secs;

    let result = timeout(
        Duration::from_secs(timeout_secs),
        state.noetl.execute_playbook(playbook_path, variables),
    )
    .await
    .map_err(|_| {
        cancel_pending_callback(state.callbacks.clone(), request_id.clone());
        auth_backend_timeout("Validate session", timeout_secs)
    })?
    .map_err(|e| {
        cancel_pending_callback(state.callbacks.clone(), request_id.clone());
        AuthError::NoetlError(format!("Validate session playbook failed: {}", e))
    })?;

    tracing::info!(
        "Auth validate_session execution_id: {}, request_id: {}",
        result.execution_id,
        request_id
    );

    // Wait for callback with configurable timeout
    let execution_id = result.execution_id.clone();
    let callback_result = timeout(Duration::from_secs(timeout_secs), rx)
        .await
        .map_err(|_| {
            cancel_pending_callback(state.callbacks.clone(), request_id.clone());
            cancel_auth_execution(
                state.noetl.clone(),
                execution_id.clone(),
                format!("Gateway validate_session timed out after {}s", timeout_secs),
            );
            auth_backend_timeout("Validate session", timeout_secs)
        })?
        .map_err(|_| AuthError::InternalError("Callback channel closed".to_string()))?;

    let output = callback_result.data;

    // A non-success callback status means the playbook itself errored (e.g. DB
    // lookup failure).  Treat as "could not validate" rather than "invalid".
    if callback_result.status != "success" {
        let reason = extract_callback_error(&output)
            .unwrap_or_else(|| format!("validate_session callback status: {}", callback_result.status));
        tracing::warn!(
            "Validate session playbook returned non-success for request_id={}: {}",
            request_id,
            reason
        );
        return Ok(None);
    }

    let valid = output.get("valid").and_then(|v| v.as_bool()).unwrap_or(false);
    if !valid {
        return Ok(None);
    }

    let user_obj = match output.get("user") {
        Some(u) => u,
        None => {
            tracing::warn!("validate_session callback valid=true but missing user payload");
            return Ok(None);
        }
    };

    // user_id may arrive as a number or a stringified number (Jinja templates).
    let user_id = user_obj
        .get("user_id")
        .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok())))
        .unwrap_or(0) as i32;
    let email = user_obj
        .get("email")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let display_name = user_obj
        .get("display_name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| email.clone());
    let roles = parse_roles(user_obj.get("roles"));

    let expires_at = output
        .get("expires_at")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    Ok(Some(ValidatedSession {
        user_id,
        email,
        display_name,
        expires_at,
        roles,
    }))
}

pub async fn resolve_session_cache_or_db(
    state: &AuthState,
    session_token: &str,
) -> Result<Option<crate::session_cache::CachedSession>, AuthError> {
    if let Some(cached) = state.session_cache.get(session_token).await {
        return Ok(Some(cached));
    }

    let validated = if auth_sync_enabled() {
        // noetl/ai-meta#167: synchronous in-process validation via the server
        // auth fast-path — a direct auth-DB lookup, immune to the off-server
        // drive's per-hop reconcile floor and drive-wedge class.  Same
        // valid/invalid decisions as the playbook, just not deadline-gated.
        let db_credential = &state.playbook_config.session_db_credential;
        tracing::debug!(
            "Session cache miss, validating via sync auth fast-path (credential={})",
            db_credential
        );
        state
            .noetl
            .validate_session_via_api(session_token, db_credential)
            .await
            .map_err(|e| AuthError::NoetlError(format!("Session validation (sync) failed: {}", e)))?
    } else if session_validate_via_playbook_enabled() {
        tracing::debug!(
            "Session cache miss, validating via auth playbook ({})",
            state.playbook_config.validate_session
        );
        validate_session_via_playbook(state, session_token).await?
    } else {
        let db_credential = &state.playbook_config.session_db_credential;
        tracing::debug!(
            "Session cache miss, validating via legacy auth API (credential={})",
            db_credential
        );
        state
            .noetl
            .validate_session_via_api(session_token, db_credential)
            .await
            .map_err(|e| AuthError::NoetlError(format!("Session validation API failed: {}", e)))?
    };

    match validated {
        Some(found) => {
            let cached = crate::session_cache::CachedSession {
                session_token: session_token.to_string(),
                user_id: found.user_id,
                email: found.email,
                display_name: found.display_name,
                expires_at: found.expires_at,
                is_active: true,
                roles: found.roles,
            };

            if let Err(e) = state.session_cache.put(&cached).await {
                crate::ingress::record_session_cache_failed("after_api_validate");
                tracing::warn!("Failed to cache API-validated session: {}", e);
            }

            Ok(Some(cached))
        }
        None => {
            let _ = state.session_cache.invalidate(session_token).await;
            Ok(None)
        }
    }
}

/// Login response
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub status: String,
    pub session_token: String,
    pub user: UserInfo,
    pub expires_at: String,
    pub message: String,
}

/// User information
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserInfo {
    pub user_id: i32,
    pub email: String,
    pub display_name: String,
    #[serde(default)]
    pub roles: Vec<String>,
}

/// Session validation request
#[derive(Debug, Deserialize)]
pub struct ValidateSessionRequest {
    pub session_token: String,
}

/// Session validation response
#[derive(Debug, Serialize)]
pub struct ValidateSessionResponse {
    pub valid: bool,
    pub user: Option<UserInfo>,
    pub expires_at: Option<String>,
    pub message: String,
}

/// Check playbook access request
#[derive(Debug, Deserialize)]
pub struct CheckAccessRequest {
    pub session_token: String,
    pub playbook_path: String,
    pub permission_type: String, // "execute", "view", "edit"
}

/// Check access response
#[derive(Debug, Serialize)]
pub struct CheckAccessResponse {
    pub allowed: bool,
    pub user: Option<UserInfo>,
    pub playbook_path: String,
    pub permission_type: String,
    pub message: String,
}

/// Login endpoint - authenticates user via Auth0 and creates session
pub async fn login(
    State(state): State<Arc<AuthState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AuthError> {
    // Use provided domain or fall back to default
    let auth0_domain = req
        .auth0_domain
        .unwrap_or_else(|| "mestumre-development.us.auth0.com".to_string());
    tracing::info!("Auth login request for domain: {}", auth0_domain);

    // noetl/ai-meta#167 synchronous fast-path: authenticate in-process via the
    // server's `/api/auth/login` (JWT-claims decode + the same session-creation
    // SQL the playbook runs) instead of dispatching the multi-hop off-server
    // drive that the hard ~15s auth deadline could outrun under load.  Same
    // authenticated/rejected decisions; only the execution shape changes.
    if auth_sync_enabled() {
        let client_ip = req.client_ip.unwrap_or_else(|| "0.0.0.0".to_string());
        let credential = state.playbook_config.session_db_credential.clone();
        let (callback_status, output) = state
            .noetl
            .login_via_api(&req.auth0_token, &auth0_domain, &client_ip, &credential)
            .await
            .map_err(|e| AuthError::NoetlError(format!("Login (sync) failed: {}", e)))?;
        return finish_login(state.as_ref(), &callback_status, &output)
            .await
            .map(Json);
    }

    // Register callback to receive result via NATS
    let (request_id, nats_subject, rx) = state.callbacks.register().await;
    tracing::debug!(
        "Registered callback request_id={}, subject={}",
        request_id,
        nats_subject
    );

    // Call NoETL auth0_login playbook with callback info
    // The gateway tool abstracts NATS - playbooks just see callback_subject
    let variables = serde_json::json!({
        "auth0_token": req.auth0_token,
        "auth0_refresh_token": req.auth0_refresh_token.unwrap_or_default(),
        "auth0_domain": auth0_domain,
        "session_duration_hours": req.session_duration_hours,
        "client_ip": req.client_ip.unwrap_or_else(|| "0.0.0.0".to_string()),
        "client_user_agent": req.client_user_agent.unwrap_or_else(|| "unknown".to_string()),
        "callback_subject": nats_subject,
        "request_id": request_id.clone(),
    });

    let playbook_path = &state.playbook_config.login;
    tracing::debug!("Using login playbook: {}", playbook_path);
    let timeout_secs = state.playbook_config.timeout_secs;

    let result = timeout(
        Duration::from_secs(timeout_secs),
        state.noetl.execute_playbook(playbook_path, variables),
    )
    .await
    .map_err(|_| {
        cancel_pending_callback(state.callbacks.clone(), request_id.clone());
        auth_backend_timeout("Login", timeout_secs)
    })?
    .map_err(|e| {
        cancel_pending_callback(state.callbacks.clone(), request_id.clone());
        AuthError::NoetlError(format!("Login playbook failed: {}", e))
    })?;

    tracing::info!(
        "Auth login execution_id: {}, request_id: {}",
        result.execution_id,
        request_id
    );

    // Wait for callback with configurable timeout
    let execution_id = result.execution_id.clone();
    let callback_result = timeout(Duration::from_secs(timeout_secs), rx)
        .await
        .map_err(|_| {
            cancel_pending_callback(state.callbacks.clone(), request_id.clone());
            cancel_auth_execution(
                state.noetl.clone(),
                execution_id.clone(),
                format!("Gateway login timed out after {}s", timeout_secs),
            );
            auth_backend_timeout("Login", timeout_secs)
        })?
        .map_err(|_| AuthError::InternalError("Callback channel closed".to_string()))?;

    tracing::info!(
        "Received callback for request_id={}, status={}, data_keys={}",
        request_id,
        callback_result.status,
        callback_data_keys(&callback_result.data)
    );

    // Both the drive-callback path (here) and the #167 sync path share the same
    // output → LoginResponse parsing + session-caching tail.
    finish_login(state.as_ref(), &callback_result.status, &callback_result.data)
        .await
        .map(Json)
}

/// Turn an auth-login result envelope (`callback_status` + `output` payload)
/// into a [`LoginResponse`], caching the session on success.
///
/// The envelope shape is identical whether it arrived as the `auth0_login`
/// playbook's `/api/internal/callback` body (drive path) or the server's
/// synchronous `/api/auth/login` response (noetl/ai-meta#167 fast-path):
/// `callback_status == "success"` with `output.status == "authenticated"` on a
/// good login, otherwise an error envelope whose reason is surfaced as
/// `InvalidCredentialsWithReason`.  Keeping one implementation guarantees the
/// two paths make byte-identical auth decisions.
async fn finish_login(
    state: &AuthState,
    callback_status: &str,
    output: &serde_json::Value,
) -> Result<LoginResponse, AuthError> {
    if callback_status != "success" {
        let reason = extract_callback_error(output).unwrap_or_else(|| "Invalid credentials".to_string());
        crate::ingress::record_login("callback_failed");
        tracing::warn!(
            "Auth login failed status={} reason={}",
            callback_status,
            reason
        );
        return Err(AuthError::InvalidCredentialsWithReason(reason));
    }

    let status_str = output
        .get("status")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::InternalError("Login callback missing status field".to_string()))?;

    if status_str != "authenticated" {
        let reason =
            extract_callback_error(output).unwrap_or_else(|| format!("Authentication status: {}", status_str));
        crate::ingress::record_login("not_authenticated");
        tracing::warn!("Auth login rejected status={} reason={}", status_str, reason);
        return Err(AuthError::InvalidCredentialsWithReason(reason));
    }

    let session_token = output
        .get("session_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::InternalError("No session token returned".to_string()))?
        .to_string();

    let user_obj = output
        .get("user")
        .ok_or_else(|| AuthError::InternalError("No user data returned".to_string()))?;

    let email = user_obj
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::InternalError("Invalid email".to_string()))?
        .to_string();
    let roles = parse_roles(user_obj.get("roles"));

    // user_id can be either a number or string (from Jinja2 templates)
    let user_id = user_obj
        .get("user_id")
        .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok())))
        .ok_or_else(|| AuthError::InternalError("Invalid user_id".to_string()))? as i32;

    let user = UserInfo {
        user_id,
        email: email.clone(),
        // Use display_name if present, otherwise fall back to email
        display_name: user_obj
            .get("display_name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| email.clone()),
        roles,
    };

    let expires_at = output
        .get("expires_at")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::InternalError("Invalid expires_at".to_string()))?
        .to_string();

    tracing::info!("Auth login successful for user: {}", user.email);

    // Cache the session for fast validation on subsequent requests
    let cached_session = crate::session_cache::CachedSession {
        session_token: session_token.clone(),
        user_id: user.user_id,
        email: user.email.clone(),
        display_name: user.display_name.clone(),
        expires_at: expires_at.clone(),
        is_active: true,
        roles: user.roles.clone(),
    };
    if let Err(e) = state.session_cache.put(&cached_session).await {
        crate::ingress::record_session_cache_failed("after_login");
        tracing::warn!("Failed to cache session after login: {}", e);
    }

    crate::ingress::record_login("succeeded");
    Ok(LoginResponse {
        status: "authenticated".to_string(),
        session_token,
        user,
        expires_at,
        message: "Authentication successful".to_string(),
    })
}

/// Validate session endpoint - checks if session token is valid.
/// Uses cache-first strategy: checks NATS K/V first, then NoETL Postgres API.
pub async fn validate_session(
    State(state): State<Arc<AuthState>>,
    Json(req): Json<ValidateSessionRequest>,
) -> Result<Json<ValidateSessionResponse>, AuthError> {
    tracing::info!("Auth validate_session request");
    let session = resolve_session_cache_or_db(state.as_ref(), &req.session_token).await?;

    if let Some(cached) = session {
        return Ok(Json(ValidateSessionResponse {
            valid: true,
            user: Some(UserInfo {
                user_id: cached.user_id,
                email: cached.email,
                display_name: cached.display_name,
                roles: cached.roles,
            }),
            expires_at: Some(cached.expires_at),
            message: "Session is valid".to_string(),
        }));
    }

    Ok(Json(ValidateSessionResponse {
        valid: false,
        user: None,
        expires_at: None,
        message: "Session is invalid or expired".to_string(),
    }))
}

/// Check playbook access endpoint - verifies user has permission for playbook
pub async fn check_access(
    State(state): State<Arc<AuthState>>,
    Json(req): Json<CheckAccessRequest>,
) -> Result<Json<CheckAccessResponse>, AuthError> {
    tracing::info!(
        "Auth check_access request for playbook: {} permission: {}",
        req.playbook_path,
        req.permission_type
    );

    // noetl/ai-meta#168 synchronous authz fast-path: authorize in-process via
    // the server's `/api/auth/check-playbook-access` (the byte-identical session
    // + role/grant lookup the `check_playbook_access` playbook runs) instead of
    // dispatching the multi-hop off-server drive.  The pre-turn gate runs on
    // every Muno turn; when the drive is slow (~7s in the incident) it stacks in
    // front of the planner turn, blows the request budget, and the turn is
    // dropped before the planner execution is created → the SPA shows "Load
    // failed".  Same grant/deny decision; only the execution shape changes, so a
    // wedged/paused system-pool can no longer drop the turn.  A DB lookup error
    // returns `status != "success"` → we fail **closed** (retryable backend
    // error, never a false grant).  Gated by its own NOETL_AUTHZ_SYNC flag
    // (sibling of NOETL_AUTH_SYNC) so it ships inert and is flipped on / rolled
    // back independently of the already-live login sync path.
    if authz_sync_enabled() {
        let credential = state.playbook_config.session_db_credential.clone();
        let (status, output) = state
            .noetl
            .check_access_via_api(
                &req.session_token,
                &req.playbook_path,
                &req.permission_type,
                &credential,
            )
            .await
            .map_err(|e| AuthError::NoetlError(format!("Check access (sync) failed: {}", e)))?;
        if status != "success" {
            let reason = extract_callback_error(&output)
                .unwrap_or_else(|| "Access check backend unavailable".to_string());
            tracing::warn!("Sync check_access backend error: {}", reason);
            return Err(AuthError::AuthBackendUnavailable(reason));
        }
        return Ok(Json(finish_check_access(
            req.playbook_path,
            req.permission_type,
            &output,
        )));
    }

    // Register callback to receive result via NATS
    let (request_id, nats_subject, rx) = state.callbacks.register().await;

    // Call NoETL check_playbook_access playbook with callback info
    // The gateway tool abstracts NATS - playbooks just see callback_subject
    // Note: playbook expects "action" not "permission_type"
    let variables = serde_json::json!({
        "session_token": req.session_token,
        "playbook_path": req.playbook_path,
        "action": req.permission_type,
        "callback_subject": nats_subject,
        "request_id": request_id.clone(),
    });

    let playbook_path = &state.playbook_config.check_access;
    tracing::debug!("Using check_access playbook: {}", playbook_path);
    let timeout_secs = state.playbook_config.timeout_secs;

    let result = timeout(
        Duration::from_secs(timeout_secs),
        state.noetl.execute_playbook(playbook_path, variables),
    )
    .await
    .map_err(|_| {
        cancel_pending_callback(state.callbacks.clone(), request_id.clone());
        auth_backend_timeout("Check access", timeout_secs)
    })?
    .map_err(|e| {
        cancel_pending_callback(state.callbacks.clone(), request_id.clone());
        AuthError::NoetlError(format!("Check access playbook failed: {}", e))
    })?;

    tracing::info!(
        "Auth check_access execution_id: {}, request_id: {}",
        result.execution_id,
        request_id
    );

    // Wait for callback with configurable timeout
    let execution_id = result.execution_id.clone();
    let callback_result = timeout(Duration::from_secs(timeout_secs), rx)
        .await
        .map_err(|_| {
            cancel_pending_callback(state.callbacks.clone(), request_id.clone());
            cancel_auth_execution(
                state.noetl.clone(),
                execution_id.clone(),
                format!("Gateway check_access timed out after {}s", timeout_secs),
            );
            auth_backend_timeout("Check access", timeout_secs)
        })?
        .map_err(|_| AuthError::InternalError("Callback channel closed".to_string()))?;

    // Both the drive-callback path (here) and the #168 sync path share the same
    // `{allowed, user, message}` output → CheckAccessResponse parsing.  Keeping
    // one implementation guarantees the two paths make byte-identical
    // authorization decisions.
    Ok(Json(finish_check_access(
        req.playbook_path,
        req.permission_type,
        &callback_result.data,
    )))
}

/// Turn an access-check result envelope (`output` = `{allowed, user?, message}`)
/// into a [`CheckAccessResponse`].
///
/// The `output` shape is identical whether it arrived as the
/// `check_playbook_access` playbook's `/api/internal/callback` body (drive path)
/// or the server's synchronous `/api/auth/check-playbook-access` response
/// (noetl/ai-meta#168 fast-path): `allowed` is the grant decision, `user` is the
/// granted user object (absent on deny), and `message` is the human-readable
/// reason.  `allowed` defaults to `false` — a malformed or missing decision
/// fails **closed** (no access granted).
fn finish_check_access(
    playbook_path: String,
    permission_type: String,
    output: &serde_json::Value,
) -> CheckAccessResponse {
    let allowed = output.get("allowed").and_then(|v| v.as_bool()).unwrap_or(false);

    let user = output.get("user").map(|u| UserInfo {
        user_id: u.get("user_id").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
        email: u.get("email").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
        display_name: u
            .get("display_name")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown User")
            .to_string(),
        roles: parse_roles(u.get("roles")),
    });

    let message = output
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("Access check completed")
        .to_string();

    tracing::info!("Auth check_access allowed: {}", allowed);

    CheckAccessResponse {
        allowed,
        user,
        playbook_path,
        permission_type,
        message,
    }
}

/// Internal callback request body - matches CallbackResult structure
#[derive(Debug, Deserialize)]
pub struct InternalCallbackRequest {
    pub request_id: String,
    #[serde(default)]
    pub execution_id: Option<String>,
    #[serde(default)]
    pub step: Option<String>,
    #[serde(default = "default_callback_status")]
    pub status: String,
    #[serde(default)]
    pub data: serde_json::Value,
}

fn default_callback_status() -> String {
    "success".to_string()
}

/// Internal callback response
#[derive(Debug, Serialize)]
pub struct InternalCallbackResponse {
    pub delivered: bool,
    pub message: String,
}

/// Internal callback endpoint - allows workers to deliver results via HTTP
/// This is an alternative to NATS-based callbacks for simpler deployments.
///
/// Endpoint: POST /api/internal/callback
///
/// Workers can call this using the standard http tool:
/// ```yaml
/// - sink:
///     tool:
///       kind: http
///       method: POST
///       url: "http://gateway:8090/api/internal/callback"
///       headers:
///         Content-Type: application/json
///       body:
///         request_id: "{{ request_id }}"
///         status: "{{ result.status }}"
///         data:
///           session_token: "{{ result.session_token }}"
///           user: ...
/// ```
pub async fn internal_callback(
    State(state): State<Arc<AuthState>>,
    Json(req): Json<InternalCallbackRequest>,
) -> Json<InternalCallbackResponse> {
    tracing::info!(
        "Internal callback received: request_id={}, status={}, step={:?}, data_keys={}",
        req.request_id,
        req.status,
        req.step,
        callback_data_keys(&req.data)
    );

    // Convert to CallbackResult and deliver
    let callback_result = crate::callbacks::CallbackResult {
        request_id: req.request_id.clone(),
        execution_id: req.execution_id,
        step: req.step,
        status: req.status,
        data: req.data,
    };

    let delivered = state.callbacks.deliver(callback_result).await;

    if delivered {
        tracing::info!("Callback delivered for request_id={}", req.request_id);
        Json(InternalCallbackResponse {
            delivered: true,
            message: "Callback delivered successfully".to_string(),
        })
    } else {
        tracing::warn!("No pending request for callback request_id={}", req.request_id);
        Json(InternalCallbackResponse {
            delivered: false,
            message: "No pending request found for this request_id".to_string(),
        })
    }
}
