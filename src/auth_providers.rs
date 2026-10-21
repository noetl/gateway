//! Auth providers: sign-in by pluggable playbooks, sessions minted here.
//!
//! Off unless `GATEWAY_AUTH_PROVIDERS` is set. Each provider is a playbook
//! that proves who the caller is (an emailed one-time code, a Google or Apple
//! sign-in, …) and returns only a verified identity. The gateway turns that
//! into a session through the server (`POST /api/auth/provider-session`, with
//! `NOETL_AUTH_MINT_KEY`), caches it, and returns the token in this HTTP
//! response. A session token never appears in a playbook result, so never in
//! execution history.
//!
//! * `POST /api/auth/providers/{provider}/{action}`: public. Only configured
//!   providers and their declared actions (404 otherwise); a JSON object body
//!   of at most 4 KB (413). Rate-limited per client IP and, when the provider
//!   names a `key_field` (e.g. `email`), per value of that input field.
//! * The playbook runs with workload `{action, input, provider, client_ip,
//!   user_agent}`. Its result is read from the server's execution record (the
//!   `call.done` of `result_step`, default `result`), never from a callback a
//!   third party could post. Contract: `{status: "pending", message, data?}`,
//!   `{status: "denied", message}` or `{status: "authenticated", identity:
//!   {subject, email, email_verified, name?, picture?}}`; any other field is a
//!   contract violation (502, no session).
//! * Sessions belong to the provider's `app`. The user key is
//!   `ap:<provider>|<subject>`; `crate::authorization::Policy` maps it back to
//!   the app and allows only that app's `GATEWAY_APP_USER_PLAYBOOKS`.
//! * `POST /api/auth/logout` (generic, any session): ends the caller's session.
//!
//! Spec: noetl/ai-meta `specs/active/2026-10-21-gateway-auth-providers`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, HeaderName, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::AuthState;
use crate::guest::{client_ip, now_secs, too_many, Limiter};

const MAX_BODY: usize = 4096;
const MIN_KEY_BYTES: usize = 32;
const MAX_SESSION_HOURS: i64 = 24 * 90;
const POLL_MS: u64 = 250;

/// One provider, as configured in `GATEWAY_AUTH_PROVIDERS`.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProviderSpec {
    pub playbook: String,
    pub actions: Vec<String>,
    pub app: String,
    #[serde(default = "default_session_hours")]
    pub session_hours: i64,
    #[serde(default = "default_result_step")]
    pub result_step: String,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub limits: Limits,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Calls per client IP per rolling hour, all actions together.
    #[serde(default = "default_ip_per_hour")]
    pub ip_per_hour: usize,
    /// An input field to rate-limit by (e.g. `email`), case-insensitive.
    #[serde(default)]
    pub key_field: Option<String>,
    /// Calls per value of `key_field` per rolling hour.
    #[serde(default = "default_key_per_hour")]
    pub key_per_hour: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self { ip_per_hour: default_ip_per_hour(), key_field: None, key_per_hour: default_key_per_hour() }
    }
}

fn default_session_hours() -> i64 {
    24
}
fn default_result_step() -> String {
    "result".into()
}
fn default_timeout_secs() -> u64 {
    30
}
fn default_ip_per_hour() -> usize {
    30
}
fn default_key_per_hour() -> usize {
    10
}

/// Provider mode: the providers, the mint key and per-app playbook lists.
#[derive(Debug, Clone)]
pub struct ProvidersConfig {
    pub providers: HashMap<String, ProviderSpec>,
    pub mint_key: String,
    pub ip_header: Option<HeaderName>,
    /// `GATEWAY_APP_USER_PLAYBOOKS`: what each app's users may start.
    pub app_playbooks: HashMap<String, Vec<String>>,
}

fn name_ok(s: &str, max: usize) -> bool {
    let b = s.as_bytes();
    (2..=max).contains(&b.len())
        && b[0].is_ascii_alphanumeric()
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

fn action_ok(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=32).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

impl ProvidersConfig {
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> anyhow::Result<Option<Self>> {
        let Some(raw) = get("GATEWAY_AUTH_PROVIDERS").filter(|v| !v.trim().is_empty()) else {
            return Ok(None);
        };
        let providers: HashMap<String, ProviderSpec> = serde_json::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("GATEWAY_AUTH_PROVIDERS is not valid provider JSON: {e}"))?;
        if providers.is_empty() {
            return Ok(None);
        }
        for (name, p) in &providers {
            if !name_ok(name, 32) {
                anyhow::bail!("auth provider {name:?}: names are 2-32 chars of a-z, 0-9 and '-'");
            }
            if p.playbook.trim().is_empty() {
                anyhow::bail!("auth provider {name:?}: playbook is required");
            }
            if p.actions.is_empty() || !p.actions.iter().all(|a| action_ok(a)) {
                anyhow::bail!("auth provider {name:?}: actions must be 1-32 chars of a-z, 0-9 and '_'");
            }
            if !name_ok(&p.app, 64) {
                anyhow::bail!("auth provider {name:?}: app must be 2-64 chars of a-z, 0-9 and '-'");
            }
            if !(1..=MAX_SESSION_HOURS).contains(&p.session_hours) {
                anyhow::bail!("auth provider {name:?}: session_hours must be 1-{MAX_SESSION_HOURS}");
            }
            if !(1..=120).contains(&p.timeout_secs) || p.result_step.trim().is_empty() {
                anyhow::bail!("auth provider {name:?}: timeout_secs must be 1-120 and result_step non-empty");
            }
        }
        let mint_key = match get("NOETL_AUTH_MINT_KEY_FILE").filter(|v| !v.trim().is_empty()) {
            Some(path) => std::fs::read_to_string(path.trim())
                .map_err(|e| anyhow::anyhow!("NOETL_AUTH_MINT_KEY_FILE={path:?}: {e}"))?
                .trim()
                .to_string(),
            None => get("NOETL_AUTH_MINT_KEY").unwrap_or_default().trim().to_string(),
        };
        if mint_key.len() < MIN_KEY_BYTES {
            anyhow::bail!(
                "GATEWAY_AUTH_PROVIDERS is set but NOETL_AUTH_MINT_KEY (or _FILE) is missing or shorter than {MIN_KEY_BYTES} bytes"
            );
        }
        let app_playbooks: HashMap<String, Vec<String>> = match get("GATEWAY_APP_USER_PLAYBOOKS")
            .filter(|v| !v.trim().is_empty())
        {
            None => HashMap::new(),
            Some(v) => serde_json::from_str(&v)
                .map_err(|e| anyhow::anyhow!("GATEWAY_APP_USER_PLAYBOOKS must be JSON {{app: [playbook, ...]}}: {e}"))?,
        };
        let ip_header = match get("GATEWAY_CLIENT_IP_HEADER")
            .map(|v| v.trim().to_ascii_lowercase())
            .filter(|v| !v.is_empty())
        {
            None => None,
            Some(h) => Some(
                HeaderName::try_from(h.as_str()).map_err(|e| anyhow::anyhow!("GATEWAY_CLIENT_IP_HEADER={h:?}: {e}"))?,
            ),
        };
        Ok(Some(Self { providers, mint_key, ip_header, app_playbooks }))
    }

    /// Provider name → app, for `crate::authorization::Policy`.
    pub fn provider_apps(&self) -> HashMap<String, String> {
        self.providers.iter().map(|(n, p)| (n.clone(), p.app.clone())).collect()
    }
}

/// Which app a session belongs to, from its user key (`auth0_sub`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionApp {
    /// Not a provider user (Auth0, dev bypass): the global user allowlist.
    None,
    /// A provider user of a configured provider.
    App(String),
    /// `ap:<provider>|…` for a provider no longer configured: fail closed.
    Unknown,
}

pub fn session_app(auth0_sub: Option<&str>, provider_apps: &HashMap<String, String>) -> SessionApp {
    let Some(rest) = auth0_sub.and_then(|s| s.strip_prefix("ap:")) else {
        return SessionApp::None;
    };
    match rest.split_once('|').and_then(|(p, _)| provider_apps.get(p)) {
        Some(app) => SessionApp::App(app.clone()),
        None => SessionApp::Unknown,
    }
}

/// A provider playbook's result, checked against the contract.
#[derive(Debug, Clone, PartialEq)]
pub enum ProviderResult {
    Pending { message: String, data: Value },
    Denied { message: String },
    Authenticated { subject: String, email: String, email_verified: bool, name: Option<String> },
}

fn only_keys(v: &Value, allowed: &[&str]) -> Result<(), String> {
    let obj = v.as_object().ok_or("not an object")?;
    match obj.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(k) => Err(format!("unexpected field {k:?}")),
        None => Ok(()),
    }
}

fn str_field(v: &Value, k: &str, max: usize) -> Result<Option<String>, String> {
    match v.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.chars().count() <= max => Ok(Some(s.clone())),
        Some(_) => Err(format!("{k} must be a string of at most {max} chars")),
    }
}

/// Check a provider result. Anything outside the contract is refused, so a
/// playbook can't smuggle a credential or extra data through the gateway.
pub fn parse_result(v: &Value) -> Result<ProviderResult, String> {
    let status = v.get("status").and_then(Value::as_str).ok_or("missing status")?;
    match status {
        "pending" => {
            only_keys(v, &["status", "message", "data"])?;
            let data = v.get("data").cloned().unwrap_or_else(|| json!({}));
            if !data.is_object() || data.to_string().len() > 2048 {
                return Err("data must be an object of at most 2 KB".into());
            }
            Ok(ProviderResult::Pending { message: str_field(v, "message", 500)?.unwrap_or_default(), data })
        }
        "denied" => {
            only_keys(v, &["status", "message"])?;
            Ok(ProviderResult::Denied { message: str_field(v, "message", 500)?.unwrap_or_default() })
        }
        "authenticated" => {
            only_keys(v, &["status", "identity"])?;
            let id = v.get("identity").ok_or("missing identity")?;
            only_keys(id, &["subject", "email", "email_verified", "name", "picture"])?;
            let subject = str_field(id, "subject", 200)?.filter(|s| !s.trim().is_empty()).ok_or("missing subject")?;
            let email = str_field(id, "email", 255)?.filter(|s| s.contains('@')).ok_or("missing email")?;
            let email_verified = id.get("email_verified").and_then(Value::as_bool).unwrap_or(false);
            let name = str_field(id, "name", 200)?;
            let _ = str_field(id, "picture", 1000)?;
            Ok(ProviderResult::Authenticated { subject, email, email_verified, name })
        }
        other => Err(format!("unknown status {other:?}")),
    }
}

/// `call.done` result data of `step` in a server execution record.
fn step_result(exec: &Value, step: &str) -> Option<Value> {
    exec.get("events")?.as_array()?.iter().rev().find_map(|e| {
        (e.get("node_name").and_then(Value::as_str) == Some(step)
            && e.get("event_type").and_then(Value::as_str) == Some("call.done"))
        .then(|| e.pointer("/result/context/result/context/data").cloned())
        .flatten()
    })
}

fn terminal_failure(exec: &Value) -> bool {
    matches!(
        exec.get("status").and_then(Value::as_str).map(str::to_ascii_uppercase).as_deref(),
        Some("FAILED" | "ERROR" | "CANCELLED" | "CANCELED")
    )
}

pub struct ProviderState {
    pub config: ProvidersConfig,
    pub auth: Arc<AuthState>,
    limiter: Mutex<Limiter>,
}

impl ProviderState {
    pub fn new(config: ProvidersConfig, auth: Arc<AuthState>) -> Self {
        Self { config, auth, limiter: Mutex::new(Limiter::default()) }
    }

    fn admit(&self, keys: &[(String, usize)]) -> Result<(), u64> {
        self.limiter.lock().unwrap_or_else(|e| e.into_inner()).admit(keys, now_secs())
    }
}

fn reply(status: StatusCode, body: Value) -> Response {
    (status, Json(body)).into_response()
}

/// `POST /api/auth/providers/{provider}/{action}`.
pub async fn sign_in(
    State(st): State<Arc<ProviderState>>,
    Path((provider, action)): Path<(String, String)>,
    request: axum::extract::Request,
) -> Response {
    let Some(spec) = st.config.providers.get(&provider).cloned() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !spec.actions.contains(&action) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let peer = request.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0);
    let headers = request.headers().clone();
    let ip = client_ip(st.config.ip_header.as_ref(), &headers, peer);
    let user_agent: String = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .chars()
        .take(300)
        .collect();
    let body = match axum::body::to_bytes(request.into_body(), MAX_BODY).await {
        Ok(b) => b,
        Err(_) => return reply(StatusCode::PAYLOAD_TOO_LARGE, json!({ "error": "Request body too large" })),
    };
    let input: Value = if body.is_empty() {
        json!({})
    } else {
        match serde_json::from_slice::<Value>(&body) {
            Ok(v) if v.is_object() => v,
            _ => return reply(StatusCode::BAD_REQUEST, json!({ "error": "Body must be a JSON object" })),
        }
    };

    let mut keys = vec![(format!("auth:{provider}:ip:{ip}"), spec.limits.ip_per_hour)];
    if let Some(field) = &spec.limits.key_field {
        if let Some(v) = input.get(field).and_then(Value::as_str).map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()) {
            keys.push((format!("auth:{provider}:key:{v}"), spec.limits.key_per_hour));
        }
    }
    if let Err(wait) = st.admit(&keys) {
        return too_many(wait, "Too many sign-in attempts. Please try again later.");
    }

    let noetl = st.auth.noetl.clone();
    let workload = json!({
        "action": action,
        "input": input,
        "provider": provider,
        "client_ip": ip,
        "user_agent": user_agent,
    });
    let execution = match noetl.execute_playbook(&spec.playbook, workload).await {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(provider = %provider, error = %e, "auth provider playbook did not start");
            return reply(StatusCode::BAD_GATEWAY, json!({ "error": "Sign-in is unavailable right now" }));
        }
    };
    let execution_id = execution.execution_id.clone();

    // Read the result from the server's execution record: unforgeable,
    // unlike the public callback route.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(spec.timeout_secs);
    let raw = loop {
        if let Ok(exec) = noetl
            .api_call("GET", &format!("/api/executions/{execution_id}?page_size=200"), None)
            .await
        {
            if let Some(r) = step_result(&exec, &spec.result_step) {
                break Some(r);
            }
            if terminal_failure(&exec) {
                break None;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            let _ = noetl.cancel_execution(&execution_id, "auth provider timed out").await;
            break None;
        }
        tokio::time::sleep(Duration::from_millis(POLL_MS)).await;
    };
    let Some(raw) = raw else {
        tracing::warn!(provider = %provider, execution_id = %execution_id, "auth provider gave no result");
        return reply(StatusCode::BAD_GATEWAY, json!({ "error": "Sign-in is unavailable right now" }));
    };
    let result = match parse_result(&raw) {
        Ok(r) => r,
        Err(why) => {
            tracing::warn!(provider = %provider, execution_id = %execution_id, why = %why, "auth provider broke the result contract");
            return reply(StatusCode::BAD_GATEWAY, json!({ "error": "Sign-in is unavailable right now" }));
        }
    };

    match result {
        ProviderResult::Pending { message, data } => {
            reply(StatusCode::OK, json!({ "status": "pending", "message": message, "data": data }))
        }
        ProviderResult::Denied { message } => reply(StatusCode::UNAUTHORIZED, json!({ "status": "denied", "message": message })),
        ProviderResult::Authenticated { subject, email, email_verified, name } => {
            let body = json!({
                "provider": provider,
                "subject": subject,
                "email": email,
                "email_verified": email_verified,
                "name": name,
                "session_hours": spec.session_hours,
                "client_ip": ip,
                "user_agent": user_agent,
                "credential": st.auth.playbook_config.session_db_credential,
            });
            match noetl.mint_provider_session(&st.config.mint_key, body).await {
                Ok((status, output)) => match crate::auth::finish_login(&st.auth, &status, &output).await {
                    Ok(login) => (StatusCode::OK, Json(login)).into_response(),
                    Err(e) => e.into_response(),
                },
                Err(e) => {
                    tracing::warn!(provider = %provider, error = %e, "provider session mint failed");
                    reply(StatusCode::BAD_GATEWAY, json!({ "error": "Sign-in is unavailable right now" }))
                }
            }
        }
    }
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| headers.get("x-session-token").and_then(|v| v.to_str().ok()))
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string)
}

/// `POST /api/auth/logout`: end the caller's session (any kind). A guest
/// token has nothing to end; it just expires.
pub async fn logout(State(auth): State<Arc<AuthState>>, headers: HeaderMap) -> Response {
    let Some(token) = bearer(&headers) else {
        return reply(StatusCode::UNAUTHORIZED, json!({ "error": "No session" }));
    };
    if token.starts_with("ng1.") {
        return reply(StatusCode::OK, json!({ "status": "ok" }));
    }
    if let Err(e) = auth.noetl.logout(&token, &auth.playbook_config.session_db_credential).await {
        tracing::warn!(error = %e, "logout at the server failed");
        return reply(StatusCode::BAD_GATEWAY, json!({ "error": "Could not end the session" }));
    }
    if let Err(e) = auth.session_cache.invalidate(&token).await {
        tracing::warn!(error = %e, "logout: session cache invalidate failed");
    }
    reply(StatusCode::OK, json!({ "status": "ok" }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "0123456789abcdef0123456789abcdef";

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k| m.get(k).cloned()
    }

    const PROVIDERS: &str = r#"{"msr-email": {"playbook": "shastaranch/auth/email_code", "actions": ["start", "verify"], "app": "mountshastaranch", "session_hours": 720, "limits": {"key_field": "email", "key_per_hour": 5}}}"#;

    #[test]
    fn off_without_providers() {
        assert!(ProvidersConfig::from_lookup(env(&[])).unwrap().is_none());
        assert!(ProvidersConfig::from_lookup(env(&[("GATEWAY_AUTH_PROVIDERS", " ")])).unwrap().is_none());
    }

    #[test]
    fn parses_and_validates_providers() {
        let c = ProvidersConfig::from_lookup(env(&[
            ("GATEWAY_AUTH_PROVIDERS", PROVIDERS),
            ("NOETL_AUTH_MINT_KEY", KEY),
            ("GATEWAY_APP_USER_PLAYBOOKS", r#"{"mountshastaranch": ["shastaranch/concierge/turn"]}"#),
        ]))
        .unwrap()
        .unwrap();
        let p = &c.providers["msr-email"];
        assert_eq!(p.session_hours, 720);
        assert_eq!(p.result_step, "result");
        assert_eq!(p.limits.key_field.as_deref(), Some("email"));
        assert_eq!(p.limits.ip_per_hour, 30);
        assert_eq!(c.app_playbooks["mountshastaranch"], vec!["shastaranch/concierge/turn".to_string()]);
        assert_eq!(c.provider_apps()["msr-email"], "mountshastaranch");

        let bad = |providers: &str, key: &str| {
            ProvidersConfig::from_lookup(env(&[("GATEWAY_AUTH_PROVIDERS", providers), ("NOETL_AUTH_MINT_KEY", key)])).is_err()
        };
        assert!(bad(PROVIDERS, "short"), "a short mint key is a startup error");
        assert!(bad(r#"{"X": {"playbook": "p", "actions": ["start"], "app": "a1"}}"#, KEY));
        assert!(bad(r#"{"ok-name": {"playbook": "p", "actions": ["Start"], "app": "a1"}}"#, KEY));
        assert!(bad(r#"{"ok-name": {"playbook": "p", "actions": ["start"], "app": "a1", "session_hours": 9999}}"#, KEY));
        assert!(bad(r#"{"ok-name": {"playbook": "p", "actions": ["start"], "app": "a1", "typo": 1}}"#, KEY));
        assert!(bad("not json", KEY));
    }

    #[test]
    fn session_app_from_user_key() {
        let apps: HashMap<String, String> = [("msr-email".to_string(), "mountshastaranch".to_string())].into();
        assert_eq!(session_app(Some("google-oauth2|123"), &apps), SessionApp::None);
        assert_eq!(session_app(None, &apps), SessionApp::None);
        assert_eq!(session_app(Some("ap:msr-email|abc"), &apps), SessionApp::App("mountshastaranch".into()));
        assert_eq!(session_app(Some("ap:gone|abc"), &apps), SessionApp::Unknown);
        assert_eq!(session_app(Some("ap:no-bar"), &apps), SessionApp::Unknown);
    }

    #[test]
    fn result_contract() {
        assert_eq!(
            parse_result(&json!({"status": "pending", "message": "Code sent", "data": {"resend_in": 30}})).unwrap(),
            ProviderResult::Pending { message: "Code sent".into(), data: json!({"resend_in": 30}) }
        );
        assert_eq!(
            parse_result(&json!({"status": "denied", "message": "Wrong code"})).unwrap(),
            ProviderResult::Denied { message: "Wrong code".into() }
        );
        assert_eq!(
            parse_result(&json!({"status": "authenticated", "identity": {"subject": "s1", "email": "a@b.org", "email_verified": true, "name": "A"}})).unwrap(),
            ProviderResult::Authenticated { subject: "s1".into(), email: "a@b.org".into(), email_verified: true, name: Some("A".into()) }
        );
        // Anything outside the contract is refused.
        assert!(parse_result(&json!({"status": "authenticated", "identity": {"subject": "s"}, "session_token": "x"})).is_err());
        assert!(parse_result(&json!({"status": "authenticated", "identity": {"subject": "s", "email": "a@b.org", "token": "x"}})).is_err());
        assert!(parse_result(&json!({"status": "pending", "message": "m", "token": "x"})).is_err());
        assert!(parse_result(&json!({"status": "pending", "data": "not an object"})).is_err());
        assert!(parse_result(&json!({"status": "pending", "data": {"big": "x".repeat(3000)}})).is_err());
        assert!(parse_result(&json!({"status": "authenticated", "identity": {"subject": " ", "email": "a@b.org"}})).is_err());
        assert!(parse_result(&json!({"status": "authenticated", "identity": {"subject": "s", "email": "nope"}})).is_err());
        assert!(parse_result(&json!({"status": "ok"})).is_err());
        assert!(parse_result(&json!("authenticated")).is_err());
    }

    #[test]
    fn reads_the_result_step_from_the_execution_record() {
        let exec = json!({"status": "COMPLETED", "events": [
            {"node_name": "start", "event_type": "call.done", "result": {"context": {"result": {"context": {"data": {"x": 1}}}}}},
            {"node_name": "result", "event_type": "call.done", "result": {"context": {"result": {"context": {"data": {"status": "denied", "message": "m"}}}}}}
        ]});
        assert_eq!(step_result(&exec, "result").unwrap()["status"], "denied");
        assert!(step_result(&exec, "missing").is_none());
        assert!(!terminal_failure(&exec));
        assert!(terminal_failure(&json!({"status": "FAILED"})));
    }
}
