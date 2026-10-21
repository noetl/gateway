//! End to end for auth providers (`crate::auth_providers`): the public route
//! against a mock NoETL that runs a scripted provider playbook, serves its
//! execution record and mints sessions. Proves the route surface (404, 413,
//! 400), the result contract (pending, denied, a smuggled field), that the
//! session is minted by the server with the gateway's key and never comes from
//! the playbook, rate limits, logout, and per-app authorization.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};

use crate::auth::types::UserContext;
use crate::auth::AuthState;
use crate::auth_providers::{ProviderState, ProvidersConfig};
use crate::authorization::Policy;
use crate::callbacks::CallbackManager;
use crate::noetl_client::NoetlClient;
use crate::session_cache::SessionCache;

const MINT_KEY: &str = "0123456789abcdef0123456789abcdef";
const APP_PLAYBOOK: &str = "site/concierge/turn";

/// A mint request: the `X-NoETL-Auth-Mint` key and the body.
type MintCall = (Option<String>, Value);

#[derive(Clone, Default)]
struct Mock {
    /// `METHOD path` of every request.
    seen: Arc<Mutex<Vec<String>>>,
    /// Workloads sent to /api/execute, by execution id.
    runs: Arc<Mutex<Vec<(u64, Value)>>>,
    /// Bodies and keys sent to /api/auth/provider-session.
    mints: Arc<Mutex<Vec<MintCall>>>,
    next_id: Arc<AtomicU64>,
}

/// The scripted provider playbook: its `result` step data, chosen by
/// `input.script`.
fn scripted_result(input: &Value) -> Option<Value> {
    Some(match input.get("script").and_then(Value::as_str)? {
        "pending" => json!({"status": "pending", "message": "We emailed a code", "data": {"resend_in": 30}}),
        "denied" => json!({"status": "denied", "message": "Wrong code"}),
        "smuggle" => json!({"status": "authenticated", "identity": {"subject": "s1", "email": "g@example.org", "email_verified": true}, "session_token": "stolen"}),
        "ok" => json!({"status": "authenticated", "identity": {"subject": "s1", "email": "g@example.org", "email_verified": true, "name": "Guest"}}),
        "fail" => return None,
        _ => return None,
    })
}

async fn mock_noetl() -> (String, Mock) {
    let mock = Mock { next_id: Arc::new(AtomicU64::new(7000)), ..Mock::default() };

    async fn execute(State(m): State<Mock>, Json(body): Json<Value>) -> Json<Value> {
        m.seen.lock().unwrap().push("POST /api/execute".into());
        let id = m.next_id.fetch_add(1, Ordering::SeqCst);
        // The workload is somewhere in the request (`args`/`workload`).
        let workload = body.get("args").or_else(|| body.get("workload")).cloned().unwrap_or(body);
        m.runs.lock().unwrap().push((id, workload));
        Json(json!({"execution_id": id.to_string(), "status": "started", "name": "x"}))
    }
    async fn execution(State(m): State<Mock>, Path(id): Path<String>) -> Json<Value> {
        m.seen.lock().unwrap().push(format!("GET /api/executions/{id}"));
        let id: u64 = id.parse().unwrap_or(0);
        let workload = m.runs.lock().unwrap().iter().find(|(i, _)| *i == id).map(|(_, w)| w.clone());
        let result = workload.as_ref().and_then(|w| scripted_result(&w["input"]));
        match result {
            Some(data) => Json(json!({"status": "COMPLETED", "events": [
                {"node_name": "result", "event_type": "call.done",
                 "result": {"context": {"result": {"context": {"data": data}}}}}
            ]})),
            None => Json(json!({"status": "FAILED", "events": []})),
        }
    }
    async fn mint(State(m): State<Mock>, headers: HeaderMap, Json(body): Json<Value>) -> Json<Value> {
        m.seen.lock().unwrap().push("POST /api/auth/provider-session".into());
        let key = headers.get("x-noetl-auth-mint").and_then(|v| v.to_str().ok()).map(str::to_string);
        m.mints.lock().unwrap().push((key, body.clone()));
        Json(json!({"status": "success", "data": {
            "status": "authenticated",
            "session_token": "minted-by-server",
            "expires_at": "2026-11-20 00:00:00+00",
            "user": {"user_id": 42, "email": body["email"], "display_name": body["name"], "roles": [],
                     "auth0_id": format!("ap:{}|{}", body["provider"].as_str().unwrap(), body["subject"].as_str().unwrap())}
        }}))
    }
    async fn logout(State(m): State<Mock>, Json(body): Json<Value>) -> Json<Value> {
        m.seen.lock().unwrap().push(format!("POST /api/auth/logout {}", body["session_token"].as_str().unwrap_or("")));
        Json(json!({"status": "ok", "revoked": true}))
    }
    async fn cancel(State(m): State<Mock>, Path(id): Path<String>) -> Json<Value> {
        m.seen.lock().unwrap().push(format!("POST /api/executions/{id}/cancel"));
        Json(json!({"ok": true}))
    }

    let app = Router::new()
        .route("/api/execute", post(execute))
        .route("/api/executions/{id}", get(execution))
        .route("/api/executions/{id}/cancel", post(cancel))
        .route("/api/auth/provider-session", post(mint))
        .route("/api/auth/logout", post(logout))
        .with_state(mock.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), mock)
}

fn providers_config(key_per_hour: usize) -> ProvidersConfig {
    let providers = format!(
        r#"{{"msr-email": {{"playbook": "site/auth/email_code", "actions": ["start", "verify"], "app": "site-app",
            "session_hours": 720, "timeout_secs": 3, "limits": {{"key_field": "email", "key_per_hour": {key_per_hour}}}}}}}"#
    );
    let env = std::collections::HashMap::from([
        ("GATEWAY_AUTH_PROVIDERS", providers),
        ("NOETL_AUTH_MINT_KEY", MINT_KEY.to_string()),
        ("GATEWAY_APP_USER_PLAYBOOKS", format!(r#"{{"site-app": ["{APP_PLAYBOOK}"]}}"#)),
    ]);
    ProvidersConfig::from_lookup(|k| env.get(k).cloned()).unwrap().unwrap()
}

async fn gateway(noetl: &str, config: ProvidersConfig) -> String {
    let auth_state = Arc::new(AuthState {
        noetl: Arc::new(NoetlClient::new(noetl.to_string())),
        callbacks: Arc::new(CallbackManager::new(None)),
        playbook_config: Default::default(),
        // Unreachable: caching the minted session is best effort.
        session_cache: Arc::new(SessionCache::new("sessions".into(), 300, "127.0.0.1:9")),
        guests: None,
    });
    let app = Router::new()
        .route("/api/auth/providers/{provider}/{action}", post(crate::auth_providers::sign_in))
        .with_state(Arc::new(ProviderState::new(config, auth_state.clone())))
        .merge(
            Router::new()
                .route("/api/auth/logout", post(crate::auth_providers::logout))
                .with_state(auth_state),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap()
    });
    format!("http://{addr}")
}

async fn call(gw: &str, path: &str, body: &str) -> (u16, Value) {
    let res = reqwest::Client::new()
        .post(format!("{gw}{path}"))
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn route_surface() {
    let (noetl, mock) = mock_noetl().await;
    let gw = gateway(&noetl, providers_config(10)).await;
    assert_eq!(call(&gw, "/api/auth/providers/nope/start", "{}").await.0, 404);
    assert_eq!(call(&gw, "/api/auth/providers/msr-email/delete_everything", "{}").await.0, 404);
    let big = format!(r#"{{"email": "{}"}}"#, "x".repeat(5000));
    assert_eq!(call(&gw, "/api/auth/providers/msr-email/start", &big).await.0, 413);
    assert_eq!(call(&gw, "/api/auth/providers/msr-email/start", "[1,2]").await.0, 400);
    assert!(mock.seen.lock().unwrap().is_empty(), "refused requests never reach NoETL");
}

#[tokio::test]
async fn pending_denied_and_contract_violations() {
    let (noetl, mock) = mock_noetl().await;
    let gw = gateway(&noetl, providers_config(10)).await;

    let (s, b) = call(&gw, "/api/auth/providers/msr-email/start", r#"{"email": "g@example.org", "script": "pending"}"#).await;
    assert_eq!(s, 200);
    assert_eq!(b, json!({"status": "pending", "message": "We emailed a code", "data": {"resend_in": 30}}));
    let (_, workload) = mock.runs.lock().unwrap()[0].clone();
    assert_eq!(workload["action"], "start");
    assert_eq!(workload["provider"], "msr-email");
    assert_eq!(workload["input"]["email"], "g@example.org");

    let (s, b) = call(&gw, "/api/auth/providers/msr-email/verify", r#"{"script": "denied"}"#).await;
    assert_eq!((s, b["status"].as_str()), (401, Some("denied")));

    let (s, b) = call(&gw, "/api/auth/providers/msr-email/verify", r#"{"script": "smuggle"}"#).await;
    assert_eq!(s, 502);
    assert!(b.get("session_token").is_none());

    let (s, _) = call(&gw, "/api/auth/providers/msr-email/verify", r#"{"script": "fail"}"#).await;
    assert_eq!(s, 502);
    assert!(mock.mints.lock().unwrap().is_empty(), "no session without a valid authenticated result");
}

#[tokio::test]
async fn authenticated_mints_through_the_server_with_the_key() {
    let (noetl, mock) = mock_noetl().await;
    let gw = gateway(&noetl, providers_config(10)).await;
    let (s, b) = call(&gw, "/api/auth/providers/msr-email/verify", r#"{"email": "g@example.org", "script": "ok"}"#).await;
    assert_eq!(s, 200, "{b}");
    assert_eq!(b["status"], "authenticated");
    assert_eq!(b["session_token"], "minted-by-server");
    assert_eq!(b["user"]["email"], "g@example.org");

    let mints = mock.mints.lock().unwrap().clone();
    assert_eq!(mints.len(), 1);
    let (key, body) = &mints[0];
    assert_eq!(key.as_deref(), Some(MINT_KEY));
    assert_eq!(body["provider"], "msr-email");
    assert_eq!(body["subject"], "s1");
    assert_eq!(body["email_verified"], true);
    assert_eq!(body["session_hours"], 720);
}

#[tokio::test]
async fn rate_limited_per_key_field() {
    let (noetl, _mock) = mock_noetl().await;
    let gw = gateway(&noetl, providers_config(2)).await;
    for _ in 0..2 {
        assert_eq!(call(&gw, "/api/auth/providers/msr-email/start", r#"{"email": "G@Example.org", "script": "pending"}"#).await.0, 200);
    }
    // Same address, any case: refused.
    assert_eq!(call(&gw, "/api/auth/providers/msr-email/start", r#"{"email": "g@example.org", "script": "pending"}"#).await.0, 429);
    // Another address is still fine.
    assert_eq!(call(&gw, "/api/auth/providers/msr-email/start", r#"{"email": "h@example.org", "script": "pending"}"#).await.0, 200);
}

#[tokio::test]
async fn logout_ends_the_session_at_the_server() {
    let (noetl, mock) = mock_noetl().await;
    let gw = gateway(&noetl, providers_config(10)).await;
    let res = reqwest::Client::new()
        .post(format!("{gw}/api/auth/logout"))
        .bearer_auth("sess-abc")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    assert!(mock.seen.lock().unwrap().contains(&"POST /api/auth/logout sess-abc".to_string()));
    let res = reqwest::Client::new().post(format!("{gw}/api/auth/logout")).send().await.unwrap();
    assert_eq!(res.status().as_u16(), 401);
}

fn user(sub: Option<&str>, roles: &[&str]) -> UserContext {
    UserContext {
        user_id: 42,
        email: "g@example.org".into(),
        display_name: "g".into(),
        session_token: "t".into(),
        auth0_sub: sub.map(str::to_string),
        roles: roles.iter().map(|r| r.to_string()).collect(),
        guest: None,
    }
}

#[test]
fn provider_users_reach_only_their_apps_playbooks() {
    let config = providers_config(10);
    let mut policy = Policy::from_env_with(None, Some(&config));
    policy.user_playbooks = vec!["travel/playbooks/profile".into()];
    let provider_user = user(Some("ap:msr-email|s1"), &[]);
    assert!(policy.may_execute(&provider_user, APP_PLAYBOOK, "playbook"));
    assert!(!policy.may_execute(&provider_user, "travel/playbooks/profile", "playbook"), "not another app's");
    assert!(!policy.may_execute(&provider_user, APP_PLAYBOOK, "agent"));

    let auth0_user = user(Some("google-oauth2|1"), &[]);
    assert!(policy.may_execute(&auth0_user, "travel/playbooks/profile", "playbook"), "Auth0 users unchanged");
    assert!(!policy.may_execute(&auth0_user, APP_PLAYBOOK, "playbook"));

    let orphan = user(Some("ap:removed|s1"), &[]);
    assert!(!policy.may_execute(&orphan, APP_PLAYBOOK, "playbook"), "unknown provider: fail closed");

    let admin = user(Some("ap:msr-email|s2"), &["admin"]);
    assert!(policy.may_execute(&admin, "travel/playbooks/profile", "playbook"), "roles stay manual and still apply");
}
