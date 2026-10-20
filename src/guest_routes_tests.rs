//! End to end for guest sessions (`crate::guest`): mint through the public
//! route, then the REAL auth middleware, GraphQL handler and REST proxy against
//! a mock NoETL that records every request. Proves what a guest can and cannot
//! reach, that its runs are its own, the identity guard and the rate limits,
//! and that a refused request never reaches NoETL.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_graphql::{EmptySubscription, Schema};
use axum::{
    extract::State,
    middleware,
    routing::{any, post},
    Extension, Router,
};
use serde_json::{json, Value};

use crate::auth::AuthState;
use crate::authorization::{ExecutionOwners, Policy};
use crate::callbacks::CallbackManager;
use crate::graphql::schema::{AppSchema, MutationRoot, QueryRoot};
use crate::guest::{GuestConfig, GuestSessions};
use crate::noetl_client::NoetlClient;
use crate::proxy::ProxyState;
use crate::session_cache::SessionCache;

const GUEST_PLAYBOOK: &str = "site/concierge/turn";

#[derive(Clone, Default)]
struct Mock {
    seen: Arc<Mutex<Vec<String>>>,
    next_id: Arc<AtomicU64>,
}

impl Mock {
    fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

async fn mock_noetl() -> (String, Mock) {
    let mock = Mock {
        next_id: Arc::new(AtomicU64::new(5000)),
        ..Mock::default()
    };
    async fn handle(State(m): State<Mock>, method: axum::http::Method, uri: axum::http::Uri) -> axum::Json<Value> {
        let path = uri.path().to_string();
        m.seen.lock().unwrap().push(format!("{method} {path}"));
        if path == "/api/execute" {
            let id = m.next_id.fetch_add(1, Ordering::SeqCst);
            return axum::Json(json!({"execution_id": id.to_string(), "status": "started", "name": "x"}));
        }
        axum::Json(json!({"ok": true}))
    }
    let app = Router::new()
        .route("/api/{*rest}", any(handle))
        .with_state(mock.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), mock)
}

fn config(tweak: impl FnOnce(&mut GuestConfig)) -> GuestConfig {
    let mut c = crate::guest::test_config(&[GUEST_PLAYBOOK]);
    tweak(&mut c);
    c
}

/// The routes `main` mounts in guest mode, with the real auth middleware.
async fn gateway(noetl: &str, guest_config: GuestConfig) -> String {
    let guests = Arc::new(GuestSessions::new(guest_config));
    let policy = Arc::new(Policy::from_env(Some(&guests.config)));
    let owners = Arc::new(ExecutionOwners::in_memory());
    let client = Arc::new(NoetlClient::new(noetl.to_string()));
    let auth_state = Arc::new(AuthState {
        noetl: client.clone(),
        callbacks: Arc::new(CallbackManager::new(None)),
        playbook_config: Default::default(),
        // Unreachable on purpose: a guest must never touch the session cache.
        session_cache: Arc::new(SessionCache::new("sessions".into(), 300, "127.0.0.1:9")),
        guests: Some(guests.clone()),
    });
    let schema: AppSchema = Schema::build(QueryRoot, MutationRoot, EmptySubscription)
        .data(client)
        .data(policy.clone())
        .data(owners.clone())
        .data(guests.clone())
        .finish();
    let proxy_state = Arc::new(ProxyState::new(noetl.to_string()).with_authorization(policy, Some(owners)));
    let protected = Router::new()
        .route("/graphql", post(crate::graphql::graphql_handler))
        .layer(Extension(schema))
        .merge(
            Router::new()
                .route("/noetl/{*path}", any(proxy_any))
                .with_state(proxy_state),
        )
        .route_layer(middleware::from_fn_with_state(
            auth_state,
            crate::auth::middleware::auth_middleware,
        ));
    let app = Router::new()
        .route("/api/auth/guest", post(crate::guest::mint))
        .with_state(guests)
        .merge(protected);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap()
    });
    format!("http://{addr}")
}

async fn proxy_any(
    state: State<Arc<ProxyState>>,
    path: axum::extract::Path<String>,
    req: axum::http::Request<axum::body::Body>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    match req.method().clone() {
        axum::http::Method::GET => crate::proxy::proxy_get(state, path, req).await.into_response(),
        axum::http::Method::POST => crate::proxy::proxy_post(state, path, req).await.into_response(),
        axum::http::Method::PUT => crate::proxy::proxy_put(state, path, req).await.into_response(),
        axum::http::Method::DELETE => crate::proxy::proxy_delete(state, path, req).await.into_response(),
        _ => crate::proxy::proxy_patch(state, path, req).await.into_response(),
    }
}

/// A new guest session token.
async fn mint(gw: &str) -> String {
    let resp: Value = reqwest::Client::new()
        .post(format!("{gw}/api/auth/guest"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "guest");
    assert!(resp["guest_id"]
        .as_str()
        .is_some_and(|g| uuid::Uuid::parse_str(g).is_ok()));
    resp["session_token"].as_str().unwrap().to_string()
}

const EXECUTE: &str = "mutation($n: String!, $v: JSON) { executePlaybook(name: $n, variables: $v) { executionId } }";

async fn graphql_status(gw: &str, token: &str, name: &str, vars: Value) -> (reqwest::StatusCode, Value) {
    let resp = reqwest::Client::new()
        .post(format!("{gw}/graphql"))
        .bearer_auth(token)
        .json(&json!({"query": EXECUTE, "variables": {"n": name, "v": vars}}))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    (status, resp.json().await.unwrap_or(Value::Null))
}

async fn execute(gw: &str, token: &str, name: &str, vars: Value) -> Result<String, Value> {
    let (_, body) = graphql_status(gw, token, name, vars).await;
    match body
        .pointer("/data/executePlaybook/executionId")
        .and_then(Value::as_str)
    {
        Some(id) => Ok(id.to_string()),
        None => Err(body),
    }
}

async fn status(gw: &str, token: &str, method: reqwest::Method, path: &str) -> reqwest::StatusCode {
    reqwest::Client::new()
        .request(method, format!("{gw}{path}"))
        .bearer_auth(token)
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn a_guest_runs_the_guest_playbook_then_polls_and_cancels_only_its_own_run() {
    let (noetl, mock) = mock_noetl().await;
    let gw = gateway(&noetl, config(|_| {})).await;
    let (me, other) = (mint(&gw).await, mint(&gw).await);

    let id = execute(&gw, &me, GUEST_PLAYBOOK, json!({"user_uid": null}))
        .await
        .expect("guest playbook runs");
    assert_eq!(
        status(&gw, &me, reqwest::Method::GET, &format!("/noetl/executions/{id}")).await,
        200
    );
    let before = mock.seen().len();
    assert_eq!(
        status(&gw, &other, reqwest::Method::GET, &format!("/noetl/executions/{id}")).await,
        404
    );
    assert_eq!(
        status(
            &gw,
            &other,
            reqwest::Method::POST,
            &format!("/noetl/executions/{id}/cancel")
        )
        .await,
        404
    );
    assert_eq!(
        mock.seen().len(),
        before,
        "another guest's request must not reach NoETL"
    );
    assert_eq!(
        status(
            &gw,
            &me,
            reqwest::Method::POST,
            &format!("/noetl/executions/{id}/cancel")
        )
        .await,
        200
    );
    assert_eq!(
        mock.seen(),
        vec![
            "POST /api/execute".to_string(),
            format!("GET /api/executions/{id}"),
            format!("POST /api/executions/{id}/cancel")
        ]
    );
}

#[tokio::test]
async fn a_guest_cannot_start_any_other_playbook() {
    let (noetl, mock) = mock_noetl().await;
    let gw = gateway(&noetl, config(|_| {})).await;
    let me = mint(&gw).await;
    for name in [
        "muno/playbooks/profile",
        "automation/agents/mcp/firestore",
        "site/concierge/turn/",
        "",
    ] {
        assert!(execute(&gw, &me, name, json!({})).await.is_err(), "{name:?}");
    }
    assert!(mock.seen().is_empty(), "a refused execute must not reach NoETL");
}

#[tokio::test]
async fn a_guest_cannot_reach_any_other_proxy_route() {
    let (noetl, mock) = mock_noetl().await;
    let gw = gateway(&noetl, config(|_| {})).await;
    let me = mint(&gw).await;
    for (method, path) in [
        (reqwest::Method::POST, "/noetl/execute"),
        (reqwest::Method::POST, "/noetl/catalog/list"),
        (reqwest::Method::GET, "/noetl/credentials"),
        (reqwest::Method::GET, "/noetl/executions"),
        (reqwest::Method::POST, "/noetl/executions/42/rerun"),
    ] {
        assert_eq!(status(&gw, &me, method.clone(), path).await, 403, "{method} {path}");
    }
    assert!(mock.seen().is_empty());
}

#[tokio::test]
async fn a_bad_or_expired_guest_token_is_unauthorized() {
    let (noetl, mock) = mock_noetl().await;
    let gw = gateway(&noetl, config(|_| {})).await;
    let me = mint(&gw).await;
    let (signed, _) = me.rsplit_once('.').unwrap();
    let foreign = GuestSessions::new(config(|c| c.playbooks = vec!["x".into()]))
        .mint_at(0)
        .0; // expired long ago
    for token in [format!("{signed}.AAAA"), foreign, "ng1.x.y".to_string()] {
        let (code, _) = graphql_status(&gw, &token, GUEST_PLAYBOOK, json!({})).await;
        assert_eq!(code, 401, "{token}");
    }
    assert!(mock.seen().is_empty());
}

#[tokio::test]
async fn a_guest_cannot_claim_an_identity() {
    let (noetl, _) = mock_noetl().await;
    let gw = gateway(&noetl, config(|_| {})).await;
    let me = mint(&gw).await;
    assert!(execute(&gw, &me, GUEST_PLAYBOOK, json!({"uid": "auth0|someone"}))
        .await
        .is_err());
    assert!(execute(&gw, &me, GUEST_PLAYBOOK, json!({"user_uid": "auth0|someone"}))
        .await
        .is_err());
    assert!(execute(&gw, &me, GUEST_PLAYBOOK, json!({"uid": null})).await.is_ok());
    assert!(execute(&gw, &me, GUEST_PLAYBOOK, json!({"message": "hi"}))
        .await
        .is_ok());
}

#[tokio::test]
async fn guest_runs_are_rate_limited_with_retry_after() {
    let (noetl, mock) = mock_noetl().await;
    let gw = gateway(&noetl, config(|c| c.runs_per_guest = 2)).await;
    let me = mint(&gw).await;
    assert!(execute(&gw, &me, GUEST_PLAYBOOK, json!({})).await.is_ok());
    assert!(execute(&gw, &me, GUEST_PLAYBOOK, json!({})).await.is_ok());
    let err = execute(&gw, &me, GUEST_PLAYBOOK, json!({})).await.unwrap_err();
    let ext = &err["errors"][0]["extensions"];
    assert_eq!(ext["code"], "RATE_LIMITED", "{err}");
    assert!(ext["retryAfter"].as_u64().is_some_and(|s| s > 0 && s <= 3600));
    assert_eq!(mock.seen().len(), 2, "the refused run must not reach NoETL");
    // A fresh guest from the same address still has its own allowance.
    assert!(execute(&gw, &mint(&gw).await, GUEST_PLAYBOOK, json!({})).await.is_ok());
}

#[tokio::test]
async fn guest_mints_are_rate_limited_per_address() {
    let (noetl, _) = mock_noetl().await;
    let gw = gateway(&noetl, config(|c| c.mints_per_ip = 2)).await;
    mint(&gw).await;
    mint(&gw).await;
    let resp = reqwest::Client::new()
        .post(format!("{gw}/api/auth/guest"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429);
    let wait: u64 = resp.headers()["retry-after"].to_str().unwrap().parse().unwrap();
    assert!(wait > 0 && wait <= 3600);
}
