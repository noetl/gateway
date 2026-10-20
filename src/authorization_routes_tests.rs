//! End to end: through the real GraphQL handler, schema and REST proxy, against a
//! mock NoETL server that records every request it receives. Proves what an
//! regular user can and cannot reach (`crate::authorization`), and that a
//! refused request never reaches NoETL.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_graphql::{EmptySubscription, Schema};
use axum::{extract::State, routing::any, Extension, Router};
use serde_json::{json, Value};

use crate::auth::types::UserContext;
use crate::authorization::{ExecutionOwners, Policy};
use crate::graphql::schema::{AppSchema, MutationRoot, QueryRoot};
use crate::noetl_client::NoetlClient;
use crate::proxy::ProxyState;

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

/// A NoETL stand-in: records `METHOD /path` of every request; `execute` and
/// `rerun` mint a fresh execution id, everything else answers 200.
async fn mock_noetl() -> (String, Mock) {
    let mock = Mock {
        next_id: Arc::new(AtomicU64::new(1000)),
        ..Mock::default()
    };
    async fn handle(State(m): State<Mock>, method: axum::http::Method, uri: axum::http::Uri) -> axum::Json<Value> {
        let path = uri.path().to_string();
        m.seen.lock().unwrap().push(format!("{method} {path}"));
        if path == "/api/execute" || path.ends_with("/rerun") {
            let id = m.next_id.fetch_add(1, Ordering::SeqCst);
            return axum::Json(json!({"execution_id": id.to_string(), "status": "started", "name": "x"}));
        }
        axum::Json(json!({"ok": true}))
    }
    let app = Router::new().route("/api/{*rest}", any(handle)).with_state(mock.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), mock)
}

fn user(user_id: i32) -> UserContext {
    UserContext {
        user_id,
        email: format!("user{user_id}@example.invalid"),
        display_name: "User".into(),
        session_token: format!("synthetic-{user_id}"),
        auth0_sub: Some(format!("auth0|user{user_id}")),
        roles: Vec::new(),
        guest: None,
    }
}

fn admin() -> UserContext {
    UserContext {
        roles: vec!["admin".into()],
        ..user(99)
    }
}

/// The gateway's GraphQL and proxy routes as `caller`, sharing `owners`.
async fn gateway(noetl: &str, caller: UserContext, owners: Option<Arc<ExecutionOwners>>) -> String {
    let policy = Arc::new(Policy::default());
    let mut schema = Schema::build(QueryRoot, MutationRoot, EmptySubscription)
        .data(Arc::new(NoetlClient::new(noetl.to_string())))
        .data(policy.clone());
    if let Some(o) = owners.clone() {
        schema = schema.data(o);
    }
    let schema: AppSchema = schema.finish();
    let proxy_state = Arc::new(ProxyState::new(noetl.to_string()).with_authorization(policy, owners));
    let proxy = Router::new()
        .route("/noetl/{*path}", any(proxy_any))
        .with_state(proxy_state);
    let app = Router::new()
        .route("/graphql", axum::routing::post(crate::graphql::graphql_handler))
        .layer(Extension(schema))
        .merge(proxy)
        .layer(Extension(caller));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

/// The per-method handlers `main` mounts, behind one route.
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

async fn graphql(gw: &str, query: &str, variables: Value) -> Value {
    reqwest::Client::new()
        .post(format!("{gw}/graphql"))
        .json(&json!({"query": query, "variables": variables}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

const EXECUTE: &str =
    "mutation($n: String!, $v: JSON, $k: ExecutableResourceKind) { executePlaybook(name: $n, variables: $v, resourceKind: $k) { executionId } }";

/// Start `name` through `executePlaybook`; the execution id, or the errors.
async fn execute(gw: &str, name: &str) -> Result<String, Value> {
    let resp = graphql(gw, EXECUTE, json!({"n": name, "v": {"uid": "x"}})).await;
    match resp.pointer("/data/executePlaybook/executionId").and_then(Value::as_str) {
        Some(id) => Ok(id.to_string()),
        None => Err(resp),
    }
}

async fn status(method: reqwest::Method, url: String) -> reqwest::StatusCode {
    reqwest::Client::new()
        .request(method, url)
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn a_regular_user_runs_an_allowlisted_playbook_then_polls_and_cancels_it() {
    let (noetl, mock) = mock_noetl().await;
    let owners = Arc::new(ExecutionOwners::in_memory());
    let gw = gateway(&noetl, user(1), Some(owners)).await;

    let id = execute(&gw, "muno/playbooks/profile").await.expect("allowlisted playbook runs");
    assert_eq!(status(reqwest::Method::GET, format!("{gw}/noetl/executions/{id}")).await, 200);
    assert_eq!(
        status(reqwest::Method::POST, format!("{gw}/noetl/executions/{id}/cancel")).await,
        200
    );
    assert_eq!(
        mock.seen(),
        vec![
            "POST /api/execute".to_string(),
            format!("GET /api/executions/{id}"),
            format!("POST /api/executions/{id}/cancel"),
        ]
    );
}

#[tokio::test]
async fn every_allowlisted_playbook_runs_for_an_user() {
    let (noetl, _) = mock_noetl().await;
    let gw = gateway(&noetl, user(1), Some(Arc::new(ExecutionOwners::in_memory()))).await;
    for name in crate::authorization::DEFAULT_USER_PLAYBOOKS {
        assert!(execute(&gw, name).await.is_ok(), "{name}");
    }
}

#[tokio::test]
async fn a_regular_user_cannot_read_or_cancel_another_users_execution() {
    let (noetl, mock) = mock_noetl().await;
    let owners = Arc::new(ExecutionOwners::in_memory());
    let alice = gateway(&noetl, user(1), Some(owners.clone())).await;
    let bob = gateway(&noetl, user(2), Some(owners)).await;

    let id = execute(&alice, "muno/playbooks/itinerary-planner").await.unwrap();
    let before = mock.seen().len();
    assert_eq!(status(reqwest::Method::GET, format!("{bob}/noetl/executions/{id}")).await, 404);
    assert_eq!(
        status(reqwest::Method::POST, format!("{bob}/noetl/executions/{id}/cancel")).await,
        404
    );
    // An id nobody recorded looks the same as someone else's.
    assert_eq!(status(reqwest::Method::GET, format!("{bob}/noetl/executions/424242")).await, 404);
    assert_eq!(mock.seen().len(), before, "a refused request must not reach NoETL");
}

#[tokio::test]
async fn a_regular_user_cannot_start_a_playbook_outside_the_allowlist() {
    let (noetl, mock) = mock_noetl().await;
    let gw = gateway(&noetl, user(1), Some(Arc::new(ExecutionOwners::in_memory()))).await;
    for name in ["automation/agents/mcp/firestore", "auth0/login", "muno/playbooks/profile/"] {
        assert!(execute(&gw, name).await.is_err(), "{name}");
    }
    let resp = graphql(
        &gw,
        EXECUTE,
        json!({"n": "muno/playbooks/profile", "v": {}, "k": "agent"}),
    )
    .await;
    assert!(resp.get("errors").is_some(), "{resp}");
    assert!(mock.seen().is_empty());
}

#[tokio::test]
async fn a_regular_user_cannot_use_the_admin_mutations() {
    let (noetl, mock) = mock_noetl().await;
    let gw = gateway(&noetl, user(1), Some(Arc::new(ExecutionOwners::in_memory()))).await;
    let rerun = graphql(&gw, "mutation { rerunExecution(executionId: \"42\") { executionId } }", json!({})).await;
    assert!(rerun.get("errors").is_some(), "{rerun}");
    let proxied = graphql(
        &gw,
        "mutation { proxyRequest(input: {method: \"POST\", endpoint: \"/api/catalog/list\"}) { success } }",
        json!({}),
    )
    .await;
    assert!(proxied.get("errors").is_some(), "{proxied}");
    assert!(mock.seen().is_empty());
}

#[tokio::test]
async fn a_regular_user_cannot_reach_any_other_proxy_route() {
    let (noetl, mock) = mock_noetl().await;
    let gw = gateway(&noetl, user(1), Some(Arc::new(ExecutionOwners::in_memory()))).await;
    for (method, path) in [
        (reqwest::Method::POST, "execute"),
        (reqwest::Method::POST, "execute/batch"),
        (reqwest::Method::POST, "executions/42/rerun"),
        (reqwest::Method::POST, "catalog/register"),
        (reqwest::Method::POST, "catalog/list"),
        (reqwest::Method::GET, "credentials"),
        (reqwest::Method::GET, "executions"),
        (reqwest::Method::DELETE, "executions/42"),
    ] {
        assert_eq!(
            status(method.clone(), format!("{gw}/noetl/{path}")).await,
            403,
            "{method} {path}"
        );
    }
    assert!(mock.seen().is_empty());
}

#[tokio::test]
async fn an_admin_keeps_the_whole_proxy_and_every_execution() {
    let (noetl, mock) = mock_noetl().await;
    let owners = Arc::new(ExecutionOwners::in_memory());
    let alice = gateway(&noetl, user(1), Some(owners.clone())).await;
    let admin = gateway(&noetl, admin(), Some(owners)).await;

    let id = execute(&alice, "muno/playbooks/profile").await.unwrap();
    assert_eq!(status(reqwest::Method::GET, format!("{admin}/noetl/executions/{id}")).await, 200);
    assert_eq!(status(reqwest::Method::POST, format!("{admin}/noetl/catalog/register")).await, 200);
    assert!(execute(&admin, "automation/agents/mcp/firestore").await.is_ok());
    assert!(mock.seen().contains(&"POST /api/catalog/register".to_string()));
}

#[tokio::test]
async fn without_an_owner_store_a_regular_user_execution_route_is_refused() {
    let (noetl, mock) = mock_noetl().await;
    let gw = gateway(&noetl, user(1), None).await;
    let id = execute(&gw, "muno/playbooks/profile").await.unwrap();
    assert_eq!(status(reqwest::Method::GET, format!("{gw}/noetl/executions/{id}")).await, 503);
    assert_eq!(mock.seen(), vec!["POST /api/execute".to_string()]);
}
