//! End to end through the real GraphQL handler: a signed-in user's starts of a
//! playbook in `GATEWAY_USER_PLAYBOOK_LIMITS` are limited per user and in
//! total (`crate::user_limits`); admins, guests' rules and other playbooks are
//! untouched, and a refused start never reaches NoETL.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_graphql::{EmptySubscription, Schema};
use axum::{extract::State, routing::any, Extension, Router};
use serde_json::{json, Value};

use crate::auth::types::UserContext;
use crate::authorization::Policy;
use crate::graphql::schema::{AppSchema, MutationRoot, QueryRoot};
use crate::noetl_client::NoetlClient;
use crate::user_limits::UserLimits;

#[derive(Clone, Default)]
struct Mock {
    executes: Arc<Mutex<usize>>,
    next_id: Arc<AtomicU64>,
}

async fn mock_noetl() -> (String, Mock) {
    let mock = Mock { next_id: Arc::new(AtomicU64::new(1000)), ..Mock::default() };
    async fn handle(State(m): State<Mock>, uri: axum::http::Uri) -> axum::Json<Value> {
        if uri.path() == "/api/execute" {
            *m.executes.lock().unwrap() += 1;
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

fn user(user_id: i32, roles: &[&str]) -> UserContext {
    UserContext {
        user_id,
        email: format!("user{user_id}@example.invalid"),
        display_name: "User".into(),
        session_token: format!("synthetic-{user_id}"),
        auth0_sub: Some(format!("auth0|user{user_id}")),
        roles: roles.iter().map(|r| r.to_string()).collect(),
        guest: None,
    }
}

/// GraphQL as `caller`, sharing one `limits` across gateways (one pod).
async fn gateway(noetl: &str, caller: UserContext, limits: Option<Arc<UserLimits>>) -> String {
    let policy = Policy { user_playbooks: vec!["site/inbox".into(), "site/turn".into()], ..Policy::default() };
    let mut schema = Schema::build(QueryRoot, MutationRoot, EmptySubscription)
        .data(Arc::new(NoetlClient::new(noetl.to_string())))
        .data(Arc::new(policy));
    if let Some(l) = limits {
        schema = schema.data(l);
    }
    let schema: AppSchema = schema.finish();
    let app = Router::new()
        .route("/graphql", axum::routing::post(crate::graphql::graphql_handler))
        .layer(Extension(schema))
        .layer(Extension(caller));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

const EXECUTE: &str = "mutation($n: String!, $v: JSON) { executePlaybook(name: $n, variables: $v) { executionId } }";

async fn execute(gw: &str, name: &str) -> Result<String, Value> {
    let resp: Value = reqwest::Client::new()
        .post(format!("{gw}/graphql"))
        .json(&json!({"query": EXECUTE, "variables": {"n": name, "v": {}}}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    match resp.pointer("/data/executePlaybook/executionId").and_then(Value::as_str) {
        Some(id) => Ok(id.to_string()),
        None => Err(resp),
    }
}

fn limits(spec: &str) -> Arc<UserLimits> {
    UserLimits::from_spec(spec).unwrap().unwrap()
}

#[tokio::test]
async fn a_user_is_limited_per_playbook_with_retry_after() {
    let (noetl, mock) = mock_noetl().await;
    let l = limits("site/inbox=2/100");
    let gw = gateway(&noetl, user(1, &[]), Some(l.clone())).await;
    assert!(execute(&gw, "site/inbox").await.is_ok());
    assert!(execute(&gw, "site/inbox").await.is_ok());
    let err = execute(&gw, "site/inbox").await.unwrap_err();
    let ext = &err["errors"][0]["extensions"];
    assert_eq!(ext["code"], "RATE_LIMITED", "{err}");
    assert!(ext["retryAfter"].as_u64().is_some_and(|w| w > 0 && w <= 3600), "{err}");
    assert_eq!(*mock.executes.lock().unwrap(), 2, "a refused start must not reach NoETL");
    // an unlisted playbook is not limited
    for _ in 0..5 {
        assert!(execute(&gw, "site/turn").await.is_ok());
    }
    // another user, same pod, has their own budget
    let gw2 = gateway(&noetl, user(2, &[]), Some(l)).await;
    assert!(execute(&gw2, "site/inbox").await.is_ok());
}

#[tokio::test]
async fn admins_are_not_limited() {
    let (noetl, _) = mock_noetl().await;
    let gw = gateway(&noetl, user(9, &["admin"]), Some(limits("site/inbox=1/1"))).await;
    for _ in 0..4 {
        assert!(execute(&gw, "site/inbox").await.is_ok());
    }
}

#[tokio::test]
async fn without_limits_nothing_changes() {
    let (noetl, _) = mock_noetl().await;
    let gw = gateway(&noetl, user(1, &[]), None).await;
    for _ in 0..4 {
        assert!(execute(&gw, "site/inbox").await.is_ok());
    }
}

#[tokio::test]
async fn the_total_limit_spans_users() {
    let (noetl, _) = mock_noetl().await;
    let l = limits("site/inbox=10/2");
    assert!(execute(&gateway(&noetl, user(1, &[]), Some(l.clone())).await, "site/inbox").await.is_ok());
    assert!(execute(&gateway(&noetl, user(2, &[]), Some(l.clone())).await, "site/inbox").await.is_ok());
    let err = execute(&gateway(&noetl, user(3, &[]), Some(l)).await, "site/inbox").await.unwrap_err();
    assert_eq!(err["errors"][0]["extensions"]["code"], "RATE_LIMITED", "{err}");
}
