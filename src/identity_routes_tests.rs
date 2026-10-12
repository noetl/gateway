//! End to end: through the real GraphQL handler, schema and REST proxy, against a
//! mock NoETL server that records what it is asked to run. Proves the identity a
//! playbook receives is the authenticated caller's, whatever the request says.

use std::sync::{Arc, Mutex};

use async_graphql::{EmptySubscription, Schema};
use axum::{extract::State, routing::post, Extension, Json, Router};
use serde_json::{json, Value};

use crate::auth::types::UserContext;
use crate::graphql::schema::{AppSchema, MutationRoot, QueryRoot};
use crate::noetl_client::NoetlClient;
use crate::proxy::ProxyState;

const CALLER: &str = "auth0|caller";
const VICTIM: &str = "auth0|someone-else";

type Seen = Arc<Mutex<Vec<(String, Value)>>>;

/// A NoETL stand-in that records every execute/rerun body it receives.
async fn mock_noetl() -> (String, Seen) {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    async fn record(State(seen): State<Seen>, uri: axum::http::Uri, Json(body): Json<Value>) -> Json<Value> {
        seen.lock().unwrap().push((uri.path().to_string(), body));
        Json(json!({"execution_id": "1", "status": "started", "name": "x"}))
    }
    let app = Router::new()
        .route("/api/execute", post(record))
        .route("/api/execute/batch", post(record))
        .route("/api/executions/{id}/rerun", post(record))
        .with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), seen)
}

fn user(sub: Option<&str>) -> UserContext {
    UserContext {
        user_id: 7,
        email: "caller@example.invalid".into(),
        display_name: "Caller".into(),
        session_token: "synthetic-session".into(),
        auth0_sub: sub.map(str::to_string),
    }
}

/// The gateway's own routes, with the caller the auth middleware would have
/// verified (`None` = no verified caller at all).
async fn gateway(noetl: &str, caller: Option<UserContext>) -> String {
    let schema: AppSchema = Schema::build(QueryRoot, MutationRoot, EmptySubscription)
        .data(Arc::new(NoetlClient::new(noetl.to_string())))
        .finish();
    let proxy = Router::new()
        .route("/noetl/{*path}", post(crate::proxy::proxy_post))
        .with_state(Arc::new(ProxyState::new(noetl.to_string())));
    let mut app = Router::new()
        .route("/graphql", post(crate::graphql::graphql_handler))
        .layer(Extension(schema))
        .merge(proxy);
    if let Some(u) = caller {
        app = app.layer(Extension(u));
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

async fn execute_playbook(gw: &str, vars: Value) -> Value {
    reqwest::Client::new()
        .post(format!("{gw}/graphql"))
        .json(&json!({
            "query": "mutation($n: String!, $v: JSON) { executePlaybook(name: $n, variables: $v) { executionId } }",
            "variables": {"n": "muno/playbooks/profile", "v": vars}
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

fn workload(seen: &Seen, i: usize) -> Value {
    let (_, body) = seen.lock().unwrap()[i].clone();
    body.get("workload")
        .or_else(|| body.get("payload"))
        .cloned()
        .unwrap_or(Value::Null)
}

#[tokio::test]
async fn graphql_execute_runs_as_the_caller_not_the_uid_in_the_request() {
    let (noetl, seen) = mock_noetl().await;
    let gw = gateway(&noetl, Some(user(Some(CALLER)))).await;
    let resp = execute_playbook(&gw, json!({"uid": VICTIM, "profile": {}, "read_only": true})).await;
    assert!(resp.get("errors").is_none(), "{resp}");
    assert_eq!(workload(&seen, 0)["uid"], CALLER);
    assert_eq!(workload(&seen, 0)["read_only"], true);
}

#[tokio::test]
async fn graphql_execute_without_a_session_subject_is_refused_and_nothing_runs() {
    let (noetl, seen) = mock_noetl().await;
    let gw = gateway(&noetl, Some(user(None))).await;
    let resp = execute_playbook(&gw, json!({"uid": VICTIM, "profile": {}})).await;
    assert!(resp.get("errors").is_some(), "{resp}");
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn graphql_execute_with_no_verified_caller_is_refused() {
    let (noetl, seen) = mock_noetl().await;
    let gw = gateway(&noetl, None).await;
    let resp = execute_playbook(&gw, json!({"uid": VICTIM})).await;
    assert!(resp.get("errors").is_some(), "{resp}");
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn graphql_execute_of_an_identity_free_playbook_is_unchanged() {
    let (noetl, seen) = mock_noetl().await;
    let gw = gateway(&noetl, Some(user(None))).await;
    let resp = execute_playbook(&gw, json!({"city": "Paris"})).await;
    assert!(resp.get("errors").is_none(), "{resp}");
    assert_eq!(workload(&seen, 0), json!({"city": "Paris"}));
}

#[tokio::test]
async fn graphql_rerun_binds_identities_the_request_did_not_send() {
    let (noetl, seen) = mock_noetl().await;
    let gw = gateway(&noetl, Some(user(Some(CALLER)))).await;
    let resp: Value = reqwest::Client::new()
        .post(format!("{gw}/graphql"))
        .json(&json!({"query": "mutation { rerunExecution(executionId: \"42\") { executionId } }"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(resp.get("errors").is_none(), "{resp}");
    let (path, _) = seen.lock().unwrap()[0].clone();
    assert_eq!(path, "/api/executions/42/rerun");
    assert_eq!(workload(&seen, 0)["uid"], CALLER);
    assert_eq!(workload(&seen, 0)["user_uid"], CALLER);
}

#[tokio::test]
async fn proxy_execute_runs_as_the_caller_not_the_uid_in_the_body() {
    let (noetl, seen) = mock_noetl().await;
    let gw = gateway(&noetl, Some(user(Some(CALLER)))).await;
    let status = reqwest::Client::new()
        .post(format!("{gw}/noetl/execute"))
        .json(&json!({"path": "muno/playbooks/profile", "payload": {"uid": VICTIM, "profile": {}}}))
        .send()
        .await
        .unwrap()
        .status();
    assert!(status.is_success(), "{status}");
    assert_eq!(workload(&seen, 0)["uid"], CALLER);
}

#[tokio::test]
async fn proxy_batch_runs_every_item_as_the_caller() {
    let (noetl, seen) = mock_noetl().await;
    let gw = gateway(&noetl, Some(user(Some(CALLER)))).await;
    reqwest::Client::new()
        .post(format!("{gw}/noetl/execute/batch"))
        .json(&json!({"executions": [
            {"path": "a", "payload": {"uid": VICTIM}},
            {"path": "b", "workload": {"user_uid": VICTIM}}
        ]}))
        .send()
        .await
        .unwrap();
    let (_, body) = seen.lock().unwrap()[0].clone();
    assert_eq!(body["executions"][0]["payload"]["uid"], CALLER);
    assert_eq!(body["executions"][1]["workload"]["user_uid"], CALLER);
}

#[tokio::test]
async fn proxy_execute_without_a_session_subject_is_forbidden_and_nothing_runs() {
    let (noetl, seen) = mock_noetl().await;
    let gw = gateway(&noetl, Some(user(None))).await;
    let status = reqwest::Client::new()
        .post(format!("{gw}/noetl/execute"))
        .json(&json!({"path": "muno/playbooks/profile", "payload": {"uid": VICTIM}}))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, reqwest::StatusCode::FORBIDDEN);
    assert!(seen.lock().unwrap().is_empty());
}
