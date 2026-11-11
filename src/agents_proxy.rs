//! `/noetl/agents/*`: the gateway in front of noetl-server's agent endpoint
//! (`/api/agents`, interop RFC build plan item 7, noetl/ai-meta#539).
//!
//! Same policy as [`crate::mcp_proxy`] (and `executePlaybook`): a regular user
//! reaches only the agents whose playbook they may start.
//!
//! | Route | Regular user | Admin |
//! |---|---|---|
//! | `GET /noetl/agents` | cards filtered by [`Policy::may_execute`]; `not_served` removed | everything |
//! | `GET /noetl/agents/cards/{*path}` | 404 unless they may start `path` | forwarded |
//! | `POST /noetl/agents/send` | 404 unless they may start `agent`; `input` identity-bound to the session; `callback_url` refused (403) | identity-bound; callbacks allowed |
//! | `GET /noetl/agents/tasks/{id}` | only a task they started ([`ExecutionOwners`]), else 404 | forwarded |
//!
//! A refused agent answers exactly like a missing one (404 "no such agent"), so
//! the listing cannot be probed. The task id is the server's execution id; the
//! gateway records the caller as its owner when the send is accepted, which is
//! also what lets the same user read it through `GET /noetl/executions/{id}`.
//!
//! Callbacks are admin-only here: a callback makes the server POST a result to
//! a URL, and which origins are acceptable is an operator decision
//! (`NOETL_AGENT_CALLBACK_ORIGINS` on the server). A regular user polls.
//!
//! Mounted only when `GATEWAY_AGENTS_PROXY=true` (strict). Unset, `/noetl/agents/*`
//! keeps its generic-proxy behaviour: admins forwarded, everyone else 403.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, Request, Response, StatusCode},
};
use serde_json::{json, Value};

use crate::auth::types::UserContext;
use crate::authorization::Policy;
use crate::proxy::ProxyState;

/// The arming flag. Strict `== "true"`.
pub const AGENTS_PROXY_ENV: &str = "GATEWAY_AGENTS_PROXY";

pub fn agents_proxy_enabled() -> bool {
    agents_proxy_enabled_from(|k| std::env::var(k).ok())
}

pub fn agents_proxy_enabled_from(get: impl Fn(&str) -> Option<String>) -> bool {
    get(AGENTS_PROXY_ENV).as_deref() == Some("true")
}

/// Same cap as the server's endpoint.
const MAX_BODY_BYTES: usize = 1024 * 1024;

fn json_response(status: StatusCode, v: &Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(v.to_string()))
        .unwrap()
}

fn error(status: StatusCode, message: &str) -> Response<Body> {
    json_response(status, &json!({"error": message}))
}

fn no_such_agent() -> Response<Body> {
    error(StatusCode::NOT_FOUND, "no such agent")
}

fn no_such_task() -> Response<Body> {
    error(StatusCode::NOT_FOUND, "no such task")
}

fn bad_gateway(e: &str) -> Response<Body> {
    tracing::error!("agents upstream request failed: {}", e);
    error(StatusCode::BAD_GATEWAY, "upstream agent request failed")
}

/// Remove from a `GET /api/agents` reply every card whose playbook (`agent`)
/// `user` may not start, and the author diagnostics.
pub fn filter_cards(policy: &Policy, user: &UserContext, reply: &mut Value) {
    if let Some(cards) = reply.get_mut("agents").and_then(Value::as_array_mut) {
        cards.retain(|c| {
            c.get("agent")
                .and_then(Value::as_str)
                .is_some_and(|p| policy.may_execute(user, p.trim_matches('/'), "playbook"))
        });
    }
    if let Some(m) = reply.as_object_mut() {
        m.remove("not_served");
    }
}

fn task_id_ok(id: &str) -> bool {
    !id.is_empty() && id.len() <= 20 && id.bytes().all(|b| b.is_ascii_digit())
}

fn upstream_url(state: &ProxyState, tail: &str) -> String {
    format!("{}/api/agents{}", state.noetl_base_url.trim_end_matches('/'), tail)
}

/// Relay an upstream response: status, JSON body.
async fn relay(resp: Result<reqwest::Response, reqwest::Error>) -> Response<Body> {
    match resp {
        Ok(r) => {
            let status = StatusCode::from_u16(r.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            match r.bytes().await {
                Ok(b) => Response::builder()
                    .status(status)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(b.to_vec()))
                    .unwrap(),
                Err(e) => bad_gateway(&e.to_string()),
            }
        }
        Err(e) => bad_gateway(&e.to_string()),
    }
}

fn caller(req: &Request<Body>) -> Option<UserContext> {
    req.extensions().get::<UserContext>().cloned()
}

fn denied() -> Response<Body> {
    crate::ingress::record_route_authz("denied");
    error(StatusCode::FORBIDDEN, "not authorized")
}

/// `GET /noetl/agents`.
pub async fn list(State(state): State<Arc<ProxyState>>, req: Request<Body>) -> Response<Body> {
    let Some(user) = caller(&req) else { return denied() };
    let admin = state.policy.is_admin(&user);
    crate::ingress::record_route_authz(if admin { "admin" } else { "user_allowed" });
    let resp = match state.http_client.get(upstream_url(&state, "")).send().await {
        Ok(r) => r,
        Err(e) => return bad_gateway(&e.to_string()),
    };
    if admin {
        return relay(Ok(resp)).await;
    }
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let Ok(mut reply) = resp.json::<Value>().await else {
        return bad_gateway("upstream reply was not JSON");
    };
    filter_cards(&state.policy, &user, &mut reply);
    json_response(status, &reply)
}

/// `GET /noetl/agents/cards/{*path}`.
pub async fn card(
    State(state): State<Arc<ProxyState>>,
    Path(path): Path<String>,
    req: Request<Body>,
) -> Response<Body> {
    let Some(user) = caller(&req) else { return denied() };
    let path = path.trim_matches('/').to_string();
    if !state.policy.is_admin(&user) {
        if !state.policy.may_execute(&user, &path, "playbook") {
            crate::ingress::record_route_authz("denied");
            return no_such_agent();
        }
        crate::ingress::record_route_authz("user_allowed");
    } else {
        crate::ingress::record_route_authz("admin");
    }
    relay(
        state
            .http_client
            .get(upstream_url(&state, &format!("/cards/{path}")))
            .send()
            .await,
    )
    .await
}

/// `POST /noetl/agents/send`.
pub async fn send(State(state): State<Arc<ProxyState>>, req: Request<Body>) -> Response<Body> {
    let Some(user) = caller(&req) else { return denied() };
    let bytes = match axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => return error(StatusCode::PAYLOAD_TOO_LARGE, "request body too large"),
    };
    let Ok(mut body) = serde_json::from_slice::<Value>(&bytes) else {
        return error(StatusCode::BAD_REQUEST, "body must be a JSON object");
    };
    let Some(agent) = body.get("agent").and_then(Value::as_str).map(|a| a.trim_matches('/').to_string()) else {
        return error(StatusCode::BAD_REQUEST, "`agent` (the playbook path) is required");
    };
    let admin = state.policy.is_admin(&user);
    if !admin {
        if !state.policy.may_execute(&user, &agent, "playbook") {
            crate::ingress::record_route_authz("denied");
            tracing::warn!(user_id = user.user_id, agent = %agent, "agent send refused");
            return no_such_agent();
        }
        if body.get("callback_url").is_some_and(|v| !v.is_null()) {
            crate::ingress::record_route_authz("denied");
            return error(
                StatusCode::FORBIDDEN,
                "callback_url is for administrators; poll GET /noetl/agents/tasks/{task_id}",
            );
        }
        crate::ingress::record_route_authz("user_allowed");
    } else {
        crate::ingress::record_route_authz("admin");
    }
    // Identity variables come from the session, never from the caller.
    if let Some(input) = body.get_mut("input") {
        let subject = user.auth0_sub.as_deref();
        let bypass = crate::auth::middleware::is_auth_bypass_enabled();
        if let Err(e) = crate::identity::bind_identity(input, subject, bypass) {
            return error(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string());
        }
    }
    let resp = match state
        .http_client
        .post(upstream_url(&state, "/send"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.to_string())
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return bad_gateway(&e.to_string()),
    };
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let reply: Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => return bad_gateway(&e.to_string()),
    };
    if status.is_success() {
        if let Some(id) = reply.get("task_id").and_then(Value::as_str) {
            crate::authorization::record_owner(state.owners.as_ref(), id, Some(&user)).await;
        }
    }
    json_response(status, &reply)
}

/// `GET /noetl/agents/tasks/{id}`.
pub async fn task(
    State(state): State<Arc<ProxyState>>,
    Path(id): Path<String>,
    req: Request<Body>,
) -> Response<Body> {
    let Some(user) = caller(&req) else { return denied() };
    if !task_id_ok(&id) {
        return error(StatusCode::BAD_REQUEST, "task_id must be a positive integer");
    }
    if !state.policy.is_admin(&user) {
        let Some(owners) = state.owners.as_ref() else {
            crate::ingress::record_route_authz("owner_unverifiable");
            return error(StatusCode::SERVICE_UNAVAILABLE, "task ownership cannot be verified");
        };
        match owners.is_owner(&id, &user).await {
            Ok(true) => crate::ingress::record_route_authz("user_allowed"),
            Ok(false) => {
                crate::ingress::record_route_authz("not_owner");
                return no_such_task();
            }
            Err(e) => {
                crate::ingress::record_route_authz("owner_unverifiable");
                tracing::error!("task owner lookup failed: {}", e);
                return error(StatusCode::SERVICE_UNAVAILABLE, "task ownership cannot be verified");
            }
        }
    } else {
        crate::ingress::record_route_authz("admin");
    }
    relay(
        state
            .http_client
            .get(upstream_url(&state, &format!("/tasks/{id}")))
            .send()
            .await,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::ExecutionOwners;
    use axum::{
        extract::{OriginalUri, State as S},
        routing::{get, post},
        Extension, Router,
    };
    use std::sync::Mutex;

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

    fn policy() -> Policy {
        Policy {
            user_playbooks: vec!["public/agents/helper".into()],
            ..Policy::default()
        }
    }

    fn cards_reply() -> Value {
        json!({
            "agents": [
                {"name": "helper", "agent": "public/agents/helper"},
                {"name": "ops", "agent": "ops/agents/admin"},
                {"name": "nameless"},
            ],
            "not_served": [{"source": "ops/broken", "reason": "x"}],
        })
    }

    #[test]
    fn flag_is_strict() {
        assert!(agents_proxy_enabled_from(|_| Some("true".into())));
        assert!(!agents_proxy_enabled_from(|_| Some("yes".into())));
        assert!(!agents_proxy_enabled_from(|_| None));
    }

    #[test]
    fn cards_keep_only_what_the_caller_may_start() {
        let mut r = cards_reply();
        filter_cards(&policy(), &user(1), &mut r);
        assert_eq!(r["agents"], json!([{"name": "helper", "agent": "public/agents/helper"}]));
        assert!(r.get("not_served").is_none());
    }

    #[test]
    fn task_ids_are_digits() {
        assert!(task_id_ok("123"));
        assert!(!task_id_ok("1 OR 1"));
        assert!(!task_id_ok(""));
    }

    // ---- end to end against a mock server ----

    #[derive(Clone, Default)]
    struct Mock {
        calls: Arc<Mutex<Vec<(String, Value)>>>,
    }

    async fn up_get(S(m): S<Mock>, OriginalUri(uri): OriginalUri) -> axum::Json<Value> {
        let path = uri.path().to_string();
        m.calls.lock().unwrap().push((format!("GET {path}"), Value::Null));
        axum::Json(match path.as_str() {
            "/api/agents" => cards_reply(),
            p if p.starts_with("/api/agents/cards/") => json!({"agent": p.trim_start_matches("/api/agents/cards/")}),
            p => json!({"task_id": p.trim_start_matches("/api/agents/tasks/"), "status": "completed"}),
        })
    }

    async fn up_send(S(m): S<Mock>, axum::Json(body): axum::Json<Value>) -> (StatusCode, axum::Json<Value>) {
        m.calls.lock().unwrap().push(("POST /api/agents/send".into(), body.clone()));
        (
            StatusCode::ACCEPTED,
            axum::Json(json!({"task_id": "555", "agent": body["agent"], "status": "submitted", "echo": body["input"]})),
        )
    }

    async fn setup(caller: UserContext) -> (String, Mock, Arc<ExecutionOwners>) {
        let mock = Mock::default();
        let up = Router::new()
            .route("/api/agents", get(up_get))
            .route("/api/agents/cards/{*p}", get(up_get))
            .route("/api/agents/tasks/{id}", get(up_get))
            .route("/api/agents/send", post(up_send))
            .with_state(mock.clone());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, up).await.unwrap() });

        let owners = Arc::new(ExecutionOwners::in_memory());
        let state = Arc::new(
            ProxyState::new(format!("http://{up_addr}")).with_authorization(Arc::new(policy()), Some(owners.clone())),
        );
        // Beside the generic catch-all, as in `main`: the specific routes must win.
        let app = Router::new()
            .route("/noetl/agents", get(list))
            .route("/noetl/agents/cards/{*path}", get(card))
            .route("/noetl/agents/send", post(send))
            .route("/noetl/agents/tasks/{id}", get(task))
            .route(
                "/noetl/{*path}",
                get(|| async { (StatusCode::IM_A_TEAPOT, "generic proxy") })
                    .post(|| async { (StatusCode::IM_A_TEAPOT, "generic proxy") }),
            )
            .with_state(state)
            .layer(Extension(caller));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (format!("http://{addr}"), mock, owners)
    }

    async fn get_json(url: String) -> (u16, Value) {
        let r = reqwest::get(url).await.unwrap();
        let s = r.status().as_u16();
        (s, r.json().await.unwrap_or(Value::Null))
    }

    async fn post_json(url: String, body: Value) -> (u16, Value) {
        let r = reqwest::Client::new().post(url).json(&body).send().await.unwrap();
        let s = r.status().as_u16();
        (s, r.json().await.unwrap_or(Value::Null))
    }

    #[tokio::test]
    async fn regular_user_lists_reads_and_sends_only_allowed_agents() {
        let (gw, mock, owners) = setup(user(1)).await;
        let (s, cards) = get_json(format!("{gw}/noetl/agents")).await;
        assert_eq!(s, 200);
        assert_eq!(cards["agents"].as_array().unwrap().len(), 1, "{cards}");
        assert!(cards.get("not_served").is_none());

        assert_eq!(get_json(format!("{gw}/noetl/agents/cards/public/agents/helper")).await.0, 200);
        let before = mock.calls.lock().unwrap().len();
        let (s, e) = get_json(format!("{gw}/noetl/agents/cards/ops/agents/admin")).await;
        assert_eq!((s, e["error"].as_str()), (404, Some("no such agent")));

        // Allowed send: identity bound, owner recorded.
        let (s, sent) = post_json(
            format!("{gw}/noetl/agents/send"),
            json!({"agent": "public/agents/helper", "input": {"q": "hi", "uid": "someone-else"}}),
        )
        .await;
        assert_eq!(s, 202, "{sent}");
        assert_eq!(sent["echo"]["uid"], "auth0|user1");
        assert!(owners.is_owner("555", &user(1)).await.unwrap());

        // Refused send: looks like a missing agent; never reaches the server.
        let (s, _) = post_json(format!("{gw}/noetl/agents/send"), json!({"agent": "ops/agents/admin", "input": {}})).await;
        assert_eq!(s, 404);
        // Callbacks are admin-only.
        let (s, e) = post_json(
            format!("{gw}/noetl/agents/send"),
            json!({"agent": "public/agents/helper", "input": {}, "callback_url": "https://hooks.example.invalid/x"}),
        )
        .await;
        assert_eq!(s, 403, "{e}");
        let sends = mock.calls.lock().unwrap()[before..]
            .iter()
            .filter(|(k, _)| k.starts_with("POST"))
            .count();
        assert_eq!(sends, 1, "only the allowed send went upstream");
    }

    #[tokio::test]
    async fn tasks_are_owner_only_for_regular_users() {
        let (gw, mock, owners) = setup(user(1)).await;
        owners.record("777", &user(1)).await.unwrap();
        owners.record("888", &user(2)).await.unwrap();
        let (s, mine) = get_json(format!("{gw}/noetl/agents/tasks/777")).await;
        assert_eq!((s, mine["status"].as_str()), (200, Some("completed")));
        let before = mock.calls.lock().unwrap().len();
        assert_eq!(get_json(format!("{gw}/noetl/agents/tasks/888")).await.0, 404);
        assert_eq!(get_json(format!("{gw}/noetl/agents/tasks/999")).await.0, 404);
        assert_eq!(get_json(format!("{gw}/noetl/agents/tasks/1%20OR%201")).await.0, 400);
        assert_eq!(mock.calls.lock().unwrap().len(), before, "refused reads never reach the server");
    }

    #[tokio::test]
    async fn admin_sees_everything_and_may_set_callbacks() {
        let (gw, _, _) = setup(admin()).await;
        let (_, cards) = get_json(format!("{gw}/noetl/agents")).await;
        assert_eq!(cards["agents"].as_array().unwrap().len(), 3);
        assert!(cards["not_served"].is_array());
        let (s, sent) = post_json(
            format!("{gw}/noetl/agents/send"),
            json!({"agent": "ops/agents/admin", "input": {"uid": "x"}, "callback_url": "https://hooks.example.invalid/x"}),
        )
        .await;
        assert_eq!(s, 202);
        assert_eq!(sent["echo"]["uid"], "auth0|user99", "admins are bound too");
        assert_eq!(get_json(format!("{gw}/noetl/agents/tasks/123")).await.0, 200);
    }
}
