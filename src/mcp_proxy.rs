//! `/noetl/mcp` and `/noetl/mcp/{*server}`: the gateway in front of
//! noetl-server's playbook MCP endpoint (`/api/mcp`, interop RFC Phase 5,
//! noetl/ai-meta#539).
//!
//! The generic proxy (`crate::proxy`) forwards `/noetl/mcp` for admins and
//! refuses it for everyone else, because it cannot see inside a JSON-RPC body.
//! This route can, so it lets a regular user use MCP under the same policy as
//! `executePlaybook`:
//!
//! - `tools/list`: tools whose playbook the caller may not start
//!   ([`Policy::may_execute`]) are removed from the answer. A tool that does not
//!   name its playbook (`_meta["noetl/playbook"]`) is removed too: fail closed.
//! - `tools/call` on a playbook tool: the tool is resolved to its playbook with an
//!   upstream `tools/list`, and the call is refused as an unknown tool unless the
//!   caller may start it (a hidden tool and a missing one look the same). The
//!   arguments get the same identity binding as every execution the gateway
//!   starts ([`crate::identity::bind_identity`]). The execution the call started
//!   is recorded as the caller's ([`ExecutionOwners`]).
//! - `tools/call` on a helper (`noetl.execution.status` / `.result` / `.cancel`):
//!   only for an execution the caller started, as with `GET /noetl/executions/{id}`.
//! - Everything else (`initialize`, `ping`, notifications, unparseable bodies) is
//!   forwarded unchanged: none of it starts or reads an execution.
//!
//! Admins pass through with identity binding and owner recording only.
//!
//! Mounted only when `GATEWAY_MCP_PROXY=true` (strict). Unset, `/noetl/mcp` keeps
//! its generic-proxy behaviour: admins forwarded, everyone else 403.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, Request, Response, StatusCode},
};
use serde_json::{json, Value};

use crate::auth::types::UserContext;
use crate::authorization::{ExecutionOwners, Policy};
use crate::proxy::ProxyState;

/// The arming flag. Strict `== "true"`.
pub const MCP_PROXY_ENV: &str = "GATEWAY_MCP_PROXY";

pub fn mcp_proxy_enabled() -> bool {
    mcp_proxy_enabled_from(|k| std::env::var(k).ok())
}

pub fn mcp_proxy_enabled_from(get: impl Fn(&str) -> Option<String>) -> bool {
    get(MCP_PROXY_ENV).as_deref() == Some("true")
}

/// Same cap as the server's endpoint: one JSON-RPC message.
const MAX_BODY_BYTES: usize = 1024 * 1024;
const HELPER_PREFIX: &str = "noetl.";
const PLAYBOOK_META: &str = "noetl/playbook";
const EXECUTION_META: &str = "noetl/execution_id";
const INVALID_PARAMS: i64 = -32602;
const INTERNAL_ERROR: i64 = -32603;
/// Implementation-defined server error: a guest's run limit (HTTP 429, `Retry-After`).
const RATE_LIMITED: i64 = -32000;

fn rpc_error(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn json_response(status: StatusCode, v: &Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(v.to_string()))
        .unwrap()
}

/// Remove from a `tools/list` reply every tool `user` may not start. Helpers
/// stay: they are owner-checked per call.
pub fn filter_tools_list(policy: &Policy, user: &UserContext, reply: &mut Value) {
    let Some(tools) = reply.pointer_mut("/result/tools").and_then(Value::as_array_mut) else {
        return;
    };
    tools.retain(|t| {
        let name = t.get("name").and_then(Value::as_str).unwrap_or("");
        if name.starts_with(HELPER_PREFIX) {
            return true;
        }
        t.pointer(&format!("/_meta/{}", PLAYBOOK_META.replace('/', "~1")))
            .and_then(Value::as_str)
            .is_some_and(|p| policy.may_execute(user, p, "playbook"))
    });
    // `noetl/not_served` names playbooks and why they are broken: author
    // diagnostics, not for a regular user.
    if let Some(meta) = reply.pointer_mut("/result/_meta").and_then(Value::as_object_mut) {
        meta.remove("noetl/not_served");
    }
}

/// The playbook a tool runs, from a `tools/list` reply.
pub fn tool_playbook(list_reply: &Value, tool: &str) -> Option<String> {
    list_reply
        .pointer("/result/tools")?
        .as_array()?
        .iter()
        .find(|t| t.get("name").and_then(Value::as_str) == Some(tool))?
        .pointer(&format!("/_meta/{}", PLAYBOOK_META.replace('/', "~1")))?
        .as_str()
        .map(str::to_string)
}

/// The execution a `tools/call` reply reports having started.
pub fn started_execution(reply: &Value) -> Option<String> {
    reply
        .pointer(&format!("/result/_meta/{}", EXECUTION_META.replace('/', "~1")))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn helper_execution_id(args: Option<&Value>) -> Option<String> {
    match args?.get("execution_id")? {
        Value::String(s) => Some(s.trim().to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
    .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
}

struct Upstream<'a> {
    state: &'a ProxyState,
    url: String,
    accept: Option<String>,
}

impl Upstream<'_> {
    async fn post(&self, body: &Value) -> Result<(StatusCode, Vec<u8>), String> {
        let mut req = self
            .state
            .http_client
            .post(&self.url)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.to_string());
        if let Some(a) = &self.accept {
            req = req.header(header::ACCEPT, a);
        }
        let resp = req.send().await.map_err(|e| e.to_string())?;
        let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
        let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
        Ok((status, bytes.to_vec()))
    }

    async fn post_json(&self, body: &Value) -> Result<(StatusCode, Option<Value>), String> {
        let (status, bytes) = self.post(body).await?;
        Ok((status, serde_json::from_slice(&bytes).ok()))
    }

    /// Forward `body` and relay the reply verbatim.
    async fn relay(&self, body: &Value) -> Response<Body> {
        match self.post(body).await {
            Ok((status, bytes)) => {
                let mut b = Response::builder().status(status);
                if !bytes.is_empty() {
                    b = b.header(header::CONTENT_TYPE, "application/json");
                }
                b.body(Body::from(bytes)).unwrap()
            }
            Err(e) => bad_gateway(&e),
        }
    }
}

fn bad_gateway(e: &str) -> Response<Body> {
    tracing::error!("MCP upstream request failed: {}", e);
    json_response(StatusCode::BAD_GATEWAY, &json!({"error": "upstream MCP request failed"}))
}

async fn record(owners: Option<&Arc<ExecutionOwners>>, reply: &Value, user: &UserContext) {
    if let Some(id) = started_execution(reply) {
        crate::authorization::record_owner(owners, &id, Some(user)).await;
    }
}

/// `POST /noetl/mcp`.
pub async fn mcp_root(State(state): State<Arc<ProxyState>>, req: Request<Body>) -> Response<Body> {
    handle(&state, None, req).await
}

/// `POST /noetl/mcp/{*server}`.
pub async fn mcp_named(
    State(state): State<Arc<ProxyState>>,
    Path(server): Path<String>,
    req: Request<Body>,
) -> Response<Body> {
    handle(&state, Some(server), req).await
}

async fn handle(state: &ProxyState, server: Option<String>, req: Request<Body>) -> Response<Body> {
    let (parts, body) = req.into_parts();
    let Some(user) = parts.extensions.get::<UserContext>().cloned() else {
        crate::ingress::record_route_authz("denied");
        return json_response(StatusCode::FORBIDDEN, &json!({"error": "not authorized"}));
    };
    let bytes = match axum::body::to_bytes(body, MAX_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => return json_response(StatusCode::PAYLOAD_TOO_LARGE, &json!({"error": "request body too large"})),
    };
    let path = match &server {
        Some(s) => format!("mcp/{}", s.trim_matches('/')),
        None => "mcp".to_string(),
    };
    let upstream = Upstream {
        state,
        url: format!("{}/api/{}", state.noetl_base_url.trim_end_matches('/'), path),
        accept: parts
            .headers
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string),
    };

    let Ok(mut message) = serde_json::from_slice::<Value>(&bytes) else {
        // Not JSON: the server answers -32700, and nothing can start.
        return match upstream
            .state
            .http_client
            .post(&upstream.url)
            .header(header::CONTENT_TYPE, "application/json")
            .body(bytes.to_vec())
            .send()
            .await
        {
            Ok(r) => {
                let status = StatusCode::from_u16(r.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
                let b = r.bytes().await.unwrap_or_default();
                Response::builder()
                    .status(status)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(b.to_vec()))
                    .unwrap()
            }
            Err(e) => bad_gateway(&e.to_string()),
        };
    };

    let admin = state.policy.is_admin(&user);
    let id = message.get("id").cloned().unwrap_or(Value::Null);
    let method = message.get("method").and_then(Value::as_str).unwrap_or("").to_string();

    match method.as_str() {
        "tools/list" => {
            crate::ingress::record_route_authz(if admin { "admin" } else { "user_allowed" });
            let (status, reply) = match upstream.post_json(&message).await {
                Ok(r) => r,
                Err(e) => return bad_gateway(&e),
            };
            let Some(mut reply) = reply else {
                return json_response(status, &rpc_error(&id, INTERNAL_ERROR, "upstream reply was not JSON"));
            };
            if !admin {
                filter_tools_list(&state.policy, &user, &mut reply);
            }
            json_response(status, &reply)
        }
        "tools/call" => {
            let name = message
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if name.starts_with(HELPER_PREFIX) {
                if !admin {
                    let Some(exec_id) = helper_execution_id(message.pointer("/params/arguments")) else {
                        // The server explains a missing id; nothing can be read.
                        return upstream.relay(&message).await;
                    };
                    let Some(owners) = state.owners.as_ref() else {
                        crate::ingress::record_route_authz("owner_unverifiable");
                        return json_response(
                            StatusCode::OK,
                            &rpc_error(&id, INTERNAL_ERROR, "execution ownership cannot be verified"),
                        );
                    };
                    match owners.is_owner(&exec_id, &user).await {
                        Ok(true) => crate::ingress::record_route_authz("user_allowed"),
                        Ok(false) => {
                            crate::ingress::record_route_authz("not_owner");
                            return json_response(StatusCode::OK, &rpc_error(&id, INVALID_PARAMS, "execution not found"));
                        }
                        Err(e) => {
                            crate::ingress::record_route_authz("owner_unverifiable");
                            tracing::error!("execution owner lookup failed: {}", e);
                            return json_response(
                                StatusCode::OK,
                                &rpc_error(&id, INTERNAL_ERROR, "execution ownership cannot be verified"),
                            );
                        }
                    }
                } else {
                    crate::ingress::record_route_authz("admin");
                }
                return upstream.relay(&message).await;
            }

            if !admin {
                let list = json!({"jsonrpc": "2.0", "id": "gateway-resolve", "method": "tools/list"});
                let playbook = match upstream.post_json(&list).await {
                    Ok((_, Some(reply))) => tool_playbook(&reply, &name),
                    Ok((status, None)) => {
                        return json_response(status, &rpc_error(&id, INTERNAL_ERROR, "upstream reply was not JSON"))
                    }
                    Err(e) => return bad_gateway(&e),
                };
                let allowed = playbook
                    .as_deref()
                    .is_some_and(|p| state.policy.may_execute(&user, p, "playbook"));
                if !allowed {
                    crate::ingress::record_route_authz("denied");
                    tracing::warn!(user_id = user.user_id, tool = %name, "MCP tool call refused");
                    // The same answer as a tool that does not exist.
                    return json_response(
                        StatusCode::OK,
                        &rpc_error(&id, INVALID_PARAMS, &format!("unknown tool `{name}`")),
                    );
                }
                // A guest's tools/call starts an execution: it counts against the
                // same per-guest / per-IP / total run limits as executePlaybook
                // and an agent send.
                if let Some(guest) = user.guest.as_ref() {
                    let Some(guests) = state.guests.as_ref() else {
                        crate::ingress::record_route_authz("denied");
                        return json_response(StatusCode::FORBIDDEN, &json!({"error": "not authorized"}));
                    };
                    let playbook = playbook.as_deref().unwrap_or_default();
                    if let Err(crate::guest::RateLimited(wait)) = guests.admit_run(guest, playbook) {
                        crate::ingress::record_route_authz("guest_rate_limited");
                        tracing::debug!(retry_after = wait, tool = %name, "guest MCP tools/call refused: rate limit");
                        let mut body = rpc_error(&id, RATE_LIMITED, "Too many requests; try again later");
                        body["error"]["data"] = json!({"retryAfter": wait});
                        let mut r = json_response(StatusCode::TOO_MANY_REQUESTS, &body);
                        r.headers_mut().insert(header::RETRY_AFTER, wait.to_string().parse().unwrap());
                        return r;
                    }
                }
                crate::ingress::record_route_authz("user_allowed");
            } else {
                crate::ingress::record_route_authz("admin");
            }

            // Identity variables come from the session, never from the caller.
            if let Some(args) = message.pointer_mut("/params/arguments") {
                let subject = user.auth0_sub.as_deref();
                let bypass = crate::auth::middleware::is_auth_bypass_enabled();
                if let Err(e) = crate::identity::bind_identity(args, subject, bypass) {
                    return json_response(StatusCode::OK, &rpc_error(&id, INVALID_PARAMS, &e.to_string()));
                }
            }

            let (status, reply) = match upstream.post_json(&message).await {
                Ok(r) => r,
                Err(e) => return bad_gateway(&e),
            };
            let Some(reply) = reply else {
                return json_response(status, &rpc_error(&id, INTERNAL_ERROR, "upstream reply was not JSON"));
            };
            record(state.owners.as_ref(), &reply, &user).await;
            json_response(status, &reply)
        }
        _ => upstream.relay(&message).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::State as S, routing::post, Extension, Router};
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
            user_playbooks: vec!["public/tools/findings".into()],
            ..Policy::default()
        }
    }

    fn tools_list_reply() -> Value {
        json!({"jsonrpc": "2.0", "id": 1, "result": {
            "tools": [
                {"name": "findings", "_meta": {"noetl/playbook": "public/tools/findings"}},
                {"name": "admin_report", "_meta": {"noetl/playbook": "ops/admin_report"}},
                {"name": "untagged"},
                {"name": "noetl.execution.status"},
            ],
            "_meta": {"noetl/not_served": [{"source": "ops/broken", "reason": "x"}]},
        }})
    }

    #[test]
    fn flag_is_strict() {
        assert!(mcp_proxy_enabled_from(|_| Some("true".into())));
        assert!(!mcp_proxy_enabled_from(|_| Some("1".into())));
        assert!(!mcp_proxy_enabled_from(|_| None));
    }

    #[test]
    fn tools_list_keeps_only_what_the_caller_may_start() {
        let mut reply = tools_list_reply();
        filter_tools_list(&policy(), &user(1), &mut reply);
        let names: Vec<&str> = reply["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["findings", "noetl.execution.status"]);
        assert!(reply["result"]["_meta"].get("noetl/not_served").is_none());
    }

    #[test]
    fn reply_helpers() {
        assert_eq!(tool_playbook(&tools_list_reply(), "admin_report").as_deref(), Some("ops/admin_report"));
        assert_eq!(tool_playbook(&tools_list_reply(), "untagged"), None);
        let r = json!({"result": {"_meta": {"noetl/execution_id": "42"}}});
        assert_eq!(started_execution(&r).as_deref(), Some("42"));
        assert_eq!(helper_execution_id(Some(&json!({"execution_id": "12"}))).as_deref(), Some("12"));
        assert_eq!(helper_execution_id(Some(&json!({"execution_id": "1 OR 1"}))), None);
    }

    // ---- end to end against a mock server ----

    #[derive(Clone, Default)]
    struct Mock {
        calls: Arc<Mutex<Vec<Value>>>,
    }

    async fn upstream(S(m): S<Mock>, axum::Json(body): axum::Json<Value>) -> axum::Json<Value> {
        m.calls.lock().unwrap().push(body.clone());
        let id = body.get("id").cloned().unwrap_or(Value::Null);
        match body.get("method").and_then(Value::as_str) {
            Some("tools/list") => {
                let mut r = tools_list_reply();
                r["id"] = id;
                axum::Json(r)
            }
            Some("tools/call") => axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": {
                "content": [{"type": "text", "text": "{}"}], "isError": false,
                "_meta": {"noetl/execution_id": "777"},
                "echo": body["params"]["arguments"],
            }})),
            _ => axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": {}})),
        }
    }

    async fn setup(caller: UserContext) -> (String, Mock, Arc<ExecutionOwners>) {
        setup_with(caller, None, policy()).await
    }

    async fn setup_with(
        caller: UserContext,
        guests: Option<Arc<crate::guest::GuestSessions>>,
        pol: Policy,
    ) -> (String, Mock, Arc<ExecutionOwners>) {
        let mock = Mock::default();
        let up = Router::new().route("/api/{*rest}", post(upstream)).with_state(mock.clone());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, up).await.unwrap() });

        let owners = Arc::new(ExecutionOwners::in_memory());
        let state = Arc::new(
            ProxyState::new(format!("http://{up_addr}"))
                .with_authorization(Arc::new(pol), Some(owners.clone()))
                .with_guests(guests),
        );
        // Mounted beside the generic catch-all exactly as `main` does, so the
        // test also proves the specific route wins.
        let app = Router::new()
            .route("/noetl/mcp", post(mcp_root))
            .route("/noetl/mcp/{*server}", post(mcp_named))
            .route(
                "/noetl/{*path}",
                post(|| async { (StatusCode::IM_A_TEAPOT, "generic proxy") }),
            )
            .with_state(state)
            .layer(Extension(caller));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (format!("http://{addr}"), mock, owners)
    }

    async fn rpc(gw: &str, path: &str, method: &str, params: Value) -> (u16, Value) {
        let r = reqwest::Client::new()
            .post(format!("{gw}{path}"))
            .json(&json!({"jsonrpc": "2.0", "id": 5, "method": method, "params": params}))
            .send()
            .await
            .unwrap();
        let status = r.status().as_u16();
        (status, r.json().await.unwrap_or(Value::Null))
    }

    #[tokio::test]
    async fn regular_user_sees_and_calls_only_allowed_tools() {
        let (gw, mock, owners) = setup(user(1)).await;

        let (s, list) = rpc(&gw, "/noetl/mcp", "tools/list", json!({})).await;
        assert_eq!(s, 200);
        assert_eq!(list["result"]["tools"].as_array().unwrap().len(), 2);

        // Allowed: forwarded with the identity bound to the session, owner recorded.
        let (_, ok) = rpc(&gw, "/noetl/mcp", "tools/call",
            json!({"name": "findings", "arguments": {"minutes": 5, "uid": "someone-else"}})).await;
        assert_eq!(ok["result"]["echo"]["uid"], "auth0|user1", "{ok}");
        assert_eq!(ok["result"]["echo"]["minutes"], 5);
        assert!(owners.is_owner("777", &user(1)).await.unwrap());
        assert!(!owners.is_owner("777", &user(2)).await.unwrap());

        // Refused: answered as an unknown tool, and the call never reaches the server.
        let before = mock.calls.lock().unwrap().len();
        let (_, no) = rpc(&gw, "/noetl/mcp", "tools/call", json!({"name": "admin_report", "arguments": {}})).await;
        assert_eq!(no["error"]["code"], INVALID_PARAMS);
        assert_eq!(no["error"]["message"], "unknown tool `admin_report`");
        let after: Vec<Value> = mock.calls.lock().unwrap()[before..].to_vec();
        assert!(after.iter().all(|c| c["method"] == "tools/list"), "only the resolve list went upstream: {after:?}");

        // An untagged tool is not callable either.
        let (_, no) = rpc(&gw, "/noetl/mcp", "tools/call", json!({"name": "untagged"})).await;
        assert_eq!(no["error"]["code"], INVALID_PARAMS);
    }

    #[tokio::test]
    async fn helpers_are_owner_only_for_regular_users() {
        let (gw, mock, owners) = setup(user(1)).await;
        owners.record("777", &user(1)).await.unwrap();
        owners.record("888", &user(2)).await.unwrap();

        let (_, mine) = rpc(&gw, "/noetl/mcp", "tools/call",
            json!({"name": "noetl.execution.status", "arguments": {"execution_id": "777"}})).await;
        assert!(mine.get("result").is_some(), "{mine}");

        let before = mock.calls.lock().unwrap().len();
        let (_, theirs) = rpc(&gw, "/noetl/mcp", "tools/call",
            json!({"name": "noetl.execution.result", "arguments": {"execution_id": "888"}})).await;
        assert_eq!(theirs["error"]["message"], "execution not found");
        assert_eq!(mock.calls.lock().unwrap().len(), before, "refused helper never reaches the server");
    }

    #[tokio::test]
    async fn admin_sees_everything_and_named_servers_route_through() {
        let (gw, mock, _) = setup(admin()).await;
        let (_, list) = rpc(&gw, "/noetl/mcp/mcp/qnetmon", "tools/list", json!({})).await;
        assert_eq!(list["result"]["tools"].as_array().unwrap().len(), 4);
        assert!(list["result"]["_meta"]["noetl/not_served"].is_array(), "admins keep the diagnostics");
        let (_, call) = rpc(&gw, "/noetl/mcp", "tools/call",
            json!({"name": "admin_report", "arguments": {"uid": "spoof"}})).await;
        assert_eq!(call["result"]["echo"]["uid"], "auth0|user99", "admins are bound too");
        assert!(mock.calls.lock().unwrap().iter().any(|c| c["method"] == "tools/call"));
    }

    #[tokio::test]
    async fn other_methods_pass_through() {
        let (gw, _, _) = setup(user(1)).await;
        let (s, init) = rpc(&gw, "/noetl/mcp", "initialize", json!({"protocolVersion": "2025-06-18"})).await;
        assert_eq!(s, 200);
        assert_eq!(init["result"], json!({}));
    }

    fn guest(id: &str) -> UserContext {
        UserContext {
            user_id: 0,
            auth0_sub: None,
            guest: Some(crate::guest::Guest {
                id: id.into(),
                ip: "203.0.113.9".into(),
            }),
            ..user(0)
        }
    }

    #[tokio::test]
    async fn a_guest_tool_call_counts_against_the_guest_run_limits() {
        let mut cfg = crate::guest::test_config(&["public/tools/findings"]);
        cfg.runs_per_guest = 1;
        let guests = Arc::new(crate::guest::GuestSessions::new(cfg.clone()));
        let pol = Policy::from_env_with(Some(&cfg), None);
        let g = guest("g-1");
        let (gw, mock, owners) = setup_with(g.clone(), Some(guests), pol).await;

        let (s, ok) = rpc(&gw, "/noetl/mcp", "tools/call", json!({"name": "findings", "arguments": {}})).await;
        assert_eq!(s, 200);
        assert!(ok.get("result").is_some(), "{ok}");
        assert!(owners.is_owner("777", &g).await.unwrap(), "the guest owns the execution");

        let calls_before = mock.calls.lock().unwrap().iter().filter(|c| c["method"] == "tools/call").count();
        let r = reqwest::Client::new()
            .post(format!("{gw}/noetl/mcp"))
            .json(&json!({"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "findings", "arguments": {}}}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 429);
        assert!(r.headers().get("retry-after").is_some());
        let body: Value = r.json().await.unwrap();
        assert_eq!(body["error"]["code"], RATE_LIMITED, "{body}");
        assert!(body["error"]["data"]["retryAfter"].as_u64().is_some());
        let calls_after = mock.calls.lock().unwrap().iter().filter(|c| c["method"] == "tools/call").count();
        assert_eq!(calls_after, calls_before, "the limited call never started an execution");

        // Listing starts nothing and is not counted.
        let (s, _) = rpc(&gw, "/noetl/mcp", "tools/list", json!({})).await;
        assert_eq!(s, 200);
    }

    #[tokio::test]
    async fn a_guest_without_guest_mode_cannot_call_a_tool() {
        let cfg = crate::guest::test_config(&["public/tools/findings"]);
        let (gw, mock, _) = setup_with(guest("g-2"), None, Policy::from_env_with(Some(&cfg), None)).await;
        let r = reqwest::Client::new()
            .post(format!("{gw}/noetl/mcp"))
            .json(&json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "findings"}}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 403);
        assert!(!mock.calls.lock().unwrap().iter().any(|c| c["method"] == "tools/call"));
    }

    #[tokio::test]
    async fn signed_in_users_are_not_guest_limited() {
        let (gw, _, _) = setup(user(1)).await;
        for _ in 0..3 {
            let (s, ok) = rpc(&gw, "/noetl/mcp", "tools/call", json!({"name": "findings", "arguments": {}})).await;
            assert_eq!(s, 200);
            assert!(ok.get("result").is_some(), "{ok}");
        }
    }
}
