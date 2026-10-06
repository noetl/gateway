//! Opt-in, session-authorized application actions. No database access or business rules.
use crate::auth::types::UserContext;
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    routing::post,
    Extension, Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
type Error = (StatusCode, Json<Value>);
fn error(status: StatusCode, code: &str) -> Error {
    (status, Json(json!({"error":code})))
}
fn denied() -> Error {
    error(StatusCode::FORBIDDEN, "action_not_authorized")
}
fn upstream() -> Error {
    error(StatusCode::BAD_GATEWAY, "workflow_service_unavailable")
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Validated gateway user ID -> action name -> immutable catalog ID as decimal string.
    pub bindings: BTreeMap<String, BTreeMap<String, String>>,
}
pub struct ScopedApps {
    config: Config,
    base: String,
    token: String,
    key: Vec<u8>,
    http: reqwest::Client,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    request: serde_json::Map<String, Value>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Poll {
    receipt: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    user: i32,
    session: String,
    action: String,
    catalog: i64,
    execution: String,
    expires: u64,
}

impl ScopedApps {
    pub fn from_env(base: &str) -> anyhow::Result<Option<Arc<Self>>> {
        let Ok(file) = std::env::var("GATEWAY_SCOPED_APPS_FILE") else {
            return Ok(None);
        };
        anyhow::ensure!(
            !crate::auth::middleware::is_auth_bypass_enabled(),
            "Scoped apps forbid auth bypass"
        );
        let config: Config = serde_json::from_str(&std::fs::read_to_string(file)?)?;
        let token = std::env::var("NOETL_INTERNAL_API_TOKEN")?;
        let key = std::env::var("GATEWAY_SCOPED_RECEIPT_KEY")?.into_bytes();
        anyhow::ensure!(
            key.len() >= 32 && !token.is_empty(),
            "Scoped apps require an internal token and receipt key of at least 32 bytes"
        );
        validate_config(&config)?;
        Ok(Some(Arc::new(Self {
            config,
            base: base.trim_end_matches('/').to_owned(),
            token,
            key,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(20))
                .build()?,
        })))
    }
    fn catalog(&self, user: &UserContext, action: &str) -> Result<i64, Error> {
        if user.user_id <= 0 || crate::auth::middleware::is_auth_bypass_enabled() {
            return Err(denied());
        }
        self.config
            .bindings
            .get(&user.user_id.to_string())
            .and_then(|m| m.get(action))
            .and_then(|v| v.parse().ok())
            .ok_or_else(denied)
    }
    fn sign(&self, r: &Receipt) -> String {
        let data = URL_SAFE_NO_PAD.encode(serde_json::to_vec(r).expect("receipt serialization"));
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC key");
        mac.update(data.as_bytes());
        format!("{}.{}", data, URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    }
    fn verify(&self, value: &str, user: &UserContext, action: &str) -> Result<Receipt, Error> {
        if value.len() > 4096 {
            return Err(denied());
        }
        let (data, sig) = value.split_once('.').ok_or_else(denied)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).map_err(|_| denied())?;
        mac.update(data.as_bytes());
        mac.verify_slice(&URL_SAFE_NO_PAD.decode(sig).map_err(|_| denied())?)
            .map_err(|_| denied())?;
        let r: Receipt =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(data).map_err(|_| denied())?).map_err(|_| denied())?;
        if r.user != user.user_id
            || r.session != session_digest(user)
            || r.action != action
            || r.catalog != self.catalog(user, action)?
            || r.expires <= now()
            || !decimal_id(&r.execution)
        {
            return Err(denied());
        }
        Ok(r)
    }
}
fn decimal_id(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()) && s.parse::<i64>().is_ok_and(|id| id > 0)
}
fn validate_config(c: &Config) -> anyhow::Result<()> {
    anyhow::ensure!(!c.bindings.is_empty(), "No scoped bindings configured");
    for (user, actions) in &c.bindings {
        anyhow::ensure!(
            user.parse::<i32>().is_ok_and(|id| id > 0) && !actions.is_empty(),
            "Invalid scoped user binding"
        );
        for (action, catalog) in actions {
            anyhow::ensure!(
                !action.is_empty()
                    && action.len() <= 64
                    && action
                        .bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
                    && decimal_id(catalog),
                "Invalid action or catalog ID"
            );
        }
    }
    Ok(())
}
fn session_digest(u: &UserContext) -> String {
    hex::encode(Sha256::digest(u.session_token.as_bytes()))
}
pub fn routes(state: Arc<ScopedApps>) -> Router {
    Router::new()
        .route("/api/scoped/{action}", post(execute))
        .route("/api/scoped/{action}/result", post(result))
        .layer(DefaultBodyLimit::max(32 * 1024))
        .with_state(state)
}
async fn execute(
    State(s): State<Arc<ScopedApps>>,
    Extension(user): Extension<UserContext>,
    Path(action): Path<String>,
    Json(body): Json<Request>,
) -> Result<Json<Value>, Error> {
    let catalog = s.catalog(&user, &action)?;
    let value: Value = s
        .http
        .post(format!("{}/api/execute", s.base))
        .bearer_auth(&s.token)
        .json(&json!({"catalog_id":catalog,"payload":{"request":body.request}}))
        .send()
        .await
        .map_err(|_| upstream())?
        .error_for_status()
        .map_err(|_| upstream())?
        .json()
        .await
        .map_err(|_| upstream())?;
    let id = value
        .get("execution_id")
        .and_then(|v| {
            v.as_str()
                .map(str::to_owned)
                .or_else(|| v.as_i64().map(|n| n.to_string()))
        })
        .filter(|s| decimal_id(s))
        .ok_or_else(upstream)?;
    let receipt = s.sign(&Receipt {
        user: user.user_id,
        session: session_digest(&user),
        action,
        catalog,
        execution: id.clone(),
        expires: now() + 3600,
    });
    Ok(Json(json!({"execution_id":id,"receipt":receipt})))
}
async fn result(
    State(s): State<Arc<ScopedApps>>,
    Extension(user): Extension<UserContext>,
    Path(action): Path<String>,
    Json(body): Json<Poll>,
) -> Result<Json<Value>, Error> {
    let r = s.verify(&body.receipt, &user, &action)?;
    let value: Value = s
        .http
        .get(format!("{}/api/executions/{}", s.base, r.execution))
        .bearer_auth(&s.token)
        .send()
        .await
        .map_err(|_| upstream())?
        .error_for_status()
        .map_err(|_| upstream())?
        .json()
        .await
        .map_err(|_| upstream())?;
    project(&value, r.catalog).map(Json)
}
/// Deliberately support only reviewed one-step PostgreSQL application playbooks.
/// Never forward workload, errors, SQL, event metadata or credential resolutions.
fn project(value: &Value, catalog: i64) -> Result<Value, Error> {
    if value.get("catalog_id").and_then(Value::as_i64) != Some(catalog) {
        return Err(upstream());
    }
    let status = value.get("status").and_then(Value::as_str).ok_or_else(upstream)?;
    match status {
        "FAILED" | "CANCELLED" => Ok(json!({"status":status,"rows":[],"error":"workflow_failed"})),
        "COMPLETED" => {
            let events = value.get("events").and_then(Value::as_array).ok_or_else(upstream)?;
            let event = events
                .iter()
                .find(|e| e["event_type"] == "call.done" && e["node_name"] == "start")
                .ok_or_else(upstream)?;
            let rows = event
                .pointer("/result/context/result/context/data/rows")
                .and_then(Value::as_array)
                .ok_or_else(upstream)?;
            let rows: Option<Vec<Value>> = rows
                .iter()
                .map(|r| r.get("result").filter(|v| v.is_object()).cloned())
                .collect();
            Ok(json!({"status":status,"rows":rows.ok_or_else(upstream)?}))
        }
        "RUNNING" | "PENDING" | "QUEUED" | "CREATED" => Ok(json!({"status":"RUNNING","rows":[]})),
        _ => Err(upstream()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn user() -> UserContext {
        UserContext {
            user_id: 7,
            email: "test@example.invalid".into(),
            display_name: "Test".into(),
            session_token: "session-one".into(),
        }
    }
    fn state() -> ScopedApps {
        ScopedApps {
            config: serde_json::from_value(json!({"bindings":{"7":{"availability":"123"}}})).unwrap(),
            base: "http://127.0.0.1".into(),
            token: "test".into(),
            key: vec![42; 32],
            http: reqwest::Client::new(),
        }
    }
    fn receipt() -> Receipt {
        Receipt {
            user: 7,
            session: session_digest(&user()),
            action: "availability".into(),
            catalog: 123,
            execution: "9007199254740993".into(),
            expires: now() + 60,
        }
    }
    #[test]
    fn rejects_unknown_actions_users_and_workload_overrides() {
        let s = state();
        assert!(s.catalog(&user(), "reset").is_err());
        let mut u = user();
        u.user_id = 9;
        assert!(s.catalog(&u, "availability").is_err());
        assert!(serde_json::from_value::<Request>(json!({"request":{},"catalog_id":1})).is_err());
        assert!(serde_json::from_value::<Request>(json!({"request":[],"path":"evil"})).is_err());
    }
    #[test]
    fn receipt_is_bound_to_session_action_catalog_and_expiry() {
        let mut s = state();
        let token = s.sign(&receipt());
        assert_eq!(
            s.verify(&token, &user(), "availability").unwrap().execution,
            "9007199254740993"
        );
        let mut u = user();
        u.session_token = "other".into();
        assert!(s.verify(&token, &u, "availability").is_err());
        assert!(s.verify(&token, &user(), "hold").is_err());
        assert!(s.verify(&(token.clone() + "x"), &user(), "availability").is_err());
        let mut r = receipt();
        r.expires = now() - 1;
        assert!(s.verify(&s.sign(&r), &user(), "availability").is_err());
        s.config
            .bindings
            .get_mut("7")
            .unwrap()
            .insert("availability".into(), "124".into());
        assert!(s.verify(&token, &user(), "availability").is_err());
    }
    #[test]
    fn config_rejects_non_numeric_catalogs_and_path_actions() {
        for c in [
            json!({"bindings":{"7":{"availability":"/evil"}}}),
            json!({"bindings":{"7":{"../execute":"1"}}}),
            json!({"bindings":{"0":{"hold":"1"}}}),
        ] {
            assert!(validate_config(&serde_json::from_value(c).unwrap()).is_err());
        }
    }
    #[test]
    fn projection_is_fail_closed_and_sanitized() {
        let v = json!({"catalog_id":123,"status":"COMPLETED","workload":{"secret":"hidden"},"events":[{"event_type":"call.done","node_name":"start","result":{"context":{"result":{"context":{"data":{"rows":[{"result":{"unit_id":"9007199254740993"}}]}}}}}}]});
        assert_eq!(
            project(&v, 123).unwrap(),
            json!({"status":"COMPLETED","rows":[{"unit_id":"9007199254740993"}]})
        );
        assert!(project(&v, 124).is_err());
        assert!(project(&json!({"catalog_id":123,"status":"COMPLETED","events":[]}), 123).is_err());
        assert_eq!(
            project(&json!({"catalog_id":123,"status":"FAILED","error":"SQL password"}), 123).unwrap()["error"],
            "workflow_failed"
        );
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;
    async fn run_action(http: &reqwest::Client, base: &str, action: &str, request: Value) -> Value {
        let launched: Value = http
            .post(format!("{base}/{action}"))
            .json(&json!({"request":request}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        for _ in 0..100 {
            let res = http
                .post(format!("{base}/{action}/result"))
                .json(&json!({"receipt":launched["receipt"]}))
                .send()
                .await
                .unwrap();
            let status = res.status();
            let value: Value = res.json().await.unwrap();
            assert_eq!(status, StatusCode::OK, "{value}");
            if value["status"] == "COMPLETED" {
                return value["rows"].clone();
            }
            assert_ne!(value["status"], "FAILED", "{value}");
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        }
        panic!("workflow timeout")
    }

    /// Real server/worker/PostgreSQL, synthetic validated identity injected only in this test.
    /// Does not claim to exercise a production OIDC issuer or the session-validation backend.
    #[tokio::test]
    #[ignore = "requires isolated Rust runtime and scoped catalog registration"]
    async fn real_runtime_scoped_actions() {
        let config: Config =
            serde_json::from_str(&std::fs::read_to_string(std::env::var("SCOPED_LIVE_BINDINGS").unwrap()).unwrap())
                .unwrap();
        validate_config(&config).unwrap();
        let s = Arc::new(ScopedApps {
            config,
            base: "http://127.0.0.1:58082".into(),
            token: String::new(),
            key: vec![42; 32],
            http: reqwest::Client::new(),
        });
        let user = UserContext {
            user_id: 7,
            email: "staff@example.invalid".into(),
            display_name: "Synthetic staff".into(),
            session_token: "synthetic-session".into(),
        };
        let app = routes(s).layer(Extension(user));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let http = reqwest::Client::new();
        let base = format!("http://{addr}/api/scoped");
        let denied = http
            .post(format!("{base}/reset"))
            .json(&json!({"request":{}}))
            .send()
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        let override_request = http
            .post(format!("{base}/reservations"))
            .json(&json!({"request":{},"catalog_id":1}))
            .send()
            .await
            .unwrap();
        assert_eq!(override_request.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let launched: Value = http
            .post(format!("{base}/reservations"))
            .json(&json!({"request":{}}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(launched["execution_id"].is_string());
        let wrong = http
            .post(format!("{base}/availability/result"))
            .json(&json!({"receipt":launched["receipt"]}))
            .send()
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::FORBIDDEN);
        let mut done = false;
        for _ in 0..100 {
            let res = http
                .post(format!("{base}/reservations/result"))
                .json(&json!({"receipt":launched["receipt"]}))
                .send()
                .await
                .unwrap();
            let status = res.status();
            let body: Value = res.json().await.unwrap();
            assert_eq!(status, StatusCode::OK, "{body}");
            if body["status"] == "COMPLETED" {
                assert!(body["rows"].is_array());
                assert!(body.get("events").is_none());
                assert!(body.get("workload").is_none());
                done = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        }
        assert!(done, "Runtime did not return completed rows");

        let request_path = std::path::PathBuf::from(std::env::var("SCOPED_LIVE_BINDINGS").unwrap())
            .with_file_name("scoped-live-request.json");
        let fixture: Value = serde_json::from_str(&std::fs::read_to_string(request_path).unwrap()).unwrap();
        let available = run_action(
            &http,
            &base,
            "availability",
            json!({"arrival":"2070-01-01","departure":"2070-01-03","guests":1}),
        )
        .await;
        assert!(available
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["unit_id"] == fixture["unit_id"]));
        let request = json!({"unit_id":fixture["unit_id"],"guest_id":fixture["guest_id"],"arrival":"2070-01-01","departure":"2070-01-03","guests":1,"idempotency_key":uuid::Uuid::new_v4().to_string()});
        let held = run_action(&http, &base, "hold", request.clone()).await;
        let replay = run_action(&http, &base, "hold", request).await;
        assert_eq!(held[0]["reservation_id"], replay[0]["reservation_id"]);
        assert_eq!(held[0]["expires_at"], replay[0]["expires_at"]);
        let id = held[0]["reservation_id"].clone();
        assert!(id.is_string());
        let confirmed = run_action(
            &http,
            &base,
            "transition",
            json!({"reservation_id":id,"status":"confirmed","expected_version":1}),
        )
        .await;
        assert_eq!(confirmed[0]["status"], "confirmed");
        let read = run_action(&http, &base, "reservation", json!({"reservation_id":id})).await;
        assert_eq!(read[0]["status"], "confirmed");
        let cancelled = run_action(
            &http,
            &base,
            "transition",
            json!({"reservation_id":id,"status":"cancelled","expected_version":2}),
        )
        .await;
        assert_eq!(cancelled[0]["status"], "cancelled");
        task.abort();
    }
}
