//! Gateway push-ingress (Mode C) — `POST /ingress/{listener}`.
//!
//! Phase 3 of the subscription/listener RFC
//! ([noetl/ai-meta#90](https://github.com/noetl/ai-meta/issues/90), RFC §3.3 /
//! §6 / §7.5).
//!
//! The gateway terminates untrusted inbound push/webhook traffic and is a
//! **verify-and-forward gatekeeper**: it authenticates a delivery, and *only
//! after verification passes* parses header directives and forwards one
//! `POST /api/execute` per delivery to the server on the subscription's
//! dedicated pool.  It never reads domain data or holds a DB connection
//! (`agents/rules/data-access-boundary.md`); the verify scheme, Wallet-resolved
//! secret, dispatch target, and directive allowlist all come from the server's
//! `GET /api/internal/ingress/{listener}` config endpoint.
//!
//! ## Flow (RFC §6, auth-gated directive trust §7.5)
//!
//! ```text
//! POST /ingress/{listener}            (no session auth — a source, not a user)
//!   1. fetch ingress config (cached) — verify scheme + secret + dispatch + directives
//!   2. verify the delivery (HMAC / bearer / OIDC)
//!        fail → 401/403, metric noetl_ingress_rejected_total, NO forward, NO directives
//!   3. ON SUCCESS ONLY: parse + resolve header directives (allowlist, RFC §7)
//!   4. forward POST {server}/api/execute  (one execution per delivery, dedicated pool)
//!   5. emit subscription.message.directives_applied (audit, RFC §7.6)
//!   6. return 202 so the source acks
//! ```

mod config;
mod directives;
mod verify;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use prometheus::{IntCounterVec, Opts, Registry};
use serde_json::{json, Value};
use tokio::sync::Mutex;

use config::{fetch_google_jwks, fetch_ingress_config, IngressConfig};
use directives::{normalize_http_headers, DirectiveSpec, DispatchPlan};
use verify::Jwks;

/// HTTP headers that must never leak into the forwarded execution workload /
/// event log (they carry auth material).  The configured signature header is
/// added to this set per-request.
const SENSITIVE_HEADERS: &[&str] = &["authorization", "cookie", "proxy-authorization"];

/// Prometheus counters for the ingress edge (observability.md P1/P2).
#[derive(Clone)]
pub struct IngressMetrics {
    pub received: IntCounterVec,
    pub rejected: IntCounterVec,
    pub dispatched: IntCounterVec,
}

impl IngressMetrics {
    pub fn register(registry: &Registry) -> anyhow::Result<Self> {
        let received = IntCounterVec::new(
            Opts::new("noetl_ingress_received_total", "Push/webhook deliveries received"),
            &["subscription"],
        )?;
        let rejected = IntCounterVec::new(
            Opts::new(
                "noetl_ingress_rejected_total",
                "Push/webhook deliveries rejected at verification (no execution dispatched)",
            ),
            &["subscription", "reason"],
        )?;
        let dispatched = IntCounterVec::new(
            Opts::new(
                "noetl_ingress_dispatched_total",
                "Verified deliveries forwarded as one execution",
            ),
            &["subscription"],
        )?;
        registry.register(Box::new(received.clone()))?;
        registry.register(Box::new(rejected.clone()))?;
        registry.register(Box::new(dispatched.clone()))?;
        Ok(Self { received, rejected, dispatched })
    }
}

struct CachedConfig {
    cfg: IngressConfig,
    at: Instant,
}

struct CachedJwks {
    jwks: Jwks,
    at: Instant,
}

/// Shared state for the ingress routes.
pub struct IngressState {
    http: reqwest::Client,
    server_base_url: String,
    internal_token: String,
    config_ttl: Duration,
    jwks_ttl: Duration,
    config_cache: Mutex<HashMap<String, CachedConfig>>,
    jwks_cache: Mutex<Option<CachedJwks>>,
    metrics: IngressMetrics,
}

impl IngressState {
    pub fn new(
        server_base_url: String,
        internal_token: String,
        metrics: IngressMetrics,
    ) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            server_base_url,
            internal_token,
            config_ttl: Duration::from_secs(30),
            jwks_ttl: Duration::from_secs(3600),
            config_cache: Mutex::new(HashMap::new()),
            jwks_cache: Mutex::new(None),
            metrics,
        }
    }

    /// Resolve the ingress config for a listener, caching for `config_ttl`.
    async fn resolve_config(&self, listener: &str) -> anyhow::Result<Option<IngressConfig>> {
        {
            let cache = self.config_cache.lock().await;
            if let Some(c) = cache.get(listener) {
                if c.at.elapsed() < self.config_ttl {
                    return Ok(Some(c.cfg.clone()));
                }
            }
        }
        let fetched = fetch_ingress_config(
            &self.http,
            &self.server_base_url,
            &self.internal_token,
            listener,
        )
        .await?;
        if let Some(cfg) = &fetched {
            let mut cache = self.config_cache.lock().await;
            cache.insert(listener.to_string(), CachedConfig { cfg: cfg.clone(), at: Instant::now() });
        }
        Ok(fetched)
    }

    /// Google JWKS for OIDC, cached for `jwks_ttl`.
    async fn resolve_jwks(&self) -> anyhow::Result<Jwks> {
        {
            let cache = self.jwks_cache.lock().await;
            if let Some(c) = cache.as_ref() {
                if c.at.elapsed() < self.jwks_ttl {
                    return Ok(c.jwks.clone());
                }
            }
        }
        let jwks = fetch_google_jwks(&self.http).await?;
        let mut cache = self.jwks_cache.lock().await;
        *cache = Some(CachedJwks { jwks: jwks.clone(), at: Instant::now() });
        Ok(jwks)
    }
}

/// `POST /ingress/{listener}` — the verify-and-forward handler.
pub async fn push_ingress(
    State(st): State<Arc<IngressState>>,
    Path(listener): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let span = tracing::info_span!("gateway.ingress", subscription = %listener);
    let _g = span.enter();

    st.metrics.received.with_label_values(&[&listener]).inc();

    // 1. Resolve config.
    let cfg = match st.resolve_config(&listener).await {
        Ok(Some(cfg)) => cfg,
        Ok(None) => {
            return reject(
                &st,
                &listener,
                "unknown_listener",
                StatusCode::NOT_FOUND,
                "no push subscription for this ingress path",
            );
        }
        Err(e) => {
            tracing::error!(subscription = %listener, error = %e, "ingress config fetch failed");
            return reject(
                &st,
                &listener,
                "config_error",
                StatusCode::BAD_GATEWAY,
                "could not resolve ingress config",
            );
        }
    };

    // Normalized HTTP header map (lowercased) for verification + directives.
    let http_headers = normalize_from_headermap(&headers);

    // 2. Verify (OIDC needs the JWKS).
    let jwks = if cfg.verify.verify_type == "pubsub_oidc" {
        match st.resolve_jwks().await {
            Ok(j) => Some(j),
            Err(e) => {
                tracing::error!(subscription = %listener, error = %e, "JWKS fetch failed");
                return reject(
                    &st,
                    &listener,
                    "jwks_error",
                    StatusCode::BAD_GATEWAY,
                    "could not fetch OIDC keys",
                );
            }
        }
    } else {
        None
    };

    // Steps 2 (verify) + 3 (directives) are fused in `verify_then_plan` so the
    // ordering is a testable invariant: directives are parsed ONLY after
    // verification returns Ok (RFC §7.5).
    let verified = match verify_then_plan(&cfg, &http_headers, &body, jwks.as_ref()) {
        Ok(v) => v,
        Err(rej) => {
            // RFC §7.5: rejected BEFORE any directive is parsed. No forward.
            tracing::warn!(
                subscription = %listener,
                reason = rej.reason,
                detail = %rej.detail,
                "ingress delivery rejected at verification — no execution dispatched, no directives applied"
            );
            st.metrics.rejected.with_label_values(&[&listener, rej.reason]).inc();
            let status = StatusCode::from_u16(rej.status).unwrap_or(StatusCode::UNAUTHORIZED);
            return (status, Json(json!({ "status": "rejected", "reason": rej.reason })))
                .into_response();
        }
    };
    let VerifiedDelivery { envelope, plan, message_id } = verified;

    // ---- Verification passed. Everything below is auth-gated. ----

    // 4. Forward one execution per delivery.
    let playbook = plan
        .playbook_override
        .clone()
        .unwrap_or_else(|| cfg.dispatch.playbook.clone());
    let pool = plan
        .execution_pool_override
        .clone()
        .or_else(|| cfg.dispatch.execution_pool.clone());
    let parent = cfg.subscription_id.parse::<i64>().ok();
    let payload = build_payload(&cfg, &envelope, &plan);

    let exec_result = post_execute(
        &st,
        &playbook,
        payload,
        pool.as_deref(),
        plan.trace.as_ref(),
        parent,
    )
    .await;

    let execution_id = match exec_result {
        Ok(id) => id,
        Err(e) => {
            tracing::error!(subscription = %listener, error = %e, "forward POST /api/execute failed");
            // The source should retry — surface 502 so it does.
            return reject(
                &st,
                &listener,
                "dispatch_error",
                StatusCode::BAD_GATEWAY,
                "verified but could not dispatch execution",
            );
        }
    };

    st.metrics.dispatched.with_label_values(&[&listener]).inc();
    tracing::info!(
        subscription = %listener,
        execution_id,
        playbook = %playbook,
        pool = pool.as_deref().unwrap_or("(default)"),
        message_id = %message_id,
        "verified delivery → one execution dispatched on dedicated pool"
    );

    // 5. Audit the applied directives (RFC §7.6) — best-effort.
    if !plan.applied.is_empty() || plan.trace.is_some() {
        emit_directives_applied(&st, &execution_id, &message_id, &plan).await;
    }

    // 6. 202 so the source acks.
    (
        StatusCode::ACCEPTED,
        Json(json!({ "status": "accepted", "execution_id": execution_id })),
    )
        .into_response()
}

/// `GET /metrics` for the ingress counters (the gateway's first metrics surface).
pub async fn metrics_handler(State(registry): State<Arc<Registry>>) -> Response {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let mut buf = Vec::new();
    if encoder.encode(&registry.gather(), &mut buf).is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "encode error").into_response();
    }
    (StatusCode::OK, String::from_utf8_lossy(&buf).into_owned()).into_response()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn reject(
    st: &IngressState,
    listener: &str,
    reason: &'static str,
    status: StatusCode,
    msg: &str,
) -> Response {
    st.metrics.rejected.with_label_values(&[listener, reason]).inc();
    (status, Json(json!({ "status": "rejected", "reason": reason, "detail": msg }))).into_response()
}

/// A delivery that passed verification — the only way to obtain a
/// [`DispatchPlan`] for a push delivery.
#[derive(Debug)]
struct VerifiedDelivery {
    envelope: Value,
    plan: DispatchPlan,
    message_id: String,
}

/// Verify the delivery and — **only on success** — build the envelope and
/// resolve the header directives.  This fuses RFC §6 steps 3 (verify) and 4
/// (parse directives) so the auth gate is a single, testable invariant: a
/// failed verification returns `Err` and **no `DispatchPlan` is ever
/// constructed** (RFC §7.5).  An unauthenticated caller can never drive
/// routing.
fn verify_then_plan(
    cfg: &IngressConfig,
    http_headers: &serde_json::Map<String, Value>,
    body: &[u8],
    jwks: Option<&Jwks>,
) -> Result<VerifiedDelivery, verify::VerifyRejection> {
    // 1. Verify FIRST. Any failure short-circuits before directive parsing.
    verify::verify(&cfg.verify, http_headers, body, jwks)?;

    // 2. Only now (auth-gated) build the envelope + resolve directives.
    let (envelope, directive_channel, message_id) = build_envelope(cfg, http_headers, body);
    let plan = match cfg.directives.as_ref() {
        Some(raw) => match DirectiveSpec::parse(raw) {
            Ok(spec) => spec.resolve(&directive_channel),
            Err(e) => {
                tracing::error!(error = %e, "directive spec parse failed; ignoring directives");
                DispatchPlan::default()
            }
        },
        None => DispatchPlan::default(),
    };

    Ok(VerifiedDelivery { envelope, plan, message_id })
}

/// Build a lowercased header map from an axum `HeaderMap`.
fn normalize_from_headermap(headers: &HeaderMap) -> serde_json::Map<String, Value> {
    let pairs: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(k, v)| v.to_str().ok().map(|s| (k.as_str().to_string(), s.to_string())))
        .collect();
    normalize_http_headers(&pairs)
}

/// Strip sensitive (auth-bearing) headers so they never reach the execution
/// workload / event log.  The configured signature header is stripped too.
fn strip_sensitive(
    headers: &serde_json::Map<String, Value>,
    sig_header: Option<&str>,
) -> serde_json::Map<String, Value> {
    let sig = sig_header.map(|s| s.to_ascii_lowercase());
    headers
        .iter()
        .filter(|(k, _)| {
            !SENSITIVE_HEADERS.contains(&k.as_str()) && Some(k.as_str()) != sig.as_deref()
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// The normalized per-delivery message envelope, the directive channel map, and
/// the message id.  Webhook: HTTP-header channel + parsed body.  Pub/Sub push:
/// the `message` envelope is unwrapped — data is base64-decoded, the directive
/// channel is the message **attributes** (RFC §7.1).
fn build_envelope(
    cfg: &IngressConfig,
    http_headers: &serde_json::Map<String, Value>,
    body: &[u8],
) -> (Value, serde_json::Map<String, Value>, String) {
    let safe_headers = strip_sensitive(http_headers, cfg.verify.header.as_deref());

    if cfg.source == "pubsub" {
        if let Some((data, attributes, message_id)) = unwrap_pubsub_push(body) {
            let directive_channel = lowercase_keys(&attributes);
            let envelope = json!({
                "id": message_id,
                "data": data,
                "headers": directive_channel,
                "attributes": attributes,
                "metadata": { "source": "pubsub", "mode": "push" },
            });
            return (envelope, directive_channel, message_id);
        }
        // Fall through to generic handling if the envelope didn't match.
    }

    // Generic webhook: parsed body is the data; HTTP headers are the channel.
    let data = parse_body(body);
    let message_id = http_headers
        .get("x-message-id")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let envelope = json!({
        "id": message_id,
        "data": data,
        "headers": safe_headers,
        "attributes": {},
        "metadata": { "source": cfg.source, "mode": "push" },
    });
    (envelope, safe_headers, message_id)
}

/// Unwrap a Google Pub/Sub push body: `{ message: { data: <base64>, messageId,
/// attributes }, subscription }`.  Returns `(decoded_data, attributes,
/// message_id)`.
fn unwrap_pubsub_push(body: &[u8]) -> Option<(Value, serde_json::Map<String, Value>, String)> {
    let v: Value = serde_json::from_slice(body).ok()?;
    let message = v.get("message")?;
    let data_b64 = message.get("data").and_then(|d| d.as_str()).unwrap_or("");
    let data = if data_b64.is_empty() {
        Value::Null
    } else {
        use base64::Engine;
        match base64::engine::general_purpose::STANDARD.decode(data_b64) {
            Ok(bytes) => parse_body(&bytes),
            Err(_) => Value::String(data_b64.to_string()),
        }
    };
    let attributes = message
        .get("attributes")
        .and_then(|a| a.as_object())
        .cloned()
        .unwrap_or_default();
    let message_id = message
        .get("messageId")
        .or_else(|| message.get("message_id"))
        .and_then(|m| m.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    Some((data, attributes, message_id))
}

fn parse_body(body: &[u8]) -> Value {
    if body.is_empty() {
        return Value::Null;
    }
    match serde_json::from_slice::<Value>(body) {
        Ok(v) => v,
        Err(_) => Value::String(String::from_utf8_lossy(body).into_owned()),
    }
}

fn lowercase_keys(m: &serde_json::Map<String, Value>) -> serde_json::Map<String, Value> {
    m.iter().map(|(k, v)| (k.to_ascii_lowercase(), v.clone())).collect()
}

/// Build the per-delivery execution payload (mirrors the worker's `build_payload`).
fn build_payload(cfg: &IngressConfig, envelope: &Value, plan: &DispatchPlan) -> Value {
    let mut payload = serde_json::Map::new();
    payload.insert("message".to_string(), envelope.clone());
    payload.insert("subscription".to_string(), json!(cfg.catalog_path));
    payload.insert("source".to_string(), json!(cfg.source));

    let data = envelope.get("data").cloned().unwrap_or(Value::Null);
    let attributes = envelope.get("attributes").cloned().unwrap_or(json!({}));
    let primary = match cfg.dispatch.payload_from.as_str() {
        "message.attributes" => attributes,
        "message.body" => match &data {
            Value::String(s) => Value::String(s.clone()),
            other => Value::String(other.to_string()),
        },
        _ => data, // "message.json" (default)
    };
    match primary {
        Value::Object(map) => {
            for (k, v) in map {
                payload.entry(k).or_insert(v);
            }
        }
        other => {
            payload.insert("body".to_string(), other);
        }
    }

    if let Some(k) = plan.idempotency_key.as_ref() {
        payload.insert("idempotency_key".to_string(), json!(k));
    }
    if let Some(c) = plan.content_type.as_ref() {
        payload.insert("content_type".to_string(), json!(c));
    }
    Value::Object(payload)
}

/// `POST {server}/api/execute` — one execution per delivery, on the resolved
/// playbook + pool, carrying the trace + parent (the subscription) lineage.
async fn post_execute(
    st: &IngressState,
    playbook: &str,
    payload: Value,
    pool: Option<&str>,
    trace: Option<&directives::TraceContext>,
    parent: Option<i64>,
) -> anyhow::Result<String> {
    let mut body = serde_json::Map::new();
    body.insert("path".to_string(), json!(playbook));
    body.insert("workload".to_string(), payload);
    body.insert("resource_kind".to_string(), json!("playbook"));
    if let Some(p) = pool {
        body.insert("execution_pool".to_string(), json!(p));
    }
    if let Some(t) = trace {
        if let Ok(tv) = serde_json::to_value(t) {
            body.insert("trace".to_string(), tv);
        }
    }
    if let Some(pid) = parent {
        body.insert("parent_execution_id".to_string(), json!(pid));
    }

    let url = format!("{}/api/execute", st.server_base_url.trim_end_matches('/'));
    let resp = st.http.post(&url).json(&Value::Object(body)).send().await?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!("/api/execute returned {}: {}", status, text);
    }
    let parsed: Value = serde_json::from_str(&text)?;
    parsed
        .get("execution_id")
        .map(|v| match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        })
        .ok_or_else(|| anyhow::anyhow!("/api/execute response missing execution_id: {text}"))
}

/// Emit `subscription.message.directives_applied` (RFC §7.6) — best-effort.
async fn emit_directives_applied(
    st: &IngressState,
    execution_id: &str,
    message_id: &str,
    plan: &DispatchPlan,
) {
    let context = json!({
        "message_id": message_id,
        "applied": plan.applied,
        "route_override": {
            "playbook": plan.playbook_override,
            "pool": plan.execution_pool_override,
        },
        "trace": plan.trace,
    });
    let event = json!({
        "execution_id": execution_id,
        "step": "ingress",
        "event_type": "subscription.message.directives_applied",
        "status": "APPLIED",
        "context": context,
        "worker_id": "gateway",
        "meta": { "emitter": "gateway_ingress" },
    });
    let url = format!("{}/api/events", st.server_base_url.trim_end_matches('/'));
    if let Err(e) = st.http.post(&url).json(&event).send().await {
        tracing::debug!(execution_id, error = %e, "directives_applied audit emit failed (non-fatal)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(source: &str, payload_from: &str) -> IngressConfig {
        serde_json::from_value(json!({
            "listener": "x",
            "catalog_path": "subscriptions/x",
            "source": source,
            "subscription_id": "999",
            "verify": { "type": "hmac_sha256", "header": "x-sig", "secret": "s" },
            "dispatch": { "playbook": "domain/d", "payload_from": payload_from }
        }))
        .unwrap()
    }

    #[test]
    fn strip_sensitive_removes_auth_and_sig() {
        let h = serde_json::from_value(json!({
            "authorization": "Bearer x",
            "x-sig": "abc",
            "x-keep": "yes"
        }))
        .unwrap();
        let safe = strip_sensitive(&h, Some("x-sig"));
        assert!(!safe.contains_key("authorization"));
        assert!(!safe.contains_key("x-sig"));
        assert_eq!(safe.get("x-keep").unwrap(), "yes");
    }

    #[test]
    fn webhook_envelope_uses_http_headers_channel() {
        let c = cfg("webhook", "message.json");
        let headers = serde_json::from_value(json!({
            "authorization": "Bearer secret",
            "x-noetl-route": "domain/other",
            "x-message-id": "abc-1"
        }))
        .unwrap();
        let (envelope, channel, mid) = build_envelope(&c, &headers, br#"{"a":1}"#);
        assert_eq!(mid, "abc-1");
        // Auth header stripped from the envelope + channel.
        assert!(!channel.contains_key("authorization"));
        assert_eq!(channel.get("x-noetl-route").unwrap(), "domain/other");
        assert_eq!(envelope.get("data").unwrap(), &json!({"a": 1}));
    }

    #[test]
    fn pubsub_push_unwrapped() {
        use base64::Engine;
        let data = base64::engine::general_purpose::STANDARD.encode(br#"{"temp":21}"#);
        let body = json!({
            "message": {
                "data": data,
                "messageId": "msg-7",
                "attributes": { "X-Noetl-Route": "domain/fraud", "device": "sensor-1" }
            },
            "subscription": "projects/p/subscriptions/s"
        });
        let c = cfg("pubsub", "message.json");
        let (envelope, channel, mid) =
            build_envelope(&c, &serde_json::Map::new(), body.to_string().as_bytes());
        assert_eq!(mid, "msg-7");
        // Pub/Sub directive channel = attributes (lowercased).
        assert_eq!(channel.get("x-noetl-route").unwrap(), "domain/fraud");
        assert_eq!(channel.get("device").unwrap(), "sensor-1");
        assert_eq!(envelope.get("data").unwrap(), &json!({"temp": 21}));
    }

    #[test]
    fn payload_merges_json_body_top_level() {
        let c = cfg("webhook", "message.json");
        let envelope = json!({ "id": "1", "data": { "order_id": 42 }, "attributes": {} });
        let payload = build_payload(&c, &envelope, &DispatchPlan::default());
        // message.json default merges the object body to the top level.
        assert_eq!(payload.get("order_id").unwrap(), &json!(42));
        assert!(payload.get("message").is_some());
        assert_eq!(payload.get("subscription").unwrap(), &json!("subscriptions/x"));
    }

    #[test]
    fn payload_scalar_body_under_body_key() {
        let c = cfg("webhook", "message.body");
        let envelope = json!({ "id": "1", "data": "raw-text", "attributes": {} });
        let payload = build_payload(&c, &envelope, &DispatchPlan::default());
        assert_eq!(payload.get("body").unwrap(), &json!("raw-text"));
    }

    // ---- THE headline Phase-3 security property (RFC §7.5) ----

    /// A push config with a routing directive (`x-noetl-route` → playbook
    /// redirect), guarded by HMAC verification.
    fn directive_cfg() -> IngressConfig {
        serde_json::from_value(json!({
            "listener": "x",
            "catalog_path": "subscriptions/x",
            "source": "webhook",
            "subscription_id": "999",
            "verify": { "type": "hmac_sha256", "header": "x-sig", "secret": "topsecret" },
            "dispatch": { "playbook": "domain/default", "payload_from": "message.json" },
            "directives": {
                "directives": [
                    { "header": "x-noetl-route", "controls": "dispatch.playbook",
                      "allowed": ["domain/redirected"] }
                ]
            }
        }))
        .unwrap()
    }

    fn sign(secret: &str, body: &[u8]) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut m = <Hmac<Sha256>>::new_from_slice(secret.as_bytes()).unwrap();
        m.update(body);
        hex::encode(m.finalize().into_bytes())
    }

    #[test]
    fn directives_applied_only_after_verification_passes() {
        let c = directive_cfg();
        let body = br#"{"event":"x"}"#;

        // A forged caller sets the redirect header BUT a bad signature.
        let forged: serde_json::Map<String, Value> = serde_json::from_value(json!({
            "x-sig": "deadbeef",
            "x-noetl-route": "domain/redirected"
        }))
        .unwrap();
        let err = verify_then_plan(&c, &forged, body, None).unwrap_err();
        assert_eq!(err.reason, "bad_signature");
        // The proof: a failed verification yields NO VerifiedDelivery at all,
        // so the redirect directive could not have been honored. An
        // unauthenticated caller can never drive routing.

        // The SAME header, now with a valid signature, DOES redirect.
        let mut authed = forged.clone();
        authed.insert("x-sig".to_string(), json!(sign("topsecret", body)));
        let ok = verify_then_plan(&c, &authed, body, None).unwrap();
        assert_eq!(ok.plan.playbook_override.as_deref(), Some("domain/redirected"));
        assert_eq!(ok.plan.applied.len(), 1);
    }

    #[test]
    fn non_allowlisted_redirect_ignored_even_when_authed() {
        let c = directive_cfg();
        let body = br#"{}"#;
        let mut authed: serde_json::Map<String, Value> = serde_json::from_value(json!({
            "x-noetl-route": "domain/evil"
        }))
        .unwrap();
        authed.insert("x-sig".to_string(), json!(sign("topsecret", body)));
        let ok = verify_then_plan(&c, &authed, body, None).unwrap();
        // Authenticated, but the value isn't allowlisted → no redirect.
        assert!(ok.plan.playbook_override.is_none());
    }
}
