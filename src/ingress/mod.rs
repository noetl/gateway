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
use prometheus::{IntCounterVec, IntGaugeVec, Opts, Registry};
use serde_json::{json, Value};
use tokio::sync::Mutex;

use config::{fetch_google_jwks, fetch_ingress_config, IngressConfig};
use noetl_directives::{normalize_http_headers, DirectiveSpec, DispatchPlan};
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

/// Register `noetl_gateway_build_info{version}` — always 1; the version is the
/// point.
///
/// `Registry::gather` prunes metric families with no children, so a labelled
/// metric is absent from `/metrics` until a child series exists.  Every metric
/// on this registry is labelled by `subscription`, which means a gateway that
/// has not yet received a delivery serves an empty body — as production does
/// today.  Empty cannot be told apart from a broken exporter or the wrong port,
/// and it identifies no binary.
///
/// This gauge is unconditional and needs no traffic, so the endpoint always
/// answers with at least "I am a gateway, and I am this version".
pub fn register_build_info(registry: &Registry) -> anyhow::Result<()> {
    let build_info = IntGaugeVec::new(
        Opts::new(
            "noetl_gateway_build_info",
            "Always 1; the version label identifies the running binary (noetl/ai-meta#238).",
        ),
        &["version"],
    )?;
    registry.register(Box::new(build_info.clone()))?;
    build_info
        .with_label_values(&[env!("CARGO_PKG_VERSION")])
        .set(1);
    Ok(())
}

/// Auth outcome counters for the gateway edge.
///
/// The gateway terminates untrusted inbound traffic, and until now every auth
/// decision it made was visible only as a `tracing::warn!` on the failing
/// branch.  That makes the *rate* — the thing that actually distinguishes a
/// broken auth backend from credential-stuffing from a quiet Tuesday —
/// unavailable without log aggregation.
///
/// Both label sets are closed and pinned at 0, so a gateway that has served no
/// logins reads zeros rather than being absent.
pub const LOGIN_OUTCOMES: [&str; 3] = ["succeeded", "callback_failed", "not_authenticated"];

/// Outcomes of the per-request session check in the auth middleware.
/// Outcomes of the per-request authorization check.
///
/// The gateway makes THREE auth decisions — login, session validity, and
/// access — and only the first two were counted.  `backend_error` matters
/// operationally even though it fails closed: when the access-check backend is
/// down every request is denied, and from a dashboard "everyone is denied" and
/// "nobody is asking" look identical without this.
pub const AUTHZ_OUTCOMES: [&str; 3] = ["allowed", "denied", "backend_error"];

pub const SESSION_CHECK_OUTCOMES: [&str; 5] =
    ["ok", "missing_token", "invalid_or_expired", "validation_error", "bypass"];

static LOGIN_TOTAL: std::sync::OnceLock<IntCounterVec> = std::sync::OnceLock::new();
static SESSION_CHECK_TOTAL: std::sync::OnceLock<IntCounterVec> = std::sync::OnceLock::new();
static AUTHZ_TOTAL: std::sync::OnceLock<IntCounterVec> = std::sync::OnceLock::new();

/// Register both auth-outcome counters and pin every series at 0.
pub fn register_auth_outcome_metrics(registry: &Registry) -> anyhow::Result<()> {
    let login = IntCounterVec::new(
        Opts::new(
            "noetl_gateway_login_total",
            "Login attempts by outcome (noetl/ai-meta#238).",
        ),
        &["outcome"],
    )?;
    registry.register(Box::new(login.clone()))?;
    for o in LOGIN_OUTCOMES {
        login.with_label_values(&[o]).inc_by(0);
    }
    let _ = LOGIN_TOTAL.set(login);

    let session = IntCounterVec::new(
        Opts::new(
            "noetl_gateway_session_check_total",
            "Per-request session checks by outcome (noetl/ai-meta#238).",
        ),
        &["outcome"],
    )?;
    registry.register(Box::new(session.clone()))?;
    for o in SESSION_CHECK_OUTCOMES {
        session.with_label_values(&[o]).inc_by(0);
    }
    let _ = SESSION_CHECK_TOTAL.set(session);

    let authz = IntCounterVec::new(
        Opts::new(
            "noetl_gateway_authz_total",
            "Authorization checks by outcome (noetl/ai-meta#238).",
        ),
        &["outcome"],
    )?;
    registry.register(Box::new(authz.clone()))?;
    for o in AUTHZ_OUTCOMES {
        authz.with_label_values(&[o]).inc_by(0);
    }
    let _ = AUTHZ_TOTAL.set(authz);
    Ok(())
}

/// Record one authorization outcome.
pub fn record_authz(outcome: &str) {
    if let Some(m) = AUTHZ_TOTAL.get() {
        m.with_label_values(&[outcome]).inc();
    }
}

/// Record one login outcome.  A no-op before registration, so a unit test that
/// never registers cannot panic.
pub fn record_login(outcome: &str) {
    if let Some(m) = LOGIN_TOTAL.get() {
        m.with_label_values(&[outcome]).inc();
    }
}

/// Record one per-request session-check outcome.
pub fn record_session_check(outcome: &str) {
    if let Some(m) = SESSION_CHECK_TOTAL.get() {
        m.with_label_values(&[outcome]).inc();
    }
}

/// Silent-failure counters for the gateway's non-ingress paths.
///
/// Each covers a path that logged and counted nothing.  All are unlabelled or
/// closed-label and pinned at 0, so a healthy gateway reads zeros.
///
/// Deliberately NOT covering the ingress forward failure: that path already
/// records `noetl_ingress_rejected_total{reason="dispatch_error"}` inside the
/// `reject()` helper.  A scan for `metrics::` near the log line misses recording
/// delegated to a helper, so it looked uninstrumented and is not.
pub const EVENT_FEED_RECONNECT_REASONS: [&str; 2] = ["ended", "error"];
pub const SESSION_CACHE_STAGES: [&str; 2] = ["after_login", "after_api_validate"];

static AUTH_CANCEL_FAILED: std::sync::OnceLock<prometheus::IntCounter> = std::sync::OnceLock::new();
static SESSION_CACHE_FAILED: std::sync::OnceLock<IntCounterVec> = std::sync::OnceLock::new();
static CALLBACK_UNDELIVERED: std::sync::OnceLock<prometheus::IntCounter> = std::sync::OnceLock::new();
static EVENT_FEED_RECONNECT: std::sync::OnceLock<IntCounterVec> = std::sync::OnceLock::new();

/// Register the silent-failure counters and pin every series at 0.
pub fn register_silent_failure_metrics(registry: &Registry) -> anyhow::Result<()> {
    let cancel = prometheus::IntCounter::new(
        "noetl_gateway_auth_cancel_failed_total",
        "Auth executions the gateway timed out on and then failed to cancel (noetl/ai-meta#238).",
    )?;
    registry.register(Box::new(cancel.clone()))?;
    let _ = AUTH_CANCEL_FAILED.set(cancel);

    let cache = IntCounterVec::new(
        Opts::new(
            "noetl_gateway_session_cache_failed_total",
            "Sessions the gateway failed to cache, by stage (noetl/ai-meta#238).",
        ),
        &["stage"],
    )?;
    registry.register(Box::new(cache.clone()))?;
    for st in SESSION_CACHE_STAGES {
        cache.with_label_values(&[st]).inc_by(0);
    }
    let _ = SESSION_CACHE_FAILED.set(cache);

    let cb = prometheus::IntCounter::new(
        "noetl_gateway_callback_undelivered_total",
        "Callbacks whose receiver was already gone — the caller got nothing (noetl/ai-meta#238).",
    )?;
    registry.register(Box::new(cb.clone()))?;
    let _ = CALLBACK_UNDELIVERED.set(cb);

    let feed = IntCounterVec::new(
        Opts::new(
            "noetl_gateway_event_feed_reconnect_total",
            "Lifecycle-feed reconnects, by reason (noetl/ai-meta#238).",
        ),
        &["reason"],
    )?;
    registry.register(Box::new(feed.clone()))?;
    for r in EVENT_FEED_RECONNECT_REASONS {
        feed.with_label_values(&[r]).inc_by(0);
    }
    let _ = EVENT_FEED_RECONNECT.set(feed);
    Ok(())
}

/// An auth execution was left running after the gateway gave up on it.
pub fn record_auth_cancel_failed() {
    if let Some(m) = AUTH_CANCEL_FAILED.get() {
        m.inc();
    }
}

/// A session was validated but not cached, so the next request repeats the work.
pub fn record_session_cache_failed(stage: &str) {
    if let Some(m) = SESSION_CACHE_FAILED.get() {
        m.with_label_values(&[stage]).inc();
    }
}

/// A callback arrived for a receiver that was already gone.
pub fn record_callback_undelivered() {
    if let Some(m) = CALLBACK_UNDELIVERED.get() {
        m.inc();
    }
}

/// The execution-lifecycle feed dropped and is redialling.
pub fn record_event_feed_reconnect(reason: &str) {
    if let Some(m) = EVENT_FEED_RECONNECT.get() {
        m.with_label_values(&[reason]).inc();
    }
}

/// Register `noetl_gateway_auth_bypass_enabled` — 1 when `GATEWAY_AUTH_BYPASS`
/// is on, meaning the gateway accepts ANY session token and injects a synthetic
/// `user_id: 0` context.
///
/// This is the single most consequential piece of state the gateway holds, and
/// until now its only signal was a `tracing::warn!` emitted **per request** —
/// so the evidence that authentication is disabled is a log flood, and the
/// flood is also the symptom.  Nothing on `/metrics` said anything at all.
///
/// A gauge is the right shape: it survives the boot it describes, it is
/// alertable (`== 1` would be the highest-severity rule in the fleet), and it
/// is present at 0 on a healthy gateway rather than absent — because "auth is
/// fine" and "I cannot tell whether auth is on" must not look the same.
///
/// Verified 2026-08-05: the variable is NOT set on the production gateway, and
/// the parse is fail-safe — only exactly `"true"` or `"1"` enable it, so a
/// typo like `TRUE` or `yes` leaves authentication ON.
pub fn register_auth_bypass_gauge(registry: &Registry, enabled: bool) -> anyhow::Result<()> {
    let g = IntGaugeVec::new(
        Opts::new(
            "noetl_gateway_auth_bypass_enabled",
            "1 when GATEWAY_AUTH_BYPASS is on and every session token is accepted (noetl/ai-meta#238).",
        ),
        &["mode"],
    )?;
    registry.register(Box::new(g.clone()))?;
    g.with_label_values(&[if enabled { "bypass" } else { "enforced" }])
        .set(i64::from(enabled));
    Ok(())
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
    trace: Option<&noetl_directives::TraceContext>,
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

    /// Every silent-failure counter must be present at 0 and recorded at its
    /// real site.
    ///
    /// The forward-failure path is deliberately absent from this list: it
    /// already records `noetl_ingress_rejected_total{reason="dispatch_error"}`
    /// inside `reject()`.  A scan for `metrics::` near a log line cannot see
    /// recording delegated to a helper, so it read as uninstrumented — adding a
    /// second counter there would have double-counted the same event.
    #[test]
    fn silent_failure_metrics_are_present_and_wired() {
        use prometheus::{Encoder, TextEncoder};
        let registry = Registry::new();
        register_silent_failure_metrics(&registry).expect("register");
        let mut buf = Vec::new();
        TextEncoder::new().encode(&registry.gather(), &mut buf).expect("encode");
        let text = String::from_utf8(buf).expect("utf8");

        for name in [
            "noetl_gateway_auth_cancel_failed_total",
            "noetl_gateway_callback_undelivered_total",
        ] {
            assert!(
                text.lines().any(|l| l.starts_with(&format!("{name} "))),
                "{name} must be present at 0"
            );
        }
        for (metric, values) in [
            ("noetl_gateway_session_cache_failed_total", &SESSION_CACHE_STAGES[..]),
            ("noetl_gateway_event_feed_reconnect_total", &EVENT_FEED_RECONNECT_REASONS[..]),
        ] {
            for v in values {
                assert!(
                    text.lines().any(|l| l.starts_with(&format!("{metric}{{"))
                        && l.contains(&format!("\"{v}\""))),
                    "{metric} is missing {v}"
                );
            }
        }

        // Each must be recorded where the failure actually happens.
        let auth = include_str!("../auth/mod.rs");
        assert!(auth.contains("record_auth_cancel_failed()"));
        for stage in SESSION_CACHE_STAGES {
            assert!(
                auth.contains(&format!("record_session_cache_failed(\"{stage}\")")),
                "session cache stage {stage} is declared but never recorded"
            );
        }
        assert!(include_str!("../callbacks.rs").contains("record_callback_undelivered()"));
        let feed = include_str!("../event_feed.rs");
        for r in EVENT_FEED_RECONNECT_REASONS {
            assert!(
                feed.contains(&format!("record_event_feed_reconnect(\"{r}\")")),
                "feed reconnect reason {r} is declared but never recorded"
            );
        }
    }

    /// Every declared auth outcome must be pinned AND actually recorded
    /// somewhere, and every branch of the middleware must record exactly once.
    ///
    /// The failure this guards is asymmetric instrumentation: counting only the
    /// failures makes the RATE meaningless, because a spike in
    /// `invalid_or_expired` is only interpretable against `ok`.  That is the
    /// whole reason these exist rather than the pre-existing warns.
    #[test]
    fn every_auth_outcome_is_instrumented_and_pinned() {
        use prometheus::{Encoder, TextEncoder};
        let registry = Registry::new();
        register_auth_outcome_metrics(&registry).expect("register");
        let mut buf = Vec::new();
        TextEncoder::new().encode(&registry.gather(), &mut buf).expect("encode");
        let text = String::from_utf8(buf).expect("utf8");

        for (metric, outcomes) in [
            ("noetl_gateway_login_total", &LOGIN_OUTCOMES[..]),
            ("noetl_gateway_session_check_total", &SESSION_CHECK_OUTCOMES[..]),
            ("noetl_gateway_authz_total", &AUTHZ_OUTCOMES[..]),
        ] {
            for o in outcomes {
                assert!(
                    text.lines().any(|l| l.starts_with(&format!("{metric}{{"))
                        && l.contains(&format!("outcome=\"{o}\""))),
                    "{metric}{{outcome={o}}} must be pinned at 0"
                );
            }
        }

        // Each outcome must appear at a real call site, not only in the const.
        let auth_mod = include_str!("../auth/mod.rs");
        for o in LOGIN_OUTCOMES {
            assert!(
                auth_mod.contains(&format!("record_login(\"{o}\")")),
                "login outcome {o} is declared but never recorded"
            );
        }
        let middleware = include_str!("../auth/middleware.rs");
        for o in SESSION_CHECK_OUTCOMES {
            assert!(
                middleware.contains(&format!("record_session_check(\"{o}\")")),
                "session-check outcome {o} is declared but never recorded"
            );
        }
        // The success paths specifically — counting only failures would make
        // the rate uninterpretable.
        assert!(auth_mod.contains("record_login(\"succeeded\")"));
        // All three authz outcomes, including the one that fails CLOSED: when
        // the backend is down every request is denied, and without this
        // "everyone denied" and "nobody asking" are the same picture.
        assert!(auth_mod.contains("record_authz(\"backend_error\")"));
        assert!(
            auth_mod.contains("record_authz(if allowed"),
            "allowed/denied must both be recorded from the same decision"
        );
        assert!(middleware.contains("record_session_check(\"ok\")"));
    }

    /// The bypass gauge must be present in BOTH states.
    ///
    /// A gauge that only appears when bypass is ON would leave "auth is
    /// enforced" and "I cannot tell" identical — which is the whole failure
    /// this replaces, since the previous signal was a per-request warn that
    /// exists only in the dangerous state.
    #[test]
    fn auth_bypass_gauge_is_present_in_both_states() {
        use prometheus::{Encoder, TextEncoder};
        let render = |r: &Registry| {
            let mut buf = Vec::new();
            TextEncoder::new().encode(&r.gather(), &mut buf).expect("encode");
            String::from_utf8(buf).expect("utf8")
        };

        for (enabled, want_mode, want_value) in
            [(false, "enforced", " 0"), (true, "bypass", " 1")]
        {
            let registry = Registry::new();
            register_auth_bypass_gauge(&registry, enabled).expect("register");
            let text = render(&registry);
            let line = text
                .lines()
                .find(|l| l.starts_with("noetl_gateway_auth_bypass_enabled{"))
                .unwrap_or_else(|| panic!("gauge must be present when enabled={enabled}"));
            assert!(
                line.contains(&format!("mode=\"{want_mode}\"")),
                "enabled={enabled} must report mode={want_mode}; got {line:?}"
            );
            assert!(
                line.ends_with(want_value),
                "enabled={enabled} must read{want_value}; got {line:?}"
            );
        }
    }

    /// A registry carrying only the ingress counters gathers to nothing until a
    /// delivery arrives, which is what production serves today: a 200 with an
    /// empty body.  Registering build_info must make the endpoint answer
    /// without any traffic at all.
    #[test]
    fn build_info_makes_metrics_non_empty_without_traffic() {
        use prometheus::{Encoder, TextEncoder};

        let registry = Registry::new();
        IngressMetrics::register(&registry).expect("register ingress metrics");

        let render = |r: &Registry| {
            let mut buf = Vec::new();
            TextEncoder::new()
                .encode(&r.gather(), &mut buf)
                .expect("encode");
            String::from_utf8(buf).expect("utf8")
        };

        assert!(
            render(&registry).is_empty(),
            "precondition: labelled-only registry gathers to nothing"
        );

        register_build_info(&registry).expect("register build_info");
        let text = render(&registry);
        let line = text
            .lines()
            .find(|l| l.starts_with("noetl_gateway_build_info{"))
            .expect("build_info must be present with no traffic");
        assert!(
            line.contains(&format!("version=\"{}\"", env!("CARGO_PKG_VERSION"))),
            "build_info must carry the crate version; got {line:?}"
        );
    }

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
