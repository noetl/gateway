//! Public passthrough for NoETL **instance** routes (build plan item 9, noetl/ai-meta#544):
//! register, discover and hand off between NoETL instances through the gateway, so an
//! instance outside the cluster (a laptop, an edge box, another cluster) can reach the control
//! plane with `noetl instance … --server https://<gateway>`.
//!
//! `POST /api/instances/{register,deregister,discover,enroll,inbox,tasks/submit,tasks/result,tasks/status}`
//! → the server's identical path.
//!
//! * **Off unless `GATEWAY_INSTANCE_PROXY=on`.** Unset, nothing is mounted.
//! * **No gateway auth, by design.** These requests are not users: each body is an ML-DSA-87
//!   signed envelope that the server verifies (signature, trust or enrollment, audience,
//!   clock skew, one-time nonce). The gateway adds nothing an attacker could use and forwards
//!   no credentials: only `content-type` reaches the server. Cookies, `authorization` and
//!   `x-*` headers are dropped.
//! * **Exactly these eight routes, POST only.** The operator routes
//!   (`/api/runtime/instances*`: listing, minting enrollment tokens, revoking) are never
//!   exposed here; they stay behind the server's internal-token gate.
//! * **Rate-limited** per client IP and in total, per hour (`GATEWAY_INSTANCE_IP_PER_HOUR`,
//!   default 3600; `GATEWAY_INSTANCE_TOTAL_PER_HOUR`, default 60000), with the same limiter
//!   and trusted client-IP header (`GATEWAY_CLIENT_IP_HEADER`) as guest sessions. One
//!   instance heartbeating and long-polling uses about 400 requests an hour.
//! * Bodies over 2 MiB are refused (413) before anything is sent (a task result may be 1 MiB,
//!   plus the envelope). The upstream timeout is 35 s, above the server's 25 s inbox long-poll.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{
    body::{to_bytes, Body, Bytes},
    extract::{ConnectInfo, Request, State},
    http::{
        header::{CACHE_CONTROL, CONTENT_TYPE, RETRY_AFTER},
        HeaderMap, HeaderName, HeaderValue, StatusCode,
    },
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use serde_json::json;

use crate::guest::{client_ip, now_secs, Limiter};

pub const ENABLE_ENV: &str = "GATEWAY_INSTANCE_PROXY";
pub const MAX_BODY: usize = 2 * 1024 * 1024;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(35);

/// The instance routes the gateway passes through. Nothing else under `/api/instances`.
pub const ROUTES: [&str; 8] = [
    "register",
    "deregister",
    "discover",
    "enroll",
    "inbox",
    "tasks/submit",
    "tasks/result",
    "tasks/status",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceProxyConfig {
    pub per_ip: usize,
    pub total: usize,
    pub ip_header: Option<HeaderName>,
}

impl InstanceProxyConfig {
    /// `None` unless `GATEWAY_INSTANCE_PROXY` is `on`/`true`/`1`.
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> anyhow::Result<Option<Self>> {
        let on = get(ENABLE_ENV).map(|v| v.trim().to_ascii_lowercase()).unwrap_or_default();
        match on.as_str() {
            "on" | "true" | "1" => {}
            "" | "off" | "false" | "0" => return Ok(None),
            other => anyhow::bail!("{ENABLE_ENV}={other:?}: expected on|off"),
        }
        let num = |k: &str, d: usize| -> anyhow::Result<usize> {
            match get(k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty()) {
                None => Ok(d),
                Some(v) => v.parse().map_err(|e| anyhow::anyhow!("{k}={v:?}: {e}")),
            }
        };
        let ip_header = match get("GATEWAY_CLIENT_IP_HEADER").map(|h| h.trim().to_string()).filter(|h| !h.is_empty()) {
            None => None,
            Some(h) => Some(HeaderName::try_from(h.as_str()).map_err(|e| anyhow::anyhow!("GATEWAY_CLIENT_IP_HEADER={h:?}: {e}"))?),
        };
        Ok(Some(Self {
            per_ip: num("GATEWAY_INSTANCE_IP_PER_HOUR", 3600)?,
            total: num("GATEWAY_INSTANCE_TOTAL_PER_HOUR", 60000)?,
            ip_header,
        }))
    }
}

pub struct InstanceProxy {
    config: InstanceProxyConfig,
    base_url: String,
    client: reqwest::Client,
    limiter: Mutex<Limiter>,
}

impl InstanceProxy {
    pub fn new(config: InstanceProxyConfig, base_url: &str) -> anyhow::Result<Arc<Self>> {
        let client = reqwest::Client::builder()
            .timeout(UPSTREAM_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Arc::new(Self {
            config,
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
            limiter: Mutex::new(Limiter::default()),
        }))
    }

    fn admit(&self, ip: &str, now: u64) -> Result<(), u64> {
        let keys = [(format!("inst:ip:{ip}"), self.config.per_ip), ("inst:all".to_string(), self.config.total)];
        self.limiter.lock().unwrap_or_else(|e| e.into_inner()).admit(&keys, now)
    }
}

/// The eight public routes. Merge into the app only when enabled.
pub fn routes(state: Arc<InstanceProxy>) -> Router {
    let mut r = Router::new();
    for route in ROUTES {
        r = r.route(
            &format!("/api/instances/{route}"),
            post(move |s: State<Arc<InstanceProxy>>, req: Request| forward(s, req, route)),
        );
    }
    r.with_state(state)
}

fn json_err(status: StatusCode, error: &str) -> Response {
    (status, [(CACHE_CONTROL, HeaderValue::from_static("no-store"))], axum::Json(json!({ "error": error }))).into_response()
}

/// The only request header that reaches the server.
pub(crate) fn forwarded_headers(incoming: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    let ct = incoming.get(CONTENT_TYPE).cloned().unwrap_or(HeaderValue::from_static("application/json"));
    out.insert(CONTENT_TYPE, ct);
    out
}

async fn forward(State(s): State<Arc<InstanceProxy>>, req: Request, route: &'static str) -> Response {
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0);
    let (parts, body) = req.into_parts();
    let ip = client_ip(s.config.ip_header.as_ref(), &parts.headers, peer);
    if let Err(wait) = s.admit(&ip, now_secs()) {
        let mut r = json_err(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
        if let Ok(v) = HeaderValue::from_str(&wait.to_string()) {
            r.headers_mut().insert(RETRY_AFTER, v);
        }
        return r;
    }
    let body: Bytes = match to_bytes(body, MAX_BODY).await {
        Ok(b) => b,
        Err(_) => return json_err(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
    };
    let res = match s
        .client
        .post(format!("{}/api/instances/{route}", s.base_url))
        .headers(forwarded_headers(&parts.headers))
        .body(body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(route, error = %e, "instance proxy: upstream unreachable");
            return json_err(StatusCode::BAD_GATEWAY, "upstream_unreachable");
        }
    };
    let status = StatusCode::from_u16(res.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut out = Response::builder().status(status).header(CACHE_CONTROL, "no-store");
    if let Some(v) = res.headers().get(CONTENT_TYPE.as_str()).and_then(|v| HeaderValue::from_bytes(v.as_bytes()).ok()) {
        out = out.header(CONTENT_TYPE, v);
    }
    match res.bytes().await {
        Ok(b) => out.body(Body::from(b)).unwrap_or_else(|_| json_err(StatusCode::BAD_GATEWAY, "bad_upstream_response")),
        Err(_) => json_err(StatusCode::BAD_GATEWAY, "upstream_read_failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;
    use axum::routing::any;
    use std::collections::HashMap;

    fn cfg(pairs: &[(&str, &str)]) -> anyhow::Result<Option<InstanceProxyConfig>> {
        let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        InstanceProxyConfig::from_lookup(|k| m.get(k).cloned())
    }

    #[test]
    fn off_by_default_and_parses_limits() {
        assert_eq!(cfg(&[]).unwrap(), None);
        assert_eq!(cfg(&[(ENABLE_ENV, "off")]).unwrap(), None);
        assert!(cfg(&[(ENABLE_ENV, "yes please")]).is_err());
        let c = cfg(&[(ENABLE_ENV, "on")]).unwrap().unwrap();
        assert_eq!((c.per_ip, c.total), (3600, 60000));
        let c = cfg(&[(ENABLE_ENV, "1"), ("GATEWAY_INSTANCE_IP_PER_HOUR", "7"), ("GATEWAY_INSTANCE_TOTAL_PER_HOUR", "9")]).unwrap().unwrap();
        assert_eq!((c.per_ip, c.total), (7, 9));
    }

    async fn mock() -> String {
        async fn echo(method: Method, uri: axum::http::Uri, h: HeaderMap, body: Bytes) -> Response {
            let names: Vec<String> = h.keys().map(|k| k.to_string()).collect();
            (StatusCode::ACCEPTED, axum::Json(json!({"method": method.as_str(), "path": uri.path(), "headers": names, "len": body.len()}))).into_response()
        }
        let app = Router::new().route("/{*rest}", any(echo));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        format!("http://{addr}")
    }

    async fn serve(app: Router) -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn forwards_the_eight_routes_unchanged_and_nothing_else() {
        let up = mock().await;
        let c = InstanceProxyConfig { per_ip: 1000, total: 1000, ip_header: None };
        let app = routes(InstanceProxy::new(c, &up).unwrap())
            .merge(Router::new().route("/api/{*path}", any(|| async { (StatusCode::NOT_FOUND, "not here") })));
        let gw = serve(app).await;
        let http = reqwest::Client::new();
        for r in ROUTES {
            let res = http
                .post(format!("{gw}/api/instances/{r}"))
                .header("authorization", "Bearer x")
                .header("cookie", "a=b")
                .header("x-session-token", "t")
                .json(&json!({"alg": "ML-DSA-87", "payload": "{}"}))
                .send()
                .await
                .unwrap();
            assert_eq!(res.status(), 202, "{r}: upstream status passes through");
            let v: serde_json::Value = res.json().await.unwrap();
            assert_eq!(v["path"], format!("/api/instances/{r}"));
            assert_eq!(v["method"], "POST");
            let hs: Vec<&str> = v["headers"].as_array().unwrap().iter().filter_map(|h| h.as_str()).collect();
            assert!(hs.contains(&"content-type"), "{hs:?}");
            assert!(!hs.iter().any(|h| *h == "authorization" || *h == "cookie" || h.starts_with("x-")), "{hs:?}");
        }
        // The operator routes are never exposed, nor anything else under /api/instances.
        for p in ["/api/runtime/instances", "/api/runtime/instances/enrollments", "/api/instances/other"] {
            assert_eq!(http.post(format!("{gw}{p}")).send().await.unwrap().status(), 404, "{p}");
        }
        assert_eq!(http.get(format!("{gw}/api/instances/discover")).send().await.unwrap().status(), 405);
        let big = vec![b'a'; MAX_BODY + 1];
        assert_eq!(http.post(format!("{gw}/api/instances/register")).body(big).send().await.unwrap().status(), 413);
    }

    #[tokio::test]
    async fn rate_limited_and_unreachable() {
        let up = mock().await;
        let c = InstanceProxyConfig { per_ip: 2, total: 100, ip_header: Some(HeaderName::from_static("cf-connecting-ip")) };
        let gw = serve(routes(InstanceProxy::new(c, &up).unwrap())).await;
        let http = reqwest::Client::new();
        let call = |ip: &'static str| http.post(format!("{gw}/api/instances/discover")).header("cf-connecting-ip", ip).body("{}").send();
        assert_eq!(call("1.1.1.1").await.unwrap().status(), 202);
        assert_eq!(call("1.1.1.1").await.unwrap().status(), 202);
        let r = call("1.1.1.1").await.unwrap();
        assert_eq!(r.status(), 429);
        assert!(r.headers().get("retry-after").is_some());
        assert_eq!(call("2.2.2.2").await.unwrap().status(), 202);

        let c = InstanceProxyConfig { per_ip: 10, total: 10, ip_header: None };
        let gw = serve(routes(InstanceProxy::new(c, "http://127.0.0.1:9").unwrap())).await;
        assert_eq!(reqwest::Client::new().post(format!("{gw}/api/instances/register")).body("{}").send().await.unwrap().status(), 502);
    }
}
