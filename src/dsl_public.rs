//! Public, read-only DSL knowledge-base routes (ai-meta RFC dsl-knowledge-base,
//! ADR 2026-11-07-dsl-kb-live-upstream-gated, step 3).
//!
//! `GET  /noetl/api/dsl/{version,schema,tools}` and
//! `POST /noetl/api/dsl/validate` → the server's `/api/dsl/<route>`.
//!
//! * **Off unless `GATEWAY_PUBLIC_DSL=on`.** Unset, nothing is mounted and
//!   `/noetl/api/dsl/*` stays behind the authenticated proxy as before.
//! * **No auth, and no credentials forwarded.** Only `accept`,
//!   `if-none-match` and (for POST) `content-type` reach the server. Cookies,
//!   `authorization` and `x-*` headers are dropped. The routes are stateless on
//!   the server: they describe the grammar and parse a document; validate never
//!   registers or runs anything.
//! * **Exactly four routes.** Any other `/noetl/...` path keeps going through
//!   the authenticated proxy.
//! * **Rate-limited** per client IP and in total, per hour
//!   (`GATEWAY_PUBLIC_DSL_IP_PER_HOUR`, default 1200;
//!   `GATEWAY_PUBLIC_DSL_TOTAL_PER_HOUR`, default 12000), using the same
//!   sliding-window limiter as guest sessions and the same trusted client-IP
//!   header (`GATEWAY_CLIENT_IP_HEADER`).
//! * POST bodies over 256 KiB are refused (413) before anything is sent.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{
    body::{to_bytes, Body, Bytes},
    extract::{ConnectInfo, Request, State},
    http::{
        header::{ACCEPT, CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_NONE_MATCH, RETRY_AFTER},
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode,
    },
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use serde_json::json;

use crate::guest::{client_ip, now_secs, Limiter};

pub const ENABLE_ENV: &str = "GATEWAY_PUBLIC_DSL";
pub const MAX_BODY: usize = 256 * 1024;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DslPublicConfig {
    pub per_ip: usize,
    pub total: usize,
    pub ip_header: Option<HeaderName>,
}

impl DslPublicConfig {
    /// `None` unless `GATEWAY_PUBLIC_DSL` is `on`/`true`/`1`.
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
            per_ip: num("GATEWAY_PUBLIC_DSL_IP_PER_HOUR", 1200)?,
            total: num("GATEWAY_PUBLIC_DSL_TOTAL_PER_HOUR", 12000)?,
            ip_header,
        }))
    }
}

pub struct DslPublic {
    config: DslPublicConfig,
    base_url: String,
    client: reqwest::Client,
    limiter: Mutex<Limiter>,
}

impl DslPublic {
    pub fn new(config: DslPublicConfig, base_url: &str) -> anyhow::Result<Arc<Self>> {
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
        let keys = [(format!("dsl:ip:{ip}"), self.config.per_ip), ("dsl:all".to_string(), self.config.total)];
        self.limiter.lock().unwrap_or_else(|e| e.into_inner()).admit(&keys, now)
    }
}

/// The four public routes. Merge into the app only when enabled.
pub fn routes(state: Arc<DslPublic>) -> Router {
    Router::new()
        .route("/noetl/api/dsl/version", get(version))
        .route("/noetl/api/dsl/schema", get(schema))
        .route("/noetl/api/dsl/tools", get(tools))
        .route("/noetl/api/dsl/validate", post(validate))
        .with_state(state)
}

fn json_err(status: StatusCode, error: &str) -> Response {
    (status, [(CACHE_CONTROL, HeaderValue::from_static("no-store"))], axum::Json(json!({ "error": error }))).into_response()
}

async fn version(s: State<Arc<DslPublic>>, req: Request) -> Response {
    forward(s, req, "version").await
}
async fn schema(s: State<Arc<DslPublic>>, req: Request) -> Response {
    forward(s, req, "schema").await
}
async fn tools(s: State<Arc<DslPublic>>, req: Request) -> Response {
    forward(s, req, "tools").await
}
async fn validate(s: State<Arc<DslPublic>>, req: Request) -> Response {
    forward(s, req, "validate").await
}

/// The only request headers that reach the server.
pub(crate) fn forwarded_headers(incoming: &HeaderMap, with_body: bool) -> HeaderMap {
    let mut out = HeaderMap::new();
    let mut names = vec![ACCEPT, IF_NONE_MATCH];
    if with_body {
        names.push(CONTENT_TYPE);
    }
    for n in names {
        if let Some(v) = incoming.get(&n) {
            out.insert(n, v.clone());
        }
    }
    if with_body && !out.contains_key(CONTENT_TYPE) {
        out.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    }
    out
}

async fn forward(State(s): State<Arc<DslPublic>>, req: Request, route: &'static str) -> Response {
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0);
    let (parts, body) = req.into_parts();
    let headers = parts.headers;
    let method = parts.method;
    let ip = client_ip(s.config.ip_header.as_ref(), &headers, peer);
    if let Err(wait) = s.admit(&ip, now_secs()) {
        let mut r = json_err(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
        if let Ok(v) = HeaderValue::from_str(&wait.to_string()) {
            r.headers_mut().insert(RETRY_AFTER, v);
        }
        return r;
    }
    let with_body = method == Method::POST;
    let body: Bytes = if with_body {
        match to_bytes(body, MAX_BODY).await {
            Ok(b) => b,
            Err(_) => return json_err(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
        }
    } else {
        Bytes::new()
    };
    let mut req = s
        .client
        .request(method, format!("{}/api/dsl/{route}", s.base_url))
        .headers(forwarded_headers(&headers, with_body));
    if with_body {
        req = req.body(body);
    }
    let res = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(route, error = %e, "public dsl: upstream unreachable");
            return json_err(StatusCode::BAD_GATEWAY, "upstream_unreachable");
        }
    };
    let status = StatusCode::from_u16(res.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut out = Response::builder().status(status);
    for n in [CONTENT_TYPE, ETAG, CACHE_CONTROL] {
        if let Some(v) = res.headers().get(n.as_str()).and_then(|v| HeaderValue::from_bytes(v.as_bytes()).ok()) {
            out = out.header(n, v);
        }
    }
    match res.bytes().await {
        Ok(b) => out.body(Body::from(b)).unwrap_or_else(|_| json_err(StatusCode::BAD_GATEWAY, "bad_upstream_response")),
        Err(_) => json_err(StatusCode::BAD_GATEWAY, "upstream_read_failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::any;
    use std::collections::HashMap;

    fn cfg(pairs: &[(&str, &str)]) -> anyhow::Result<Option<DslPublicConfig>> {
        let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        DslPublicConfig::from_lookup(|k| m.get(k).cloned())
    }

    #[test]
    fn off_by_default_and_parses_limits() {
        assert_eq!(cfg(&[]).unwrap(), None);
        assert_eq!(cfg(&[(ENABLE_ENV, "off")]).unwrap(), None);
        assert!(cfg(&[(ENABLE_ENV, "maybe")]).is_err());
        let c = cfg(&[(ENABLE_ENV, "on")]).unwrap().unwrap();
        assert_eq!((c.per_ip, c.total, c.ip_header), (1200, 12000, None));
        let c = cfg(&[
            (ENABLE_ENV, "true"),
            ("GATEWAY_PUBLIC_DSL_IP_PER_HOUR", "2"),
            ("GATEWAY_PUBLIC_DSL_TOTAL_PER_HOUR", "5"),
            ("GATEWAY_CLIENT_IP_HEADER", "cf-connecting-ip"),
        ])
        .unwrap()
        .unwrap();
        assert_eq!((c.per_ip, c.total), (2, 5));
        assert_eq!(c.ip_header.unwrap().as_str(), "cf-connecting-ip");
        assert!(cfg(&[(ENABLE_ENV, "on"), ("GATEWAY_PUBLIC_DSL_IP_PER_HOUR", "x")]).is_err());
    }

    #[test]
    fn never_forwards_credentials() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer secret".parse().unwrap());
        h.insert("cookie", "s=1".parse().unwrap());
        h.insert("x-session-token", "t".parse().unwrap());
        h.insert("accept", "application/json".parse().unwrap());
        h.insert("if-none-match", "\"abc\"".parse().unwrap());
        h.insert("content-type", "application/yaml".parse().unwrap());
        let get = forwarded_headers(&h, false);
        assert_eq!(get.len(), 2);
        assert!(get.get("authorization").is_none() && get.get("cookie").is_none());
        let post = forwarded_headers(&h, true);
        assert_eq!(post.len(), 3);
        assert_eq!(post.get("content-type").unwrap(), "application/yaml");
        assert_eq!(forwarded_headers(&HeaderMap::new(), true).get("content-type").unwrap(), "application/json");
    }

    /// Mock server that echoes the path and the headers it got.
    async fn mock() -> String {
        async fn echo(method: Method, uri: axum::http::Uri, h: HeaderMap, body: Bytes) -> Response {
            let names: Vec<String> = h.keys().map(|k| k.to_string()).collect();
            (
                [(ETAG, HeaderValue::from_static("\"d1\""))],
                axum::Json(json!({"method": method.as_str(), "path": uri.path(), "headers": names, "len": body.len()})),
            )
                .into_response()
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
    async fn routes_forward_only_the_four_and_strip_credentials() {
        let up = mock().await;
        let c = DslPublicConfig { per_ip: 100, total: 100, ip_header: None };
        // A catch-all stands in for the authenticated proxy: the public routes
        // must win for their four paths and nothing else.
        let app = routes(DslPublic::new(c, &up).unwrap())
            .merge(Router::new().route("/noetl/{*path}", any(|| async { (StatusCode::UNAUTHORIZED, "auth proxy") })));
        let gw = serve(app).await;
        let http = reqwest::Client::new();
        for r in ["version", "schema", "tools"] {
            let res = http.get(format!("{gw}/noetl/api/dsl/{r}")).header("authorization", "Bearer x").header("cookie", "a=b").send().await.unwrap();
            assert_eq!(res.status(), 200, "{r}");
            assert_eq!(res.headers().get("etag").unwrap(), "\"d1\"");
            let v: serde_json::Value = res.json().await.unwrap();
            assert_eq!(v["path"], format!("/api/dsl/{r}"));
            let hs = v["headers"].as_array().unwrap();
            assert!(!hs.iter().any(|h| h == "authorization" || h == "cookie"), "{hs:?}");
        }
        let res = http.post(format!("{gw}/noetl/api/dsl/validate")).header("authorization", "Bearer x").body("kind: Playbook").send().await.unwrap();
        assert_eq!(res.status(), 200);
        let v: serde_json::Value = res.json().await.unwrap();
        assert_eq!((v["method"].as_str(), v["path"].as_str(), v["len"].as_u64()), (Some("POST"), Some("/api/dsl/validate"), Some(14)));
        // Anything else stays on the authenticated proxy.
        for p in ["/noetl/api/dsl/other", "/noetl/executions/1", "/noetl/api/dsl/version/x"] {
            assert_eq!(http.get(format!("{gw}{p}")).send().await.unwrap().status(), 401, "{p}");
        }
        // Wrong method on a public path is not forwarded.
        assert_eq!(http.post(format!("{gw}/noetl/api/dsl/version")).send().await.unwrap().status(), 405);
        // Oversized body refused before the server sees it.
        let big = vec![b'a'; MAX_BODY + 1];
        assert_eq!(http.post(format!("{gw}/noetl/api/dsl/validate")).body(big).send().await.unwrap().status(), 413);
    }

    #[tokio::test]
    async fn rate_limited_per_ip_and_total() {
        let up = mock().await;
        let c = DslPublicConfig { per_ip: 2, total: 3, ip_header: Some(HeaderName::from_static("cf-connecting-ip")) };
        let gw = serve(routes(DslPublic::new(c, &up).unwrap())).await;
        let http = reqwest::Client::new();
        let call = |ip: &'static str| http.get(format!("{gw}/noetl/api/dsl/version")).header("cf-connecting-ip", ip).send();
        assert_eq!(call("1.1.1.1").await.unwrap().status(), 200);
        assert_eq!(call("1.1.1.1").await.unwrap().status(), 200);
        let r = call("1.1.1.1").await.unwrap();
        assert_eq!(r.status(), 429);
        assert!(r.headers().get("retry-after").is_some());
        assert_eq!(call("2.2.2.2").await.unwrap().status(), 200);
        // Total ceiling (3) reached.
        assert_eq!(call("3.3.3.3").await.unwrap().status(), 429);
    }

    #[tokio::test]
    async fn unreachable_upstream_is_502() {
        let c = DslPublicConfig { per_ip: 10, total: 10, ip_header: None };
        let gw = serve(routes(DslPublic::new(c, "http://127.0.0.1:9").unwrap())).await;
        let r = reqwest::get(format!("{gw}/noetl/api/dsl/version")).await.unwrap();
        assert_eq!(r.status(), 502);
    }
}
