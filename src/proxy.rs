//! Transparent proxy module for forwarding authenticated requests to NoETL server.
//!
//! This module provides a catch-all proxy that forwards any authenticated request
//! to the underlying NoETL API server. This means:
//!
//! 1. Gateway only handles authentication
//! 2. All NoETL API functionality is available through the proxy
//! 3. No gateway changes needed when NoETL adds new APIs
//!
//! Usage:
//! - `/noetl/*path` - Forwards to `{NOETL_BASE_URL}/api/*path`
//! - Requires valid session token in Authorization header

use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, Method, Request, Response, StatusCode},
    response::IntoResponse,
};
use std::sync::Arc;

use crate::noetl_client::NoetlClient;
use crate::sharding::{
    extract_execution_id_from_body, extract_execution_id_from_path,
    path_carries_execution_id_in_body, ShardMap,
};

/// Shared state for proxy handlers.
#[derive(Clone)]
pub struct ProxyState {
    /// Default upstream URL — used when the shard map is empty
    /// (current single-replica deployments) OR when the request
    /// path doesn't carry an `execution_id`
    /// (`POST /noetl/execute`, body-param routes pending R3a-2).
    pub noetl_base_url: String,
    /// Phase F R3a of noetl/ai-meta#49 — shard map for the
    /// noetl-server cluster.  Empty by default (no behavior
    /// change from pre-R3a single-replica setups).  See
    /// `src/sharding.rs` for the routing semantics.
    pub shard_map: ShardMap,
    pub http_client: reqwest::Client,
}

impl ProxyState {
    /// Build a [`ProxyState`] with a single upstream (the
    /// pre-R3a constructor signature; preserved for tests and
    /// any caller that hasn't migrated yet).  Equivalent to
    /// `with_shards(base_url, ShardMap::empty())`.
    pub fn new(noetl_base_url: String) -> Self {
        Self::with_shards(noetl_base_url, ShardMap::empty())
    }

    /// Build a [`ProxyState`] with both the default upstream
    /// and a (possibly empty) shard map.  Phase F R3a entry
    /// point; called from `main.rs` after loading the gateway
    /// config.
    pub fn with_shards(noetl_base_url: String, shard_map: ShardMap) -> Self {
        Self {
            noetl_base_url,
            shard_map,
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(300)) // 5 min timeout for long operations
                .build()
                .unwrap_or_default(),
        }
    }

    /// Resolve the upstream base URL for a proxied request.
    ///
    /// - When the shard map is empty (no sharding configured),
    ///   returns the default `noetl_base_url`.
    /// - When the shard map is populated AND the path carries
    ///   a parseable `execution_id` (e.g.
    ///   `/noetl/executions/{id}/...`), returns the matching
    ///   shard's `base_url`.
    /// - When the shard map is populated AND the path is a
    ///   body-param route (`/noetl/events`, `/noetl/events/batch`)
    ///   AND `body_bytes` carries a JSON object with a top-level
    ///   `execution_id`, returns the matching shard's `base_url`.
    ///   This is the Phase F R3a-2 path.
    /// - Otherwise (`/noetl/execute` where the server mints the
    ///   id; cluster-wide routes like `/noetl/catalog/*`; any
    ///   route where parsing fails), falls back to the default
    ///   `noetl_base_url`.
    ///
    /// `body_bytes` is `None` for GET/DELETE (no body to parse)
    /// and `Some(&[])` or `Some(&[..])` for other methods.  Empty
    /// slices short-circuit cleanly through
    /// [`extract_execution_id_from_body`].
    fn resolve_upstream(&self, path: &str, body_bytes: Option<&[u8]>) -> &str {
        if !self.shard_map.is_configured() {
            return &self.noetl_base_url;
        }
        // Path-based routing (R3a) — covers
        // /noetl/executions/{id}/... and /noetl/vars/{id}/...
        if let Some(eid) = extract_execution_id_from_path(path) {
            if let Some(url) = self.shard_map.route(eid) {
                return url;
            }
        }
        // Body-based routing (R3a-2) — covers /noetl/events
        // and /noetl/events/batch.  Gated by the path predicate
        // so we don't waste cycles parsing JSON for routes that
        // don't carry execution_id in the body.
        if path_carries_execution_id_in_body(path) {
            if let Some(bytes) = body_bytes {
                if let Some(eid) = extract_execution_id_from_body(bytes) {
                    if let Some(url) = self.shard_map.route(eid) {
                        return url;
                    }
                }
            }
        }
        // Neither path nor body yielded a parseable id (or the
        // shard map didn't have a matching entry).  Fall back
        // to the default upstream — the safe choice for
        // /noetl/execute (server mints the id), cluster-wide
        // routes (any shard answers), or malformed bodies (the
        // server returns 400 once we forward).
        &self.noetl_base_url
    }
}

/// Proxy handler for GET requests.
pub async fn proxy_get(
    State(state): State<Arc<ProxyState>>,
    Path(path): Path<String>,
    req: Request<Body>,
) -> impl IntoResponse {
    proxy_request(state, &path, Method::GET, req).await
}

/// Proxy handler for POST requests.
pub async fn proxy_post(
    State(state): State<Arc<ProxyState>>,
    Path(path): Path<String>,
    req: Request<Body>,
) -> impl IntoResponse {
    proxy_request(state, &path, Method::POST, req).await
}

/// Proxy handler for PUT requests.
pub async fn proxy_put(
    State(state): State<Arc<ProxyState>>,
    Path(path): Path<String>,
    req: Request<Body>,
) -> impl IntoResponse {
    proxy_request(state, &path, Method::PUT, req).await
}

/// Proxy handler for DELETE requests.
pub async fn proxy_delete(
    State(state): State<Arc<ProxyState>>,
    Path(path): Path<String>,
    req: Request<Body>,
) -> impl IntoResponse {
    proxy_request(state, &path, Method::DELETE, req).await
}

/// Proxy handler for PATCH requests.
pub async fn proxy_patch(
    State(state): State<Arc<ProxyState>>,
    Path(path): Path<String>,
    req: Request<Body>,
) -> impl IntoResponse {
    proxy_request(state, &path, Method::PATCH, req).await
}

/// Proxy handler for OPTIONS preflight requests.
pub async fn proxy_options() -> impl IntoResponse {
    StatusCode::NO_CONTENT
}

/// Core proxy logic that forwards requests to NoETL server.
async fn proxy_request(state: Arc<ProxyState>, path: &str, method: Method, req: Request<Body>) -> Response<Body> {
    // Phase F R3a-2: read the body BEFORE choosing the upstream
    // URL so body-param routes (POST /noetl/events,
    // /events/batch) can inspect the JSON for `execution_id`.
    // Split into parts + body so headers stay accessible after
    // the body is consumed.
    let (parts, body) = req.into_parts();

    // Get request body for non-GET methods.
    let body_bytes: Vec<u8> = match method {
        Method::GET | Method::DELETE => Vec::new(),
        _ => match axum::body::to_bytes(body, 10 * 1024 * 1024).await {
            Ok(bytes) => bytes.to_vec(),
            Err(e) => {
                tracing::error!("Failed to read request body: {}", e);
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("Failed to read request body"))
                    .unwrap();
            }
        },
    };

    // Phase F R3a + R3a-2: resolve the upstream URL.  When the
    // shard map is empty (current single-replica deployments),
    // returns the default `noetl_base_url`.  When configured,
    // looks up the shard by:
    // - R3a: `execution_id` extracted from the path
    //   (`/noetl/executions/{id}/...`, `/noetl/vars/{id}/...`).
    // - R3a-2: `execution_id` extracted from the JSON body for
    //   `events` + `events/batch` routes.
    // Falls back to default for routes the helpers can't parse
    // (`/noetl/execute`, cluster-wide reads, malformed bodies).
    let body_opt: Option<&[u8]> = if body_bytes.is_empty() {
        None
    } else {
        Some(body_bytes.as_slice())
    };
    let base = state.resolve_upstream(path, body_opt).trim_end_matches('/');
    let target_url = format!("{}/api/{}", base, path);

    // Get query string if present
    let query = parts.uri.query().map(|q| format!("?{}", q)).unwrap_or_default();
    let full_url = format!("{}{}", target_url, query);

    tracing::debug!(
        target_url = %full_url,
        method = %method,
        sharded = state.shard_map.is_configured(),
        body_param_route = path_carries_execution_id_in_body(path),
        "Proxying request to NoETL"
    );

    // Build the proxied request
    let mut proxy_req = match method {
        Method::GET => state.http_client.get(&full_url),
        Method::POST => state.http_client.post(&full_url),
        Method::PUT => state.http_client.put(&full_url),
        Method::DELETE => state.http_client.delete(&full_url),
        Method::PATCH => state.http_client.patch(&full_url),
        _ => {
            return Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Body::from("Method not allowed"))
                .unwrap();
        }
    };

    // Forward Content-Type header
    if let Some(content_type) = parts.headers.get(header::CONTENT_TYPE) {
        if let Ok(ct) = content_type.to_str() {
            proxy_req = proxy_req.header(header::CONTENT_TYPE, ct);
        }
    }

    // Forward Accept header
    if let Some(accept) = parts.headers.get(header::ACCEPT) {
        if let Ok(a) = accept.to_str() {
            proxy_req = proxy_req.header(header::ACCEPT, a);
        }
    }

    // Forward custom headers that might be needed
    for (name, value) in parts.headers.iter() {
        let name_str = name.as_str().to_lowercase();
        // Forward x-* headers (custom headers from client)
        if name_str.starts_with("x-") {
            if let Ok(v) = value.to_str() {
                proxy_req = proxy_req.header(name.as_str(), v);
            }
        }
    }

    if !body_bytes.is_empty() {
        tracing::debug!(path = %path, body_bytes = body_bytes.len(), "Proxying request body to NoETL");
        proxy_req = proxy_req.body(body_bytes);
    }

    // Send the request
    let proxy_response = match proxy_req.send().await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!("Proxy request failed: {}", e);
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(r#"{{"error": "Proxy request failed: {}"}}"#, e)))
                .unwrap();
        }
    };

    // Build response
    let status = proxy_response.status();
    let mut response_builder = Response::builder().status(status);

    // Forward response headers
    for (name, value) in proxy_response.headers() {
        let name_str = name.as_str().to_lowercase();
        // Forward content-type, content-length, and custom headers
        if name_str == "content-type" || name_str == "content-length" || name_str.starts_with("x-") {
            if let Ok(v) = value.to_str() {
                response_builder = response_builder.header(name.as_str(), v);
            }
        }
    }

    // Get response body
    match proxy_response.bytes().await {
        Ok(bytes) => response_builder.body(Body::from(bytes.to_vec())).unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Failed to build response"))
                .unwrap()
        }),
        Err(e) => {
            tracing::error!("Failed to read proxy response: {}", e);
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(r#"{{"error": "Failed to read response: {}"}}"#, e)))
                .unwrap()
        }
    }
}

#[cfg(test)]
mod catalog_surface_tests {
    //! Guards for the catalog API surface reaching the NoETL server through the
    //! gateway (noetl/ai-meta catalog programme).
    //!
    //! The proxy is generic — `/noetl/{*path}` → `{NOETL_BASE_URL}/api/{path}` —
    //! so the catalog endpoints need no per-route wiring. That is convenient and
    //! it is also exactly why it needs a test: "it should work because the proxy
    //! is generic" is an assumption about a mapping nothing asserts, and the
    //! catalog surface grew three new endpoints that a reader would reasonably
    //! expect to find registered somewhere.

    /// The upstream URL the proxy builds, mirrored from `proxy_request`.
    ///
    /// Kept in step by the structural test below, which fails if the real
    /// format string changes.
    fn upstream(base: &str, path: &str) -> String {
        format!("{}/api/{}", base, path)
    }

    /// Every catalog endpoint the CLI and operators call maps to the server's
    /// `/api/*` path unchanged.
    #[test]
    fn the_catalog_surface_maps_onto_the_server_api() {
        let base = "http://noetl-server:8082";
        for (incoming, expected) in [
            ("catalog/register", "http://noetl-server:8082/api/catalog/register"),
            // The bulk-load endpoint the CLI's `catalog load` uses.
            (
                "catalog/register/batch",
                "http://noetl-server:8082/api/catalog/register/batch",
            ),
            ("catalog/list", "http://noetl-server:8082/api/catalog/list"),
            (
                "catalog-log/backfill",
                "http://noetl-server:8082/api/catalog-log/backfill",
            ),
            (
                "catalog-log/coverage",
                "http://noetl-server:8082/api/catalog-log/coverage",
            ),
        ] {
            assert_eq!(upstream(base, incoming), expected, "mapping for {incoming}");
        }
    }

    /// A nested path keeps every segment.
    ///
    /// `catalog/register/batch` has two segments after `catalog`; a proxy that
    /// took only the first would silently route a bulk load to the single
    /// register endpoint — which would still return 200, having registered one
    /// item instead of N.
    #[test]
    fn nested_paths_keep_every_segment() {
        assert_eq!(
            upstream("http://s", "catalog/register/batch"),
            "http://s/api/catalog/register/batch"
        );
        assert_ne!(
            upstream("http://s", "catalog/register/batch"),
            upstream("http://s", "catalog/register"),
            "a bulk load must not collapse onto the single-register endpoint"
        );
    }

    /// ⭐ The mirror above must match the real mapping.
    ///
    /// Counting the format string in the source, so a change to how the upstream
    /// URL is built fails here rather than leaving these tests asserting a
    /// mapping the code no longer performs.
    #[test]
    fn the_mirrored_mapping_matches_the_real_one() {
        let src = include_str!("proxy.rs");
        let code = src
            .split_once("\n#[cfg(test)]")
            .map(|(above, _)| above)
            .unwrap_or(src);
        assert!(
            code.contains(r#"format!("{}/api/{}", base, path)"#),
            "proxy_request no longer builds the upstream URL as `{{base}}/api/{{path}}`; \
             the mapping asserted by these tests is stale"
        );
    }

    /// ⚠ The proxy is behind auth, and must stay there.
    ///
    /// It forwards EVERY `/api/*` path, including the privileged catalog-log and
    /// credential surfaces. Losing the auth layer would expose them all at once,
    /// and nothing about the proxy code itself would look different.
    #[test]
    fn the_proxy_routes_are_auth_gated_in_main() {
        let main = include_str!("main.rs");
        let at = main
            .find("let proxy_routes = Router::new()")
            .expect("proxy_routes must exist");
        let tail = &main[at..];
        let end = tail.find(".with_state(").expect("proxy_routes must be finished");
        let block = &tail[..end];
        assert!(
            block.contains("auth::middleware::auth_middleware"),
            "the /noetl proxy is no longer auth-gated; it forwards every /api/* \
             path, so this would expose the whole server API at once:\n{block}"
        );
    }
}

