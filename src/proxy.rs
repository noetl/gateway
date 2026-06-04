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
use crate::sharding::{extract_execution_id_from_path, ShardMap};

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
    /// - Otherwise (sharding configured but path doesn't carry
    ///   an `execution_id`: `/noetl/execute`, `/noetl/events`
    ///   pre-R3a-2, etc.), falls back to the default
    ///   `noetl_base_url`.
    fn resolve_upstream(&self, path: &str) -> &str {
        if !self.shard_map.is_configured() {
            return &self.noetl_base_url;
        }
        if let Some(eid) = extract_execution_id_from_path(path) {
            if let Some(url) = self.shard_map.route(eid) {
                return url;
            }
        }
        // Path doesn't carry a parseable execution_id, OR the
        // shard map didn't yield a match.  Fall back to the
        // default upstream — this is the safe choice for
        // R3a-scoped routes (execute, events, events/batch).
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
    // Phase F R3a: resolve the upstream URL.  When the shard
    // map is empty (current single-replica deployments), this
    // returns the default `noetl_base_url` — unchanged from
    // pre-R3a behavior.  When configured, looks up the shard
    // for path-based execution_ids.
    let base = state.resolve_upstream(path).trim_end_matches('/');
    let target_url = format!("{}/api/{}", base, path);

    // Get query string if present
    let query = req.uri().query().map(|q| format!("?{}", q)).unwrap_or_default();
    let full_url = format!("{}{}", target_url, query);

    tracing::debug!(
        target_url = %full_url,
        method = %method,
        sharded = state.shard_map.is_configured(),
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
    if let Some(content_type) = req.headers().get(header::CONTENT_TYPE) {
        if let Ok(ct) = content_type.to_str() {
            proxy_req = proxy_req.header(header::CONTENT_TYPE, ct);
        }
    }

    // Forward Accept header
    if let Some(accept) = req.headers().get(header::ACCEPT) {
        if let Ok(a) = accept.to_str() {
            proxy_req = proxy_req.header(header::ACCEPT, a);
        }
    }

    // Forward custom headers that might be needed
    for (name, value) in req.headers() {
        let name_str = name.as_str().to_lowercase();
        // Forward x-* headers (custom headers from client)
        if name_str.starts_with("x-") {
            if let Ok(v) = value.to_str() {
                proxy_req = proxy_req.header(name.as_str(), v);
            }
        }
    }

    // Get request body for non-GET methods
    let body_bytes = match method {
        Method::GET | Method::DELETE => vec![],
        _ => match axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024).await {
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
