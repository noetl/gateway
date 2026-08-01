#![allow(dead_code, unused_imports, unused_variables)]

use std::net::SocketAddr;
use std::sync::Arc;

use async_graphql::http::playground_source;
use async_graphql::{EmptySubscription, Schema};
use async_graphql_axum::GraphQL;
use axum::{
    extract::State,
    http::header::{AUTHORIZATION, CONTENT_TYPE},
    http::{HeaderName, Method},
    middleware,
    response::Html,
    routing::{delete, get, options, patch, post, put},
    Json, Router,
};
use dotenvy::dotenv;
use serde_json::{json, Value};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing_subscriber::EnvFilter;

mod auth;
mod callbacks;
mod config;
mod connection_hub;
mod ehdb_kv;
mod event_feed;
mod graphql;
mod ingress;
mod noetl_client;
mod playbook_state;
mod proxy;
mod request_store;
mod result_ext;
mod session_cache;
mod sharding;
mod sse;

use crate::callbacks::CallbackManager;
use crate::config::GatewayConfig;
use crate::connection_hub::ConnectionHub;
use crate::graphql::schema::{AppSchema, MutationRoot, QueryRoot};
use crate::noetl_client::NoetlClient;
use crate::proxy::ProxyState;
use crate::request_store::RequestStore;
use crate::result_ext::ResultExt;
use crate::session_cache::SessionCache;
use crate::sse::SseState;

#[ctor::ctor]
fn init() {
    dotenv().ok();
    tracing_subscriber::fmt()
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .with_target(true)
        .init();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load configuration from file and/or environment variables
    let config = GatewayConfig::load().log("Failed to load gateway configuration")?;

    // Log configuration summary
    tracing::info!("Gateway configuration loaded:");
    tracing::info!("  Server: {}:{}", config.server.bind, config.server.port);
    tracing::info!("  NoETL: {}", config.noetl.base_url);
    
    tracing::info!("  Auth playbooks:");
    tracing::info!("    login: {}", config.auth_playbooks.login);
    tracing::info!(
        "    validate_session (legacy fallback): {}",
        config.auth_playbooks.validate_session
    );
    tracing::info!(
        "    session_db_credential: {}",
        config.auth_playbooks.session_db_credential
    );
    tracing::info!("    check_access: {}", config.auth_playbooks.check_access);
    tracing::info!("    timeout: {}s", config.auth_playbooks.timeout_secs);

    let noetl = NoetlClient::new(config.noetl.base_url.clone());
    let noetl_arc = Arc::new(noetl);

    // Callback manager using NATS pub/sub
    let callback_manager = Arc::new(CallbackManager::new(Some(config.kv.callback_subject_prefix.clone())));

    // noetl/ai-meta#213 — the NATS callback listener is GONE.
    //
    // `noetl.callbacks.>` was a legacy delivery path. Every auth playbook that
    // still names `callback_subject` marks it "Legacy - kept for compatibility"
    // and delivers over `/api/internal/callback` instead, and all three auth
    // flows run on their sync fast-paths (NOETL_AUTH_SYNC / NOETL_AUTHZ_SYNC)
    // which never dispatch a playbook at all.
    //
    // It also could not have survived the NATS teardown: this call used `?`, so
    // a gateway with no NATS to reach exited 1 at boot. `CallbackManager` stays
    // — the HTTP endpoint uses its in-process registry.

    // The EHDB KV store backs both the session cache and the request store
    // (noetl/ai-meta#214/#215). There is no other backend since the NATS
    // removal, so an unset address is a hard startup error: the request store
    // backs EVERY SSE route, and a gateway that starts without it serves an SPA
    // that silently receives nothing.
    let kv_addr = std::env::var("NOETL_KV_ADDR").unwrap_or_default();
    if kv_addr.trim().is_empty() {
        anyhow::bail!(
            "NOETL_KV_ADDR is empty — the gateway has no KV store for its session \
             cache or its request store, and every SSE route would be dropped. \
             Point it at the events writer's KV face (e.g. \
             noetl-cmdbus-writer-0.noetl.svc.cluster.local:9107)."
        );
    }
    let kv_addr = kv_addr.trim();

    let session_cache = Arc::new(SessionCache::new(
        config.kv.session_bucket.clone(),
        config.kv.session_cache_ttl_secs,
        kv_addr,
    ));
    tracing::info!(
        "Session cache on EHDB KV: bucket={}, ttl={}s",
        config.kv.session_bucket,
        config.kv.session_cache_ttl_secs
    );

    // Initialize connection hub for SSE/WebSocket connections
    let connection_hub = Arc::new(ConnectionHub::new());

    let request_store = Arc::new(RequestStore::new(
        config.kv.request_bucket.clone(),
        config.kv.request_ttl_secs,
        kv_addr,
    ));
    // Probe once at startup. This store backs EVERY SSE route, so a bad address
    // must be loud here rather than silently dropping every route later
    // (noetl/ai-meta#214).
    if let Err(error) = request_store.probe().await {
        tracing::error!(%error, %kv_addr, "EHDB KV unreachable — SSE routing will not work");
    } else {
        tracing::info!(
            %kv_addr,
            "Request store on EHDB KV: bucket={}, ttl={}s",
            config.kv.request_bucket,
            config.kv.request_ttl_secs
        );
    }

    // Execution-lifecycle SSE forwarding, off the EHDB events feed
    // (noetl/ai-meta#212). The NATS listener it replaced is gone, so there is no
    // transport to select between any more — an unset address is a hard startup
    // error rather than a fallback, because a gateway that starts without a
    // lifecycle feed serves an SPA that hangs with nothing in the logs.
    let feed_addr = std::env::var("NOETL_EVENT_FEED_ADDR").unwrap_or_default();
    if feed_addr.trim().is_empty() {
        anyhow::bail!(
            "NOETL_EVENT_FEED_ADDR is empty — the gateway has no execution-lifecycle \
             feed and the SPA would receive no live updates. Point it at the events \
             writer's SSE face (e.g. noetl-cmdbus-writer-0.noetl.svc.cluster.local:9105)."
        );
    }
    if let Err(error) = event_feed::start_ehdb_feed_listener(
        feed_addr.trim(),
        request_store.clone(),
        connection_hub.clone(),
    )
    .await
    {
        tracing::warn!(%error, "EHDB execution lifecycle SSE forwarding disabled");
    }

    // SSE state for real-time callbacks
    let sse_state = Arc::new(SseState {
        connection_hub: connection_hub.clone(),
        request_store: request_store.clone(),
        session_cache: session_cache.clone(),
        heartbeat_interval_secs: config.transport.heartbeat_interval_secs,
    });

    // Combined auth state with configurable playbook paths and session cache
    let auth_state = Arc::new(auth::AuthState {
        noetl: noetl_arc.clone(),
        callbacks: callback_manager.clone(),
        playbook_config: config.auth_playbooks.clone(),
        session_cache: session_cache.clone(),
    });

    // Proxy state for forwarding requests to NoETL.  Phase F
    // R3a of noetl/ai-meta#49: construct an optional ShardMap
    // from the gateway config's `noetl.shards` table.  Empty
    // list (the default) → no sharding, gateway forwards every
    // request to `noetl.base_url` unchanged (current single-
    // replica behavior).  Populated list → routes path-param
    // execution_id requests to the matching shard; falls back
    // to `noetl.base_url` for paths without an execution_id
    // (e.g. `POST /noetl/execute`).  See `src/sharding.rs`.
    let shard_map = crate::sharding::ShardMap::from_endpoints(config.noetl.shards.clone())
        .unwrap_or_else(|e| {
            panic!(
                "invalid shard map in gateway config (noetl.shards): {e}.  \
                 Indices must be contiguous from 0 to N-1 with no duplicates."
            )
        });
    if shard_map.is_configured() {
        tracing::info!(
            shard_count = shard_map.shard_count(),
            "Gateway shard routing configured"
        );
    } else {
        tracing::info!(
            base_url = %config.noetl.base_url,
            "Gateway forwarding to single NoETL upstream (no sharding configured)"
        );
    }
    let proxy_state = Arc::new(ProxyState::with_shards(
        config.noetl.base_url.clone(),
        shard_map,
    ));

    // Wrap config in Arc for sharing with GraphQL context
    let config_arc = Arc::new(config.clone());

    let schema: AppSchema = Schema::build(QueryRoot, MutationRoot, async_graphql::EmptySubscription)
        .data(noetl_arc.clone())
        .data(proxy_state.clone())
        .data(request_store.clone())
        .data(config_arc.clone())
        .finish();

    // CORS configuration
    let cors_origins_str = config.cors_origins_string();
    let allowed_origins: Vec<axum::http::HeaderValue> = config
        .cors
        .allowed_origins
        .iter()
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    tracing::info!("CORS allowed origins: {:?}", cors_origins_str);

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(allowed_origins))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::PATCH,
            Method::OPTIONS,
        ])
        .allow_headers([
            CONTENT_TYPE,
            AUTHORIZATION,
            HeaderName::from_static("x-session-id"),
            HeaderName::from_static("x-session-token"),
            HeaderName::from_static("x-user-id"),
            HeaderName::from_static("x-request-id"),
        ])
        .allow_credentials(config.cors.allow_credentials);

    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/health", get(health_check))
        .route("/api/runtime/contract", get(runtime_contract))
        .route("/api/auth/login", post(auth::login))
        .route("/api/auth/validate", post(auth::validate_session))
        .route("/api/auth/check-access", post(auth::check_access))
        // Internal callback endpoint for workers to deliver results via HTTP
        .route("/api/internal/callback", post(auth::internal_callback))
        .with_state(auth_state.clone());

    // Sharding diagnostic — Phase F R3b-2 of noetl/ai-meta#49.
    // Twin of noetl-server's GET /api/runtime/shard-info.  Public;
    // pure math; no auth.  Computes locally (NOT a proxy
    // passthrough) so the integration test in noetl/ops can
    // verify gateway and server compute the same shard_index
    // independently.
    let sharding_diagnostic_routes = Router::new()
        .route("/sharding/preview", get(crate::sharding::get_shard_preview));

    // SSE routes for real-time callbacks (auth via query param)
    let sse_routes = Router::new()
        .route("/events", get(sse::sse_handler))
        .route("/api/internal/callback/async", post(sse::callback_handler))
        .route("/api/internal/progress", post(sse::progress_handler))
        .with_state(sse_state.clone());

    // Push-ingress routes (noetl/ai-meta#90 Phase 3) + the gateway's first
    // /metrics surface.  POST /ingress/{listener} terminates untrusted
    // push/webhook traffic: verify (HMAC / bearer / Pub-Sub OIDC) then —
    // only on success — apply directives + forward one POST /api/execute per
    // delivery.  No session auth (a source, not a user); the auth IS the
    // per-delivery signature/token (RFC §6).
    let ingress_registry = Arc::new(prometheus::Registry::new());
    let ingress_metrics = ingress::IngressMetrics::register(&ingress_registry)
        .log("Failed to register ingress metrics")?;
    let ingress_routes = if let Some(token) = config.internal_api_token.clone() {
        let ingress_state = Arc::new(ingress::IngressState::new(
            config.noetl.base_url.clone(),
            token,
            ingress_metrics,
        ));
        tracing::info!("Push-ingress enabled: POST /ingress/{{listener}} (verify → forward)");
        Router::new()
            .route("/ingress/{listener}", post(ingress::push_ingress))
            .with_state(ingress_state)
    } else {
        tracing::warn!(
            "Push-ingress disabled: NOETL_INTERNAL_API_TOKEN unset — /ingress/{{listener}} returns 503"
        );
        Router::new().route("/ingress/{listener}", post(ingress_disabled))
    };
    let metrics_routes = Router::new()
        .route("/metrics", get(ingress::metrics_handler))
        .with_state(ingress_registry);

    // Protected GraphQL routes (auth required)
    let graphql_routes = Router::new()
        .route("/graphql", get(graphiql).post_service(GraphQL::new(schema.clone())))
        .route("/graphql", options(proxy::proxy_options))
        .route_layer(middleware::from_fn_with_state(
            auth_state.clone(),
            auth::middleware::auth_middleware,
        ))
        .with_state(());

    // Protected proxy routes - forward authenticated requests to NoETL server
    // Route: /noetl/{path} -> NoETL /api/{path}
    let proxy_routes = Router::new()
        .route("/noetl/{*path}", get(proxy::proxy_get))
        .route("/noetl/{*path}", post(proxy::proxy_post))
        .route("/noetl/{*path}", put(proxy::proxy_put))
        .route("/noetl/{*path}", delete(proxy::proxy_delete))
        .route("/noetl/{*path}", patch(proxy::proxy_patch))
        .route("/noetl/{*path}", options(proxy::proxy_options))
        .route_layer(middleware::from_fn_with_state(
            auth_state.clone(),
            auth::middleware::auth_middleware,
        ))
        .with_state(proxy_state);

    // Main gateway app
    let app = Router::new()
        .merge(public_routes)
        .merge(sharding_diagnostic_routes)
        .merge(sse_routes)
        .merge(ingress_routes)
        .merge(metrics_routes)
        .merge(graphql_routes)
        .merge(proxy_routes)
        .layer(cors);

    let addr = SocketAddr::from(([0, 0, 0, 0], config.server.port));
    tracing::info!(%addr, noetl_base = %config.noetl.base_url, "starting gateway server http://localhost:{}", config.server.port);
    tracing::info!("Auth endpoints: POST /api/auth/login, POST /api/auth/validate, POST /api/auth/check-access");
    tracing::info!("Runtime contract: GET /api/runtime/contract");
    tracing::info!("Internal endpoint: POST /api/internal/callback (for worker callbacks)");
    tracing::info!("SSE endpoint: GET /events?session_token=xxx (real-time callbacks)");
    tracing::info!("Async callback: POST /api/internal/callback/async (for async playbook results)");
    tracing::info!("Protected GraphQL: POST /graphql (requires authentication)");
    tracing::info!("Protected Proxy: /noetl/* -> NoETL /api/* (requires authentication)");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .log("Failed to bind to address")?;
    axum::serve(listener, app).await.log("Failed to serve app")?;
    Ok(())
}

async fn health_check() -> &'static str {
    "ok"
}

/// Fallback for `/ingress/{listener}` when push-ingress is not configured
/// (`NOETL_INTERNAL_API_TOKEN` unset).  503 — no permissive default for a
/// privileged forward surface (noetl/ai-meta#90 Phase 3).
async fn ingress_disabled() -> (axum::http::StatusCode, &'static str) {
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "push-ingress not configured (NOETL_INTERNAL_API_TOKEN unset)",
    )
}

/// Pure builder for the optional ``auth0`` block of the runtime
/// contract.  Returns ``None`` when ``domain`` is empty (the whole
/// block is omitted in that case) and drops individual fields that
/// are empty so the CLI can tell which pieces of metadata the
/// deployment actually carries.  Split from the env-reading
/// ``build_auth0_runtime_block`` so it can be unit-tested without
/// global state mutation.
///
/// See ``Auth0Config`` in ``src/config/gateway_config.rs`` for the
/// "informational only" contract.
fn build_auth0_runtime_block_from(
    domain: &str,
    client_id: &str,
    redirect_uri: &str,
    audience: &str,
) -> Option<Value> {
    let domain = domain.trim();
    if domain.is_empty() {
        return None;
    }
    let mut block = serde_json::Map::new();
    block.insert("domain".to_string(), Value::String(domain.to_string()));
    for (value, key) in [
        (client_id, "client_id"),
        (redirect_uri, "redirect_uri"),
        (audience, "audience"),
    ] {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            block.insert(key.to_string(), Value::String(trimmed.to_string()));
        }
    }
    Some(Value::Object(block))
}

/// Build the optional ``auth0`` block of the runtime contract from
/// the gateway's environment.  The ``GATEWAY_AUTH0_*`` env vars are
/// set by the Helm chart (see noetl/ops `automation/helm/gateway`)
/// from the operator's chart values.  Thin wrapper around
/// ``build_auth0_runtime_block_from``.
fn build_auth0_runtime_block() -> Option<Value> {
    let domain = std::env::var("GATEWAY_AUTH0_DOMAIN").unwrap_or_default();
    let client_id = std::env::var("GATEWAY_AUTH0_CLIENT_ID").unwrap_or_default();
    let redirect_uri = std::env::var("GATEWAY_AUTH0_REDIRECT_URI").unwrap_or_default();
    let audience = std::env::var("GATEWAY_AUTH0_AUDIENCE").unwrap_or_default();
    build_auth0_runtime_block_from(&domain, &client_id, &redirect_uri, &audience)
}

async fn runtime_contract() -> Json<Value> {
    let mut body = json!({
        "gateway_version": env!("CARGO_PKG_VERSION"),
        "contract_version": "2026-04-26",
        "summary": "Gateway authenticates clients and forwards canonical NoETL API calls. Agent and MCP activity is executed by NoETL playbooks/workers, not by Gateway.",
        "routes": {
            "public": [
                "GET /health",
                "GET /api/runtime/contract",
                "POST /api/auth/login",
                "POST /api/auth/validate",
                "POST /api/auth/check-access",
                "POST /api/internal/callback",
                "POST /api/internal/callback/async",
                "POST /api/internal/progress",
                "GET /events?session_token=..."
            ],
            "protected": [
                "ANY /noetl/{*path}",
                "POST /graphql",
                "GET /graphql"
            ]
        },
        "proxy_contract": {
            "incoming_prefix": "/noetl/",
            "upstream_prefix": "/api/",
            "supported_methods": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
            "authentication": {
                "required": true,
                "accepted_headers": [
                    "Authorization: Bearer <session_token>",
                    "x-session-token: <session_token>"
                ],
                "middleware": "auth_middleware"
            },
            "forwarded_request_headers": [
                "Content-Type",
                "Accept",
                "x-* custom headers"
            ],
            "forwarded_response_headers": [
                "Content-Type",
                "Content-Length",
                "x-* custom headers"
            ]
        },
        "cli_operation_mapping": {
            "exec": "/noetl/execute",
            "status": "/noetl/executions/{id}/status",
            "detail": "/noetl/executions/{id}",
            "events": "/noetl/executions/{id}/events",
            "cancel": "/noetl/executions/{id}/cancel",
            "catalog_list": "/noetl/catalog/list",
            "agent_catalog_list": "/noetl/catalog/agents/list",
            "catalog_register": "/noetl/catalog/register",
            "query": "/noetl/postgres/execute"
        },
        "execution_contract": {
            "start": {
                "method": "POST",
                "path": "/noetl/execute",
                "body": "{ path|catalog_id, workload, resource_kind: \"playbook\"|\"agent\" }"
            },
            "status": {
                "method": "GET",
                "path": "/noetl/executions/{id}/status"
            },
            "detail": {
                "method": "GET",
                "path": "/noetl/executions/{id}"
            },
            "events": {
                "method": "GET",
                "path": "/noetl/executions/{id}/events"
            },
            "cancel": {
                "method": "POST",
                "path": "/noetl/executions/{id}/cancel"
            }
        },
        "agent_contract": {
            "model": "agent-as-playbook",
            "discovery": "/noetl/catalog/agents/list",
            "invocation": "/noetl/execute",
            "state": "/noetl/executions/{id}",
            "mcp": "MCP servers are reached by NoETL worker tool execution, so activity is captured in NoETL command/event/execution state."
        }
    });

    // Optional ``auth0`` block — surfaced when the Helm chart sets
    // ``env.auth0Domain`` (which the deployment template maps to
    // ``GATEWAY_AUTH0_DOMAIN``).  Consumed by ``noetl context init
    // --from-gateway <url>`` to bootstrap a CLI context with the
    // right Auth0 application metadata.  See ``Auth0Config`` for
    // the full contract.
    if let Some(auth0) = build_auth0_runtime_block() {
        if let Value::Object(ref mut obj) = body {
            obj.insert("auth0".to_string(), auth0);
        }
    }

    Json(body)
}

async fn graphiql(State(()): State<()>) -> Html<String> {
    let html = playground_source(async_graphql::http::GraphQLPlaygroundConfig::new("/graphql"));
    Html(html)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth0_block_omitted_when_domain_empty() {
        // Deployments without Auth0 set domain="" and the runtime
        // contract simply omits the whole block.
        assert!(build_auth0_runtime_block_from("", "any-id", "any-uri", "any-aud").is_none());
        assert!(build_auth0_runtime_block_from("   ", "x", "y", "z").is_none(),
            "whitespace-only domain should also be treated as absent");
    }

    #[test]
    fn auth0_block_includes_only_non_empty_fields() {
        // domain present + client_id present; redirect_uri and audience
        // empty are dropped from the emitted block.
        let block = build_auth0_runtime_block_from(
            "acme.auth0.com",
            "abc123",
            "",
            "",
        )
        .expect("domain present -> block present");
        let obj = block.as_object().unwrap();
        assert_eq!(obj.get("domain").and_then(|v| v.as_str()), Some("acme.auth0.com"));
        assert_eq!(obj.get("client_id").and_then(|v| v.as_str()), Some("abc123"));
        assert!(obj.get("redirect_uri").is_none(), "empty fields are dropped");
        assert!(obj.get("audience").is_none());
    }

    #[test]
    fn auth0_block_full_carries_every_field() {
        let block = build_auth0_runtime_block_from(
            "  acme.auth0.com  ",
            "  Jqop7YoaiZalLHdBRo5ScNQ1RJhbhbDN  ",
            "https://travel.example.com/login",
            "https://api.example.com",
        )
        .unwrap();
        let obj = block.as_object().unwrap();
        // Values are trimmed before insertion.
        assert_eq!(obj.get("domain").and_then(|v| v.as_str()), Some("acme.auth0.com"));
        assert_eq!(
            obj.get("client_id").and_then(|v| v.as_str()),
            Some("Jqop7YoaiZalLHdBRo5ScNQ1RJhbhbDN")
        );
        assert_eq!(
            obj.get("redirect_uri").and_then(|v| v.as_str()),
            Some("https://travel.example.com/login")
        );
        assert_eq!(
            obj.get("audience").and_then(|v| v.as_str()),
            Some("https://api.example.com")
        );
    }
}
