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
mod graphql;
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
    tracing::info!("  NATS: {}", config.nats.url);
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
    let callback_manager = Arc::new(CallbackManager::new(Some(config.nats.callback_subject_prefix.clone())));

    // Start NATS callback listener
    callbacks::start_nats_listener(&config.nats.url, callback_manager.clone())
        .await
        .log("Failed to start NATS callback listener")?;

    // Initialize session cache using NATS K/V (optional - degrades gracefully)
    let session_cache = Arc::new(SessionCache::new(
        config.nats.session_bucket.clone(),
        config.nats.session_cache_ttl_secs,
    ));
    let cache_enabled = session_cache.connect(&config.nats.url).await.unwrap_or(false);
    if cache_enabled {
        tracing::info!(
            "Session cache enabled: bucket={}, ttl={}s",
            config.nats.session_bucket,
            config.nats.session_cache_ttl_secs
        );
    } else {
        tracing::warn!(
            "Session cache disabled (NATS K/V unavailable) - all validations will query Postgres via NoETL API"
        );
    }

    // Initialize connection hub for SSE/WebSocket connections
    let connection_hub = Arc::new(ConnectionHub::new());

    // Initialize request store for pending playbook callbacks (optional - degrades gracefully)
    let request_store = Arc::new(RequestStore::new(
        config.nats.request_bucket.clone(),
        config.nats.request_ttl_secs,
    ));
    let request_store_enabled = request_store.connect(&config.nats.url).await.unwrap_or(false);
    if request_store_enabled {
        tracing::info!(
            "Request store enabled: bucket={}, ttl={}s",
            config.nats.request_bucket,
            config.nats.request_ttl_secs
        );
    } else {
        tracing::warn!("Request store disabled (NATS K/V unavailable) - async callbacks will not work");
    }

    if let Err(error) = playbook_state::start_playbook_state_listener(
        &config.nats.url,
        &config.nats.updates_subject_prefix,
        request_store.clone(),
        connection_hub.clone(),
    )
    .await
    {
        tracing::warn!(%error, "Execution lifecycle SSE forwarding disabled");
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

    // SSE routes for real-time callbacks (auth via query param)
    let sse_routes = Router::new()
        .route("/events", get(sse::sse_handler))
        .route("/api/internal/callback/async", post(sse::callback_handler))
        .route("/api/internal/progress", post(sse::progress_handler))
        .with_state(sse_state.clone());

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
        .merge(sse_routes)
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
