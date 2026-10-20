//! Simplified GraphQL schema for gateway.
//!
//! The gateway acts as an authenticated proxy. Most API calls should go through
//! the REST proxy at /noetl/* which forwards directly to NoETL server.
//!
//! This GraphQL schema provides:
//! - Health check
//! - executePlaybook mutation (used by auth module for login/validate playbooks)
//! - rerunExecution mutation (canonical execution rerun flow)
//! - proxyRequest mutation (generic API proxy for clients preferring GraphQL)
//!
//! Who may call which mutation is `crate::authorization`: a regular user only
//! `executePlaybook` of an allowlisted playbook; an admin everything.

use async_graphql::{Context, EmptySubscription, Enum, Json, Object, Result as GqlResult, Schema};
use std::sync::Arc;
use uuid::Uuid;

use super::types::*;
use crate::auth::types::UserContext;
use crate::authorization::{ExecutionOwners, Policy};
use crate::config::GatewayConfig;
use crate::noetl_client::NoetlClient;
use crate::request_store::{PendingRequest, RequestStore};

pub type AppSchema = Schema<QueryRoot, MutationRoot, EmptySubscription>;

/// Overwrite identity variables with the authenticated caller's Auth0 subject
/// (see `crate::identity`). The caller is the `UserContext` the auth middleware
/// verified; `graphql_handler` puts it into the request data. With no
/// `UserContext` at all there is no verified caller, which fails closed exactly
/// like a session without a subject.
fn bind_caller_identity(ctx: &Context<'_>, args: &mut serde_json::Value, target: &str, force: bool) -> GqlResult<()> {
    let user = ctx.data_opt::<UserContext>();
    let subject = user.and_then(|u| u.auth0_sub.as_deref());
    let bypass = crate::auth::middleware::is_auth_bypass_enabled();
    let bound = if force {
        crate::identity::bind_identity_all(args, subject, bypass)
    } else {
        crate::identity::bind_identity(args, subject, bypass)
    };
    match bound {
        Ok(b) => {
            if !b.overridden.is_empty() {
                tracing::warn!(
                    target = target,
                    user_id = user.map(|u| u.user_id).unwrap_or(0),
                    vars = ?b.overridden,
                    "client-supplied identity replaced by the session subject"
                );
            }
            Ok(())
        }
        Err(e) => {
            tracing::warn!(target = target, "identity-bound execution refused: {}", e);
            Err(async_graphql::Error::new(e.to_string()))
        }
    }
}

fn policy(ctx: &Context<'_>) -> Arc<Policy> {
    ctx.data_opt::<Arc<Policy>>().cloned().unwrap_or_default()
}

fn not_authorized() -> async_graphql::Error {
    async_graphql::Error::new("not authorized")
}

/// `crate::authorization` for `executePlaybook`: an admin may start anything,
/// a regular user only an allowlisted playbook.
fn authorize_execute(ctx: &Context<'_>, name: &str, kind: &str) -> GqlResult<()> {
    let Some(user) = ctx.data_opt::<UserContext>() else {
        crate::ingress::record_route_authz("denied");
        return Err(not_authorized());
    };
    let policy = policy(ctx);
    if policy.is_admin(user) {
        crate::ingress::record_route_authz("admin");
        Ok(())
    } else if policy.may_execute(user, name, kind) {
        crate::ingress::record_route_authz("user_allowed");
        Ok(())
    } else {
        crate::ingress::record_route_authz("denied");
        tracing::warn!(user_id = user.user_id, target = name, kind = kind, "executePlaybook refused");
        Err(not_authorized())
    }
}

/// `crate::authorization` for mutations only an admin may call.
fn require_admin(ctx: &Context<'_>, what: &str) -> GqlResult<()> {
    match ctx.data_opt::<UserContext>() {
        Some(user) if policy(ctx).is_admin(user) => {
            crate::ingress::record_route_authz("admin");
            Ok(())
        }
        user => {
            crate::ingress::record_route_authz("denied");
            tracing::warn!(user_id = user.map(|u| u.user_id).unwrap_or(0), what = what, "admin-only mutation refused");
            Err(not_authorized())
        }
    }
}

/// Remember who started `execution_id`, so they can poll and cancel it.
/// A guest's execution counts against its rate limits (`crate::guest`); a
/// refusal is a GraphQL error with `code: RATE_LIMITED` and `retryAfter`
/// (seconds). Sessions that are not guests pass untouched.
fn admit_guest_run(ctx: &Context<'_>) -> GqlResult<()> {
    use async_graphql::ErrorExtensions;
    let Some(guest) = ctx.data_opt::<UserContext>().and_then(|u| u.guest.as_ref()) else {
        return Ok(());
    };
    // A guest session only exists when guest mode is on; without its limits, refuse.
    let Some(guests) = ctx.data_opt::<Arc<crate::guest::GuestSessions>>() else {
        return Err(not_authorized());
    };
    guests.admit_run(guest).map_err(|crate::guest::RateLimited(wait)| {
        crate::ingress::record_route_authz("guest_rate_limited");
        tracing::debug!(retry_after = wait, "guest executePlaybook refused: rate limit");
        async_graphql::Error::new("Too many requests; try again later").extend_with(|_, e| {
            e.set("code", "RATE_LIMITED");
            e.set("retryAfter", wait);
        })
    })
}

async fn record_owner(ctx: &Context<'_>, execution_id: &str) {
    crate::authorization::record_owner(
        ctx.data_opt::<Arc<ExecutionOwners>>(),
        execution_id,
        ctx.data_opt::<UserContext>(),
    )
    .await;
}

#[derive(Enum, Copy, Clone, Eq, PartialEq)]
enum ExecutableResourceKind {
    #[graphql(name = "playbook")]
    Playbook,
    #[graphql(name = "agent")]
    Agent,
}

impl ExecutableResourceKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Playbook => "playbook",
            Self::Agent => "agent",
        }
    }
}

// ============================================================================
// QUERY ROOT
// ============================================================================

pub struct QueryRoot;

#[Object]
impl QueryRoot {
    /// Health check endpoint.
    async fn health(&self) -> &str {
        "ok"
    }

    /// Gateway version info.
    async fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
}

// ============================================================================
// MUTATION ROOT
// ============================================================================

pub struct MutationRoot;

#[Object]
impl MutationRoot {
    /// Execute a playbook by path.
    ///
    /// For async callbacks (real-time results via SSE):
    /// 1. Connect to SSE endpoint first: GET /events?session_token=xxx
    /// 2. Use the returned client_id when calling this mutation
    /// 3. Results will be pushed via SSE as `playbook/result` notifications
    ///
    /// For simple fire-and-forget (no real-time results):
    /// - Omit client_id parameter
    /// - Poll NoETL API for execution status
    async fn execute_playbook(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Playbook path")] name: String,
        #[graphql(desc = "Execution variables")] variables: Option<Json<serde_json::Value>>,
        #[graphql(name = "resourceKind", desc = "Executable catalog resource kind: playbook or agent")]
        resource_kind: Option<ExecutableResourceKind>,
        #[graphql(desc = "Client ID from SSE connection (for async callbacks)")] client_id: Option<String>,
    ) -> GqlResult<ExecuteResult> {
        let client = ctx.data::<Arc<NoetlClient>>()?;
        let mut args = variables.map(|j| j.0).unwrap_or(serde_json::json!({}));
        let catalog_kind = resource_kind.unwrap_or(ExecutableResourceKind::Playbook).as_str();
        authorize_execute(ctx, &name, catalog_kind)?;
        bind_caller_identity(ctx, &mut args, &name, false)?;
        admit_guest_run(ctx)?;

        // If client_id is provided, set up async callback
        let request_id = if let Some(cid) = client_id.as_ref() {
            // Try to get request store and config from context
            let request_store = ctx.data::<Arc<RequestStore>>().ok();
            let config = ctx.data::<Arc<GatewayConfig>>().ok();

            if let Some(store) = request_store {
                let rid = Uuid::new_v4().to_string();

                // Get gateway URL for callbacks
                let gateway_url = config
                    .and_then(|c| c.server.public_url.clone())
                    .unwrap_or_else(|| "http://gateway.gateway.svc.cluster.local:8090".to_string());

                // Inject callback info into playbook args
                if let serde_json::Value::Object(ref mut map) = args {
                    map.insert("request_id".to_string(), serde_json::json!(rid));
                    map.insert("gateway_url".to_string(), serde_json::json!(gateway_url));
                }

                // We'll store the pending request after we get the execution_id
                Some((rid, cid.clone(), store.clone()))
            } else {
                tracing::warn!("Request store not available, async callbacks disabled");
                None
            }
        } else {
            None
        };

        let result = client
            .execute_catalog_entry(&name, args, catalog_kind)
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;
        record_owner(ctx, &result.execution_id).await;

        // Store pending request for callback routing
        let final_request_id = if let Some((rid, cid, store)) = request_id {
            // Get session token from context if available
            let session_token = ctx.data::<String>().cloned().unwrap_or_default();

            let pending = PendingRequest {
                client_id: cid,
                session_token,
                execution_id: result.execution_id.clone(),
                playbook_path: name.clone(),
                created_at: chrono::Utc::now().timestamp(),
            };

            if let Err(e) = store.put(&rid, &pending).await {
                tracing::error!("Failed to store pending request: {}", e);
            } else {
                tracing::debug!(
                    "Pending request stored: request_id={}, execution_id={}",
                    &rid[..8.min(rid.len())],
                    &result.execution_id[..8.min(result.execution_id.len())]
                );
            }

            Some(rid)
        } else {
            None
        };

        Ok(ExecuteResult {
            id: result.execution_id.clone(),
            execution_id: result.execution_id,
            request_id: final_request_id,
            name: result.name.or(Some(name)),
            status: result.status,
            text_output: None, // Results delivered via SSE callback
        })
    }

    /// Rerun an existing execution with optional workload overrides.
    ///
    /// Uses canonical NoETL rerun endpoint:
    /// POST /api/executions/{execution_id}/rerun
    async fn rerun_execution(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Source execution ID to rerun")] execution_id: String,
        #[graphql(desc = "Workload overrides for rerun")] variables: Option<Json<serde_json::Value>>,
        #[graphql(desc = "Client ID from SSE connection (for async callbacks)")] client_id: Option<String>,
    ) -> GqlResult<ExecuteResult> {
        let client = ctx.data::<Arc<NoetlClient>>()?;
        let mut args = variables.map(|j| j.0).unwrap_or(serde_json::json!({}));
        require_admin(ctx, "rerunExecution")?;
        // Forced: a rerun replays the source execution's stored workload, so an
        // identity this request omits would otherwise be the source's.
        bind_caller_identity(ctx, &mut args, &format!("rerun:{}", execution_id), true)?;

        // If client_id is provided, set up async callback tracking for rerun.
        let request_id = if let Some(cid) = client_id.as_ref() {
            let request_store = ctx.data::<Arc<RequestStore>>().ok();
            let config = ctx.data::<Arc<GatewayConfig>>().ok();

            if let Some(store) = request_store {
                let rid = Uuid::new_v4().to_string();
                let gateway_url = config
                    .and_then(|c| c.server.public_url.clone())
                    .unwrap_or_else(|| "http://gateway.gateway.svc.cluster.local:8090".to_string());

                if let serde_json::Value::Object(ref mut map) = args {
                    map.insert("request_id".to_string(), serde_json::json!(rid));
                    map.insert("gateway_url".to_string(), serde_json::json!(gateway_url));
                }

                Some((rid, cid.clone(), store.clone()))
            } else {
                tracing::warn!("Request store not available, async callbacks disabled");
                None
            }
        } else {
            None
        };

        let result = client
            .rerun_execution(&execution_id, args)
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;
        record_owner(ctx, &result.execution_id).await;

        let final_request_id = if let Some((rid, cid, store)) = request_id {
            let session_token = ctx.data::<String>().cloned().unwrap_or_default();

            let pending = PendingRequest {
                client_id: cid,
                session_token,
                execution_id: result.execution_id.clone(),
                playbook_path: format!("rerun:{}", execution_id),
                created_at: chrono::Utc::now().timestamp(),
            };

            if let Err(e) = store.put(&rid, &pending).await {
                tracing::error!("Failed to store pending request: {}", e);
            } else {
                tracing::debug!(
                    "Pending rerun request stored: request_id={}, execution_id={}",
                    &rid[..8.min(rid.len())],
                    &result.execution_id[..8.min(result.execution_id.len())]
                );
            }

            Some(rid)
        } else {
            None
        };

        Ok(ExecuteResult {
            id: result.execution_id.clone(),
            execution_id: result.execution_id,
            request_id: final_request_id,
            name: result.name.or(result.path),
            status: result.status,
            text_output: None,
        })
    }

    /// Generic proxy for any NoETL API call via GraphQL.
    /// This allows clients to make any API request through GraphQL if they prefer
    /// that over the REST proxy at /noetl/*.
    ///
    /// Example:
    /// ```graphql
    /// mutation {
    ///   proxyRequest(input: {
    ///     method: "POST",
    ///     endpoint: "/api/catalog/list",
    ///     body: { "resource_type": "Playbook" }
    ///   }) {
    ///     success
    ///     data
    ///     error
    ///   }
    /// }
    /// ```
    async fn proxy_request(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "Proxy request parameters")] input: ProxyRequestInput,
    ) -> GqlResult<ProxyResponse> {
        require_admin(ctx, "proxyRequest")?;
        let client = ctx.data::<Arc<NoetlClient>>()?;

        let body = input.body.map(|j| j.0);

        match client.api_call(&input.method, &input.endpoint, body).await {
            Ok(data) => Ok(ProxyResponse {
                success: true,
                data: Some(Json(data)),
                error: None,
            }),
            Err(e) => Ok(ProxyResponse {
                success: false,
                data: None,
                error: Some(e.to_string()),
            }),
        }
    }
}
