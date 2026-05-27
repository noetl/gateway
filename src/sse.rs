//! Server-Sent Events (SSE) endpoint for real-time playbook callbacks.
//!
//! Clients connect to GET /events with their session token to receive
//! playbook execution results in real-time via SSE.

use axum::{
    extract::{Query, State},
    response::{
        sse::{Event, Sse},
        IntoResponse,
    },
};
use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio_stream::StreamExt;
use uuid::Uuid;

use crate::connection_hub::{ConnectionHub, JsonRpcMessage, SseSender};
use crate::firestore_subscriptions::FirestoreSubscriptionManager;
use crate::request_store::{PendingRequest, RequestStore};
use crate::session_cache::SessionCache;

/// SSE connection query parameters
#[derive(Debug, Deserialize)]
pub struct SseParams {
    /// Session token for authentication
    pub session_token: String,
    /// Optional client_id for reconnection
    pub client_id: Option<String>,
}

/// SSE app state
pub struct SseState {
    pub connection_hub: Arc<ConnectionHub>,
    pub request_store: Arc<RequestStore>,
    pub session_cache: Arc<SessionCache>,
    pub firestore_subscriptions: Option<Arc<FirestoreSubscriptionManager>>,
    pub heartbeat_interval_secs: u64,
}

/// Initialization response data
#[derive(Serialize)]
struct InitResponse {
    #[serde(rename = "protocolVersion")]
    protocol_version: String,
    #[serde(rename = "serverInfo")]
    server_info: ServerInfo,
    #[serde(rename = "clientId")]
    client_id: String,
    capabilities: Capabilities,
    #[serde(rename = "pendingRequests", skip_serializing_if = "Option::is_none")]
    pending_requests: Option<Vec<PendingRequestInfo>>,
}

#[derive(Serialize)]
struct ServerInfo {
    name: String,
    version: String,
}

#[derive(Serialize)]
struct Capabilities {
    playbooks: bool,
    callbacks: bool,
    subscriptions: bool,
    #[serde(rename = "playbookState")]
    playbook_state: bool,
}

#[derive(Serialize)]
struct PendingRequestInfo {
    #[serde(rename = "requestId")]
    request_id: String,
    #[serde(rename = "executionId")]
    execution_id: String,
    #[serde(rename = "playbookPath")]
    playbook_path: String,
}

/// SSE endpoint handler
///
/// GET /events?session_token=xxx&client_id=yyy
///
/// Returns Server-Sent Events stream with JSON-RPC 2.0 messages
pub async fn sse_handler(
    State(state): State<Arc<SseState>>,
    Query(params): Query<SseParams>,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    // Validate session token
    let session = match state.session_cache.get(&params.session_token).await {
        Some(s) if s.is_active => s,
        _ => {
            // Return error as SSE event then close
            let error_msg = JsonRpcMessage::error_response(
                None,
                crate::connection_hub::error_codes::UNAUTHORIZED,
                "Invalid or expired session",
                None,
            );
            let event = Event::default()
                .event("error")
                .data(serde_json::to_string(&error_msg).unwrap_or_default());

            let error_stream = futures::stream::once(async move { Ok::<_, Infallible>(event) });
            return Sse::new(error_stream)
                .keep_alive(axum::response::sse::KeepAlive::new())
                .into_response();
        }
    };

    // Generate or reuse client_id
    let client_id = params.client_id.unwrap_or_else(|| Uuid::new_v4().to_string());

    // Create channel for sending events to client
    let (tx, rx): (SseSender, mpsc::UnboundedReceiver<JsonRpcMessage>) = mpsc::unbounded_channel();

    // Register connection
    state
        .connection_hub
        .register_sse(client_id.clone(), params.session_token.clone(), tx.clone())
        .await;

    // Get pending requests for reconnection recovery
    let pending_requests = if state.request_store.is_connected().await {
        let requests = state.request_store.get_by_client(&client_id).await;
        if requests.is_empty() {
            None
        } else {
            Some(
                requests
                    .into_iter()
                    .map(|(request_id, req)| PendingRequestInfo {
                        request_id,
                        execution_id: req.execution_id,
                        playbook_path: req.playbook_path,
                    })
                    .collect(),
            )
        }
    } else {
        None
    };

    // Send initialization message
    let init_response = InitResponse {
        protocol_version: "2024-11-05".to_string(),
        server_info: ServerInfo {
            name: "noetl-gateway".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        client_id: client_id.clone(),
        capabilities: Capabilities {
            playbooks: true,
            callbacks: true,
            subscriptions: state.firestore_subscriptions.is_some(),
            playbook_state: true,
        },
        pending_requests,
    };

    let init_msg = JsonRpcMessage::response(
        serde_json::json!(1),
        serde_json::to_value(init_response).unwrap_or_default(),
    );

    let _ = tx.send(init_msg);

    tracing::info!(
        "SSE connection established: client_id={}, user={}",
        &client_id[..8.min(client_id.len())],
        session.email
    );

    // Create stream from receiver
    let message_stream = UnboundedReceiverStream::new(rx);

    // Clone for cleanup
    let hub = state.connection_hub.clone();
    let client_id_for_cleanup = client_id.clone();
    let heartbeat_interval = state.heartbeat_interval_secs;

    // Create heartbeat stream
    let heartbeat_stream = async_stream::stream! {
        let mut interval = tokio::time::interval(Duration::from_secs(heartbeat_interval));
        loop {
            interval.tick().await;
            let ping = JsonRpcMessage::notification("ping", serde_json::json!({}));
            yield ping;
        }
    };

    // Merge message stream with heartbeat
    let combined_stream = futures::stream::select(
        message_stream,
        Box::pin(heartbeat_stream) as std::pin::Pin<Box<dyn Stream<Item = JsonRpcMessage> + Send>>,
    );

    // Map to SSE events
    let event_stream = combined_stream.map(move |msg| {
        let event_type = msg.method.as_deref().unwrap_or("message");
        let data = serde_json::to_string(&msg).unwrap_or_default();
        Ok::<_, Infallible>(Event::default().event(event_type).data(data))
    });

    // Wrap in a stream that cleans up on drop
    let cleanup_stream = CleanupStream {
        inner: Box::pin(event_stream),
        hub,
        client_id: client_id_for_cleanup,
        cleaned_up: false,
    };

    Sse::new(cleanup_stream)
        .keep_alive(
            axum::response::sse::KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("ping"),
        )
        .into_response()
}

/// Stream wrapper that cleans up connection on drop
struct CleanupStream<S> {
    inner: std::pin::Pin<Box<S>>,
    hub: Arc<ConnectionHub>,
    client_id: String,
    cleaned_up: bool,
}

impl<S: Stream<Item = Result<Event, Infallible>> + Send> Stream for CleanupStream<S> {
    type Item = Result<Event, Infallible>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

impl<S> Drop for CleanupStream<S> {
    fn drop(&mut self) {
        if !self.cleaned_up {
            self.cleaned_up = true;
            let hub = self.hub.clone();
            let client_id = self.client_id.clone();
            tokio::spawn(async move {
                hub.unregister(&client_id).await;
                tracing::info!(
                    "SSE connection closed: client_id={}",
                    &client_id[..8.min(client_id.len())]
                );
            });
        }
    }
}

/// Worker callback request (received from playbooks)
#[derive(Debug, Deserialize)]
pub struct WorkerCallback {
    pub request_id: String,
    #[serde(default)]
    pub execution_id: Option<String>,
    #[serde(default = "default_status")]
    pub status: String,
    #[serde(default)]
    pub data: serde_json::Value,
    #[serde(default)]
    pub error: Option<WorkerCallbackError>,
}

fn default_status() -> String {
    "COMPLETED".to_string()
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorkerCallbackError {
    pub code: Option<i32>,
    pub message: String,
    #[serde(default)]
    pub data: Option<serde_json::Value>,
}

/// Internal callback handler
///
/// POST /api/internal/callback
///
/// Receives playbook results from workers and routes to connected clients
pub async fn callback_handler(
    State(state): State<Arc<SseState>>,
    axum::Json(callback): axum::Json<WorkerCallback>,
) -> impl IntoResponse {
    tracing::info!(
        "Callback received: request_id={}, status={}",
        &callback.request_id[..8.min(callback.request_id.len())],
        callback.status
    );

    // Look up the pending request
    let pending_request = match state.request_store.get(&callback.request_id).await {
        Some(req) => req,
        None => {
            tracing::warn!(
                "Callback for unknown request_id: {}",
                &callback.request_id[..8.min(callback.request_id.len())]
            );
            return (
                axum::http::StatusCode::NOT_FOUND,
                axum::Json(serde_json::json!({"error": "Request not found"})),
            );
        }
    };

    // The SPA's ``waitForExecutionCompletion(executionId)`` (see
    // ``noetl/travel/src/api/noetlClient.ts``) resolves on a
    // ``playbook/state`` notification whose ``event_type`` is
    // ``playbook.completed`` / ``playbook.failed`` and whose
    // ``execution_id`` matches.  That signal is also produced by the
    // ``playbook_state.rs`` NATS listener when noetl publishes the
    // matching lifecycle event on ``noetl.events.>``.
    //
    // The two signals race.  In production the HTTP callback POST
    // from the worker consistently arrives first — by ~270ms in the
    // 2026-05-27 itinerary-planner SPA-hang incident.  Because
    // ``request_store.remove(&callback.request_id)`` runs at the end
    // of this handler, the entry that the NATS listener needs in
    // order to call ``request_store.get_by_execution(...)`` is gone
    // by the time the lifecycle event arrives.  Result: the SPA
    // hangs at ``Muno is planning…`` forever even though the worker
    // succeeded.
    //
    // Fix: when the callback fires, also emit a synthetic
    // ``playbook/state`` notification carrying the same
    // ``execution_id`` + completion status.  The NATS-derived state
    // event (when it eventually arrives) is then redundant; the
    // SPA's lifecycle map keys by ``execution_id`` and a second
    // delivery is a no-op (see ``handlePlaybookState`` early-return
    // when ``pending`` is missing).
    let resolved_execution_id = callback
        .execution_id
        .clone()
        .unwrap_or_else(|| pending_request.execution_id.clone());
    let failed = callback.status == "FAILED" || callback.error.is_some();
    let state_event_type = if failed { "playbook.failed" } else { "playbook.completed" };
    let state_status = if failed { "failed" } else { "completed" };
    let state_message = JsonRpcMessage::notification(
        "playbook/state",
        serde_json::json!({
            "execution_id": resolved_execution_id,
            "event_type": state_event_type,
            "step_name": serde_json::Value::Null,
            "status": state_status,
            "at": chrono::Utc::now().to_rfc3339(),
        }),
    );

    // Build the JSON-RPC notification
    let message = if failed {
        let error = callback.error.unwrap_or(WorkerCallbackError {
            code: Some(crate::connection_hub::error_codes::PLAYBOOK_FAILED),
            message: "Playbook execution failed".to_string(),
            data: None,
        });

        JsonRpcMessage::notification(
            "playbook/result",
            serde_json::json!({
                "requestId": callback.request_id,
                "executionId": resolved_execution_id,
                "status": "FAILED",
                "error": {
                    "code": error.code.unwrap_or(crate::connection_hub::error_codes::PLAYBOOK_FAILED),
                    "message": error.message,
                    "data": error.data
                }
            }),
        )
    } else {
        JsonRpcMessage::notification(
            "playbook/result",
            serde_json::json!({
                "requestId": callback.request_id,
                "executionId": resolved_execution_id,
                "status": callback.status,
                "data": callback.data
            }),
        )
    };

    // Emit the synthetic lifecycle notification first so the SPA's
    // ``waitForExecutionCompletion(executionId)`` resolves before
    // the ``playbook/result`` arrives.  Order matters in the SPA:
    // ``handlePlaybookState`` flips the chat out of the
    // ``"Muno is planning…"`` state, and ``handlePlaybookResult``
    // then attaches the widget envelope.
    let state_sent = state
        .connection_hub
        .send_to_client(&pending_request.client_id, state_message)
        .await
        .unwrap_or(false);
    if state_sent {
        tracing::info!(
            "Synthetic playbook/state delivered: request_id={}, execution_id={}, event_type={}",
            &callback.request_id[..8.min(callback.request_id.len())],
            &resolved_execution_id[..8.min(resolved_execution_id.len())],
            state_event_type,
        );
    } else {
        // Client not registered or its mpsc sender is already closed.
        // The SPA's waitForExecutionCompletion(executionId) will never
        // resolve for this execution — the browser will hang at
        // "Muno is planning…" until the 15 s SSE-drop grace fires.
        // This is the fingerprint to grep for in post-incident triage.
        tracing::info!(
            "Synthetic playbook/state NOT delivered (client absent): \
             request_id={}, execution_id={}, client_id={}, event_type={}",
            &callback.request_id[..8.min(callback.request_id.len())],
            &resolved_execution_id[..8.min(resolved_execution_id.len())],
            &pending_request.client_id[..8.min(pending_request.client_id.len())],
            state_event_type,
        );
    }

    // Send to client
    let sent = state
        .connection_hub
        .send_to_client(&pending_request.client_id, message)
        .await
        .unwrap_or(false);

    if sent {
        tracing::info!(
            "Callback delivered to client: request_id={}, client_id={}",
            &callback.request_id[..8.min(callback.request_id.len())],
            &pending_request.client_id[..8.min(pending_request.client_id.len())]
        );
    } else {
        tracing::warn!(
            "Client not connected for callback: request_id={}, client_id={}",
            &callback.request_id[..8.min(callback.request_id.len())],
            &pending_request.client_id[..8.min(pending_request.client_id.len())]
        );
        // Don't remove the request - client might reconnect
        return (
            axum::http::StatusCode::ACCEPTED,
            axum::Json(serde_json::json!({"status": "queued", "clientDisconnected": true})),
        );
    }

    // Remove the request from store
    let _ = state.request_store.remove(&callback.request_id).await;

    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({"status": "delivered"})),
    )
}

/// Progress notification handler (optional)
///
/// POST /api/internal/progress
///
/// Receives progress updates from workers
pub async fn progress_handler(
    State(state): State<Arc<SseState>>,
    axum::Json(progress): axum::Json<ProgressUpdate>,
) -> impl IntoResponse {
    // Look up the pending request
    let pending_request = match state.request_store.get(&progress.request_id).await {
        Some(req) => req,
        None => {
            return (
                axum::http::StatusCode::NOT_FOUND,
                axum::Json(serde_json::json!({"error": "Request not found"})),
            );
        }
    };

    // Build progress notification
    let message = JsonRpcMessage::notification(
        "playbook/progress",
        serde_json::json!({
            "requestId": progress.request_id,
            "executionId": progress.execution_id.unwrap_or(pending_request.execution_id),
            "step": progress.step,
            "message": progress.message,
            "progress": progress.progress
        }),
    );

    // Send to client
    let _ = state
        .connection_hub
        .send_to_client(&pending_request.client_id, message)
        .await;

    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({"status": "sent"})),
    )
}

#[derive(Debug, Deserialize)]
pub struct ProgressUpdate {
    pub request_id: String,
    #[serde(default)]
    pub execution_id: Option<String>,
    #[serde(default)]
    pub step: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub progress: Option<f32>,
}
