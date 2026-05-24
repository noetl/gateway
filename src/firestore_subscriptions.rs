//! Authenticated Firestore collection subscriptions delivered over the SSE hub.
//!
//! Firestore watch support is delegated to a small sidecar command so the Rust
//! gateway can keep ownership of authentication, routing, and SSE delivery
//! without storing service-account material in this repository.

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::auth::types::UserContext;
use crate::config::FirestoreConfig;
use crate::connection_hub::{ConnectionHub, JsonRpcMessage};

#[derive(Clone)]
pub struct FirestoreSubscriptionManager {
    connection_hub: Arc<ConnectionHub>,
    subscriptions: Arc<RwLock<HashMap<String, FirestoreSubscription>>>,
    listener: FirestoreListenerBackend,
}

#[derive(Clone)]
enum FirestoreListenerBackend {
    Sidecar(SidecarConfig),
    Disabled,
}

#[derive(Clone)]
struct SidecarConfig {
    command: String,
    credentials_path: String,
    project_id: Option<String>,
}

#[derive(Debug, Clone)]
struct FirestoreSubscription {
    client_id: String,
    session_token: String,
    user_id: i32,
    path: String,
}

#[derive(Debug, Deserialize)]
pub struct FirestoreSubscriptionRequest {
    pub path: String,
    #[serde(default = "default_scope")]
    pub scope: String,
    #[serde(default)]
    pub client_id: Option<String>,
}

fn default_scope() -> String {
    "owner".to_string()
}

#[derive(Debug, Serialize)]
pub struct FirestoreSubscriptionResponse {
    pub subscription_id: String,
    pub client_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FirestoreDocumentChange {
    pub doc_id: String,
    pub data: serde_json::Value,
    pub op: FirestoreChangeOp,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FirestoreChangeOp {
    Added,
    Modified,
    Removed,
}

impl FirestoreSubscriptionManager {
    pub fn new(connection_hub: Arc<ConnectionHub>, config: FirestoreConfig) -> Self {
        let listener = match config.credentials_path {
            Some(credentials_path) => FirestoreListenerBackend::Sidecar(SidecarConfig {
                command: config.listener_command,
                credentials_path,
                project_id: config.project_id,
            }),
            None => FirestoreListenerBackend::Disabled,
        };

        Self {
            connection_hub,
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            listener,
        }
    }

    #[cfg(test)]
    fn new_disabled(connection_hub: Arc<ConnectionHub>) -> Self {
        Self {
            connection_hub,
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            listener: FirestoreListenerBackend::Disabled,
        }
    }

    pub async fn subscribe(
        &self,
        user: &UserContext,
        request: FirestoreSubscriptionRequest,
    ) -> Result<FirestoreSubscriptionResponse, SubscriptionError> {
        validate_subscription_path(&request.path, &request.scope)?;

        let client_id = match request.client_id {
            Some(client_id) if self.connection_hub.is_connected(&client_id).await => client_id,
            Some(_) => return Err(SubscriptionError::ClientNotConnected),
            None => self
                .connection_hub
                .get_session_clients(&user.session_token)
                .await
                .into_iter()
                .next()
                .ok_or(SubscriptionError::ClientNotConnected)?,
        };

        let subscription_id = Uuid::new_v4().to_string();
        let subscription = FirestoreSubscription {
            client_id: client_id.clone(),
            session_token: user.session_token.clone(),
            user_id: user.user_id,
            path: request.path,
        };

        self.subscriptions
            .write()
            .await
            .insert(subscription_id.clone(), subscription.clone());

        match self.listener.clone() {
            FirestoreListenerBackend::Sidecar(sidecar) => {
                self.spawn_sidecar_listener(subscription_id.clone(), subscription, sidecar);
            }
            FirestoreListenerBackend::Disabled => {
                self.subscriptions.write().await.remove(&subscription_id);
                return Err(SubscriptionError::ListenerUnavailable);
            }
        }

        Ok(FirestoreSubscriptionResponse {
            subscription_id,
            client_id,
        })
    }

    pub async fn unsubscribe(&self, user: &UserContext, subscription_id: &str) -> Result<(), SubscriptionError> {
        let removed = self.subscriptions.write().await.remove(subscription_id);
        match removed {
            Some(subscription) if subscription.session_token == user.session_token => Ok(()),
            Some(subscription) => {
                self.subscriptions
                    .write()
                    .await
                    .insert(subscription_id.to_string(), subscription);
                Err(SubscriptionError::Forbidden)
            }
            None => Err(SubscriptionError::NotFound),
        }
    }

    async fn emit_change(&self, subscription_id: &str, change: FirestoreDocumentChange) -> anyhow::Result<bool> {
        let subscription = {
            let subscriptions = self.subscriptions.read().await;
            subscriptions.get(subscription_id).cloned()
        };
        let Some(subscription) = subscription else {
            return Ok(false);
        };

        let message = JsonRpcMessage::notification(
            "subscription/event",
            serde_json::json!({
                "subscription_id": subscription_id,
                "doc_id": change.doc_id,
                "data": change.data,
                "op": change.op,
            }),
        );
        self.connection_hub
            .send_to_client(&subscription.client_id, message)
            .await
    }

    fn spawn_sidecar_listener(
        &self,
        subscription_id: String,
        subscription: FirestoreSubscription,
        sidecar: SidecarConfig,
    ) {
        let manager = self.clone();
        tokio::spawn(async move {
            if let Err(error) = manager
                .run_sidecar_listener(subscription_id.clone(), subscription, sidecar)
                .await
            {
                tracing::warn!(%subscription_id, error = %error, "Firestore subscription listener stopped");
            }
            manager.subscriptions.write().await.remove(&subscription_id);
        });
    }

    async fn run_sidecar_listener(
        &self,
        subscription_id: String,
        subscription: FirestoreSubscription,
        sidecar: SidecarConfig,
    ) -> anyhow::Result<()> {
        let mut parts = sidecar.command.split_whitespace();
        let executable = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("empty GATEWAY_FIRESTORE_LISTENER_CMD"))?;
        let mut command = tokio::process::Command::new(executable);
        command.args(parts);
        command
            .arg("--credentials-path")
            .arg(sidecar.credentials_path)
            .arg("--path")
            .arg(subscription.path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(project_id) = sidecar.project_id {
            command.arg("--project-id").arg(project_id);
        }

        let mut child = command.spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("Firestore listener sidecar stdout unavailable"))?;
        let mut lines = BufReader::new(stdout).lines();

        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            let change: FirestoreDocumentChange = serde_json::from_str(&line)?;
            let delivered = self.emit_change(&subscription_id, change).await?;
            if !delivered {
                break;
            }
        }

        let _ = child.kill().await;
        Ok(())
    }

    #[cfg(test)]
    async fn add_test_subscription(&self, subscription_id: &str, client_id: &str, session_token: &str) {
        self.subscriptions.write().await.insert(
            subscription_id.to_string(),
            FirestoreSubscription {
                client_id: client_id.to_string(),
                session_token: session_token.to_string(),
                user_id: 7,
                path: "chat_threads/thread-1/trip/current/events".to_string(),
            },
        );
    }
}

#[derive(Debug)]
pub enum SubscriptionError {
    BadPath(String),
    ClientNotConnected,
    Forbidden,
    ListenerUnavailable,
    NotFound,
}

impl IntoResponse for SubscriptionError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            SubscriptionError::BadPath(message) => (StatusCode::BAD_REQUEST, message),
            SubscriptionError::ClientNotConnected => (
                StatusCode::CONFLICT,
                "No active SSE client is connected for this session".to_string(),
            ),
            SubscriptionError::Forbidden => (
                StatusCode::FORBIDDEN,
                "Subscription belongs to another session".to_string(),
            ),
            SubscriptionError::ListenerUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Firestore listener is not configured; set GATEWAY_FIRESTORE_CREDENTIALS_PATH".to_string(),
            ),
            SubscriptionError::NotFound => (StatusCode::NOT_FOUND, "Subscription not found".to_string()),
        };
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

pub async fn create_firestore_subscription(
    State(state): State<Arc<crate::sse::SseState>>,
    Extension(user): Extension<UserContext>,
    Json(request): Json<FirestoreSubscriptionRequest>,
) -> Result<Json<FirestoreSubscriptionResponse>, SubscriptionError> {
    let manager = state
        .firestore_subscriptions
        .as_ref()
        .ok_or(SubscriptionError::ListenerUnavailable)?;
    manager.subscribe(&user, request).await.map(Json)
}

pub async fn delete_subscription(
    State(state): State<Arc<crate::sse::SseState>>,
    Extension(user): Extension<UserContext>,
    Path(subscription_id): Path<String>,
) -> Result<StatusCode, SubscriptionError> {
    let manager = state
        .firestore_subscriptions
        .as_ref()
        .ok_or(SubscriptionError::ListenerUnavailable)?;
    manager.unsubscribe(&user, &subscription_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn validate_subscription_path(path: &str, scope: &str) -> Result<(), SubscriptionError> {
    let clean = path.trim().trim_matches('/');
    if scope != "owner" {
        return Err(SubscriptionError::BadPath("Only scope=owner is supported".to_string()));
    }
    if clean != path.trim() {
        return Err(SubscriptionError::BadPath(
            "Subscription path must not have leading or trailing slashes".to_string(),
        ));
    }
    let parts: Vec<&str> = clean.split('/').collect();
    if parts.len() != 5
        || parts[0] != "chat_threads"
        || parts[2] != "trip"
        || parts[3] != "current"
        || parts[4] != "events"
    {
        return Err(SubscriptionError::BadPath(
            "Subscription path must match chat_threads/<thread_id>/trip/current/events".to_string(),
        ));
    }
    let thread_id = parts[1];
    if thread_id.is_empty()
        || thread_id == "."
        || thread_id == ".."
        || !thread_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        return Err(SubscriptionError::BadPath(
            "Thread id must contain only ASCII letters, numbers, '.', '_', or '-'".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[test]
    fn rejects_out_of_scope_paths() {
        assert!(validate_subscription_path("users/u1/trips/t1/events", "owner").is_err());
        assert!(validate_subscription_path("chat_threads/../trip/current/events", "owner").is_err());
        assert!(validate_subscription_path("chat_threads/thread-1/trip/current/events", "tenant").is_err());
        assert!(validate_subscription_path("chat_threads/thread-1/trip/current/events", "owner").is_ok());
    }

    #[tokio::test]
    async fn emits_subscription_event_to_client() {
        let hub = Arc::new(ConnectionHub::new());
        let manager = FirestoreSubscriptionManager::new_disabled(hub.clone());
        let (tx, mut rx) = mpsc::unbounded_channel();
        hub.register_sse("client-1".to_string(), "session-1".to_string(), tx)
            .await;
        manager.add_test_subscription("sub-1", "client-1", "session-1").await;

        let delivered = manager
            .emit_change(
                "sub-1",
                FirestoreDocumentChange {
                    doc_id: "evt-1".to_string(),
                    data: serde_json::json!({ "title": "Depart SFO" }),
                    op: FirestoreChangeOp::Added,
                },
            )
            .await
            .expect("event delivery");

        assert!(delivered);
        let message = rx.recv().await.expect("sse message");
        assert_eq!(message.method.as_deref(), Some("subscription/event"));
        let params = message.params.expect("params");
        assert_eq!(params["subscription_id"], "sub-1");
        assert_eq!(params["doc_id"], "evt-1");
        assert_eq!(params["op"], "added");
    }
}
