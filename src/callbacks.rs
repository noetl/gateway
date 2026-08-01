//! In-process callback registry for async playbook execution results.
//!
//! When gateway starts a playbook, it generates a unique request_id and
//! Gateway receives via subscription and delivers to waiting HTTP request.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, RwLock};
use uuid::Uuid;

/// Result delivered via callback
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackResult {
    pub request_id: String,
    #[serde(default)]
    pub execution_id: Option<String>,
    #[serde(default)]
    pub step: Option<String>,
    #[serde(default = "default_status")]
    pub status: String,
    #[serde(default)]
    pub data: serde_json::Value,
}

fn default_status() -> String {
    "success".to_string()
}

/// Callback manager using NATS pub/sub
///
/// Local channels are still needed for HTTP request-response,
/// but message routing happens via NATS subscriptions.
#[derive(Clone)]
pub struct CallbackManager {
    /// Map of request_id -> oneshot sender (for delivering to waiting HTTP requests)
    pending: Arc<RwLock<HashMap<String, oneshot::Sender<CallbackResult>>>>,
    /// NATS subject prefix for callbacks
    subject_prefix: String,
}

impl CallbackManager {
    pub fn new(subject_prefix: Option<String>) -> Self {
        Self {
            pending: Arc::new(RwLock::new(HashMap::new())),
            subject_prefix: subject_prefix.unwrap_or_else(|| "noetl.callbacks".to_string()),
        }
    }

    /// Generate a new request_id and register a callback
    /// Returns (request_id, nats_subject, receiver)
    pub async fn register(&self) -> (String, String, oneshot::Receiver<CallbackResult>) {
        let request_id = Uuid::new_v4().to_string();
        let subject = format!("{}.{}", self.subject_prefix, request_id);
        let (tx, rx) = oneshot::channel();

        self.pending.write().await.insert(request_id.clone(), tx);
        tracing::debug!("Registered callback: request_id={}, subject={}", request_id, subject);

        (request_id, subject, rx)
    }

    /// Deliver a result to a waiting callback (called when NATS message arrives)
    pub async fn deliver(&self, result: CallbackResult) -> bool {
        let request_id = result.request_id.clone();

        if let Some(tx) = self.pending.write().await.remove(&request_id) {
            match tx.send(result) {
                Ok(()) => {
                    tracing::debug!("Delivered callback for request_id={}", request_id);
                    true
                }
                Err(_) => {
                    tracing::warn!("Callback receiver dropped for request_id={}", request_id);
                    false
                }
            }
        } else {
            tracing::warn!("No pending callback for request_id={}", request_id);
            false
        }
    }

    /// Cancel a pending callback (cleanup on timeout)
    pub async fn cancel(&self, request_id: &str) {
        self.pending.write().await.remove(request_id);
        tracing::debug!("Cancelled callback for request_id={}", request_id);
    }

    /// Get the NATS subject pattern for subscribing to all callbacks
    pub fn subscription_subject(&self) -> String {
        format!("{}.>", self.subject_prefix)
    }
}
