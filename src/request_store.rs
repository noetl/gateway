//! Request store for tracking pending playbook execution requests.
//!
//! Uses NATS JetStream K/V to store request_id -> client mapping.
//! This enables routing callbacks to the correct client when playbooks complete.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Pending request data stored in NATS K/V
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRequest {
    /// Client ID to route callback to
    pub client_id: String,
    /// Session token for verification
    pub session_token: String,
    /// NoETL execution ID
    pub execution_id: String,
    /// Playbook path being executed
    pub playbook_path: String,
    /// Unix timestamp when request was created
    pub created_at: i64,
}

/// Request store — the pending-request routing state that backs **every** SSE
/// route (noetl/ai-meta#214).
///
/// Two backends. `ehdb` is the live one: the NATS KV bucket it replaces is gone
/// with the rest of NATS. The NATS half is retained only until the teardown
/// commit lands, and every method prefers `ehdb` when configured.
#[derive(Clone)]
pub struct RequestStore {
    ehdb: crate::ehdb_kv::EhdbKvClient,
    bucket_name: String,
    ttl_secs: u64,
}

impl RequestStore {
    /// An EHDB-KV-backed store. `addr` is the writer's KV face
    /// (`host:9107`); `bucket_name` is the logical bucket within it.
    ///
    /// There is no other backend since the NATS removal (noetl/ai-meta#212), so
    /// this is the only constructor — a store cannot be built unbacked.
    pub fn new(bucket_name: String, ttl_secs: u64, addr: &str) -> Self {
        Self {
            ehdb: crate::ehdb_kv::EhdbKvClient::new(addr),
            bucket_name,
            ttl_secs,
        }
    }

    /// Probe the EHDB KV face so a misconfigured address surfaces at startup
    /// rather than on the first user request. This store backs **every** SSE
    /// route (noetl/ai-meta#214), so a silent failure here drops every route.
    pub async fn probe(&self) -> anyhow::Result<()> {
        self.ehdb.probe().await
    }

    /// Store a pending request
    pub async fn put(&self, request_id: &str, request: &PendingRequest) -> anyhow::Result<()> {
        let kv = &self.ehdb;
        let body = serde_json::to_string(request)?;
        // Propagate the error: a lost request means a lost SSE route, and
        // swallowing it is how the SPA hangs with nothing in the logs.
        kv.put(&self.bucket_name, request_id, &body, self.ttl_secs).await?;
        Ok(())
    }

    /// Get a pending request
    pub async fn get(&self, request_id: &str) -> Option<PendingRequest> {
        let kv = &self.ehdb;
        match kv.get(&self.bucket_name, request_id).await {
            Ok(Some(body)) => serde_json::from_str(&body).ok(),
            Ok(None) => None,
            Err(e) => {
                // A store failure is NOT "no such request" — log it loudly
                // so a routing outage is not mistaken for an idle client.
                tracing::warn!(error = %e, "EHDB KV get failed for request store");
                None
            }
        }
    }

    /// Remove a completed/failed request
    pub async fn remove(&self, request_id: &str) -> anyhow::Result<()> {
        let kv = &self.ehdb;
        let _ = kv.delete(&self.bucket_name, request_id).await;
        Ok(())
    }

    /// Get all pending requests for a client (for reconnection recovery)
    /// Note: This is inefficient for large datasets - consider indexing if needed
    pub async fn get_by_client(&self, client_id: &str) -> Vec<(String, PendingRequest)> {
        let kv = &self.ehdb;
        // One scan of the bucket, filtered locally. The NATS path did the
        // same shape (iterate keys, fetch each) but paid a round-trip per
        // key; the scan returns the whole live bucket in one call.
        match kv.scan(&self.bucket_name).await {
            Ok(entries) => entries
                .into_iter()
                .filter_map(|(k, v)| serde_json::from_str::<PendingRequest>(&v).ok().map(|r| (k, r)))
                .filter(|(_, r)| r.client_id == client_id)
                .collect(),
            Err(e) => {
                tracing::warn!(error = %e, "EHDB KV scan failed for request store");
                Vec::new()
            }
        }
    }

    /// Get all pending requests for a NoETL execution.
    /// Note: NATS K/V does not support secondary indexes, so this scans keys.
    pub async fn get_by_execution(&self, execution_id: &str) -> Vec<(String, PendingRequest)> {
        let kv = &self.ehdb;
        // One scan of the bucket, filtered locally. The NATS path did the
        // same shape (iterate keys, fetch each) but paid a round-trip per
        // key; the scan returns the whole live bucket in one call.
        match kv.scan(&self.bucket_name).await {
            Ok(entries) => entries
                .into_iter()
                .filter_map(|(k, v)| serde_json::from_str::<PendingRequest>(&v).ok().map(|r| (k, r)))
                .filter(|(_, r)| r.execution_id == execution_id)
                .collect(),
            Err(e) => {
                tracing::warn!(error = %e, "EHDB KV scan failed for request store");
                Vec::new()
            }
        }
    }
}
