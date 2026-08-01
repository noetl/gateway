//! Session cache using NATS JetStream K/V store.
//!
//! Provides fast session validation by checking the K/V cache before
//! triggering playbook execution. Sessions are cached with a configurable TTL.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Cached session data matching the structure from auth0_login playbook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedSession {
    pub session_token: String,
    pub user_id: i32,
    pub email: String,
    pub display_name: String,
    pub expires_at: String,
    pub is_active: bool,
    #[serde(default)]
    pub roles: Vec<String>,
}

/// Session cache backed by NATS JetStream K/V
#[derive(Clone)]
pub struct SessionCache {
    ehdb: crate::ehdb_kv::EhdbKvClient,
    bucket_name: String,
    ttl_secs: u64,
}

impl SessionCache {
    /// An EHDB-KV-backed cache (writer KV face at `addr`). The only backend
    /// since the NATS removal (noetl/ai-meta#212).
    pub fn new(bucket_name: String, ttl_secs: u64, addr: &str) -> Self {
        Self {
            ehdb: crate::ehdb_kv::EhdbKvClient::new(addr),
            bucket_name,
            ttl_secs,
        }
    }

    /// Get a cached session by token
    pub async fn get(&self, session_token: &str) -> Option<CachedSession> {
        let kv = &self.ehdb;
        match kv.get(&self.bucket_name, session_token).await {
            Ok(Some(body)) => serde_json::from_str(&body).ok(),
            Ok(None) => None,
            Err(e) => {
                // A cache miss and a store failure both fall through to the
                // authoritative Postgres lookup, so this is safe — but it
                // must be visible, or a dead cache looks like cold traffic.
                tracing::warn!(error = %e, "EHDB KV get failed for session cache");
                None
            }
        }
    }

    /// Cache a session
    pub async fn put(&self, session: &CachedSession) -> anyhow::Result<()> {
        let kv = &self.ehdb;
        let body = serde_json::to_string(session)?;
        // A failed cache write is not fatal — the next read falls through to
        // Postgres — so log and continue rather than failing the request.
        if let Err(e) = kv
            .put(&self.bucket_name, &session.session_token, &body, self.ttl_secs)
            .await
        {
            tracing::warn!(error = %e, "EHDB KV put failed for session cache");
        }
        Ok(())
    }

    /// Invalidate a cached session
    pub async fn invalidate(&self, session_token: &str) -> anyhow::Result<()> {
        let kv = &self.ehdb;
        // Invalidation MUST propagate: a stale cached session outliving its
        // logout is a security problem, not a performance one.
        kv.delete(&self.bucket_name, session_token).await?;
        Ok(())
    }
}
