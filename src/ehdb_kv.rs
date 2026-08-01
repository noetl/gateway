//! **The EHDB KV client — the gateway's replacement for NATS KV.**
//!
//! The gateway kept two NATS KV buckets: `sessions` (validated-session cache)
//! and `requests` (pending-request routing state, which backs **every** SSE
//! route — see noetl/ai-meta#214). Both move onto the EHDB KV face served by
//! the writer (`ehdb-feed::serve_kv`, port 9107).
//!
//! **Why a hand-rolled client rather than depending on `ehdb-feed`.** Same call
//! as [`crate::event_feed`]: the gateway is a thin HTTP edge, and taking that
//! crate would drag the whole L0 engine — durable log, substrate, Arrow — into a
//! process that only ever talks to a socket. The wire protocol is small and
//! fixed: a `u32` big-endian length prefix followed by a JSON frame.
//!
//! ```text
//! -> {"Get":{"bucket":"sessions","key":"<token>"}}
//! <- {"ok":true,"value":"<json>"}
//! ```
//!
//! **`ok=false` is not the same as a missing key.** A missing key is
//! `{"ok":true}` with no `value`; a failed call carries `err`. The gateway must
//! keep these apart — treating a store failure as "no such session" would log
//! users out on a blip, and treating it as "no such request" would silently drop
//! SSE routes, which is the failure mode #214 exists to prevent.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize)]
enum KvReq {
    Get {
        bucket: String,
        key: String,
    },
    Put {
        bucket: String,
        key: String,
        value: String,
        ttl_ms: u64,
    },
    Delete {
        bucket: String,
        key: String,
    },
    Scan {
        bucket: String,
    },
}

#[derive(Debug, Clone, Deserialize, Default)]
struct KvResp {
    ok: bool,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    entries: Vec<(String, String)>,
    #[serde(default)]
    err: Option<String>,
}

/// A lazily-connected, self-redialing client of the writer's KV face.
#[derive(Clone)]
pub struct EhdbKvClient {
    addr: Arc<String>,
    sock: Arc<Mutex<Option<TcpStream>>>,
}

impl EhdbKvClient {
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: Arc::new(addr.into()),
            sock: Arc::new(Mutex::new(None)),
        }
    }

    /// Probe the KV face once. Used at startup so a misconfigured address is
    /// visible immediately rather than on the first user request.
    pub async fn probe(&self) -> anyhow::Result<()> {
        self.get("sessions", "__probe__").await.map(|_| ())
    }

    async fn call(&self, req: &KvReq) -> anyhow::Result<KvResp> {
        let body = serde_json::to_vec(req)?;
        let mut guard = self.sock.lock().await;
        if guard.is_none() {
            let sock = TcpStream::connect(self.addr.as_str()).await?;
            sock.set_nodelay(true)?;
            *guard = Some(sock);
        }
        let sock = guard.as_mut().expect("just connected");
        let result: anyhow::Result<KvResp> = async {
            let len = u32::try_from(body.len())?;
            sock.write_all(&len.to_be_bytes()).await?;
            sock.write_all(&body).await?;
            sock.flush().await?;

            let mut len_buf = [0u8; 4];
            sock.read_exact(&mut len_buf).await?;
            let n = u32::from_be_bytes(len_buf) as usize;
            let mut buf = vec![0u8; n];
            sock.read_exact(&mut buf).await?;
            Ok(serde_json::from_slice::<KvResp>(&buf)?)
        }
        .await;
        if result.is_err() {
            // Drop the socket so the next call redials — the gateway holds this
            // for the process lifetime and must survive a writer restart.
            *guard = None;
        }
        result
    }

    pub async fn get(&self, bucket: &str, key: &str) -> anyhow::Result<Option<String>> {
        let r = self
            .call(&KvReq::Get {
                bucket: bucket.into(),
                key: key.into(),
            })
            .await?;
        if !r.ok {
            anyhow::bail!("ehdb kv get failed: {}", r.err.unwrap_or_default());
        }
        Ok(r.value)
    }

    pub async fn put(&self, bucket: &str, key: &str, value: &str, ttl_secs: u64) -> anyhow::Result<()> {
        let r = self
            .call(&KvReq::Put {
                bucket: bucket.into(),
                key: key.into(),
                value: value.into(),
                ttl_ms: ttl_secs.saturating_mul(1000),
            })
            .await?;
        if !r.ok {
            anyhow::bail!("ehdb kv put failed: {}", r.err.unwrap_or_default());
        }
        Ok(())
    }

    pub async fn delete(&self, bucket: &str, key: &str) -> anyhow::Result<()> {
        let r = self
            .call(&KvReq::Delete {
                bucket: bucket.into(),
                key: key.into(),
            })
            .await?;
        if !r.ok {
            anyhow::bail!("ehdb kv delete failed: {}", r.err.unwrap_or_default());
        }
        Ok(())
    }

    pub async fn scan(&self, bucket: &str) -> anyhow::Result<Vec<(String, String)>> {
        let r = self.call(&KvReq::Scan { bucket: bucket.into() }).await?;
        if !r.ok {
            anyhow::bail!("ehdb kv scan failed: {}", r.err.unwrap_or_default());
        }
        Ok(r.entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The request frames must match `ehdb-feed`'s externally-tagged enum
    /// exactly — this is a cross-repo wire contract, and a silent shape drift
    /// would show up as "the store is always empty" rather than as an error.
    #[test]
    fn request_frames_match_the_ehdb_feed_wire_shape() {
        let get = serde_json::to_value(KvReq::Get {
            bucket: "sessions".into(),
            key: "tok".into(),
        })
        .unwrap();
        assert_eq!(get, serde_json::json!({"Get":{"bucket":"sessions","key":"tok"}}));

        let put = serde_json::to_value(KvReq::Put {
            bucket: "requests".into(),
            key: "r1".into(),
            value: "{}".into(),
            ttl_ms: 300_000,
        })
        .unwrap();
        assert_eq!(
            put,
            serde_json::json!({"Put":{"bucket":"requests","key":"r1","value":"{}","ttl_ms":300000}})
        );

        let scan = serde_json::to_value(KvReq::Scan {
            bucket: "requests".into(),
        })
        .unwrap();
        assert_eq!(scan, serde_json::json!({"Scan":{"bucket":"requests"}}));
    }

    /// A missing key and a failed call must stay distinguishable. Conflating
    /// them logs users out on a blip and silently drops SSE routes.
    #[test]
    fn missing_key_and_failure_are_distinguishable() {
        let missing: KvResp = serde_json::from_str(r#"{"ok":true}"#).unwrap();
        assert!(missing.ok && missing.value.is_none());

        let failed: KvResp = serde_json::from_str(r#"{"ok":false,"err":"boom"}"#).unwrap();
        assert!(!failed.ok);
        assert_eq!(failed.err.as_deref(), Some("boom"));

        let found: KvResp = serde_json::from_str(r#"{"ok":true,"value":"v"}"#).unwrap();
        assert_eq!(found.value.as_deref(), Some("v"));
    }

    #[test]
    fn scan_response_decodes_entries() {
        let r: KvResp = serde_json::from_str(r#"{"ok":true,"entries":[["a","1"],["b","2"]]}"#).unwrap();
        assert_eq!(r.entries.len(), 2);
        assert_eq!(r.entries[0], ("a".to_string(), "1".to_string()));
    }

    /// TTL crosses the wire in milliseconds; the gateway's config is seconds.
    #[test]
    fn ttl_is_converted_to_milliseconds() {
        let put = serde_json::to_value(KvReq::Put {
            bucket: "b".into(),
            key: "k".into(),
            value: "v".into(),
            ttl_ms: 300u64.saturating_mul(1000),
        })
        .unwrap();
        assert_eq!(put["Put"]["ttl_ms"], 300_000);
    }
}
