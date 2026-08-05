//! **L1 T3 — the EHDB events feed as the gateway's lifecycle source.**
//!
//! The gateway forwards execution-lifecycle events to SPA clients over SSE.
//!
//! **This is the only source.** It was written as the EHDB-sourced twin of a
//! core-NATS subscribe on `noetl.events.>`, selectable via `NOETL_EVENT_SOURCE`
//! so cutover and rollback were a flag flip. T5 deleted NATS
//! (noetl/ai-meta#194), and `main.rs` now starts this listener
//! **unconditionally** once `NOETL_EVENT_FEED_ADDR` is non-empty — there is no
//! mode branch and no other path.
//!
//! Consequences worth knowing before editing:
//!
//! - `NOETL_EVENT_SOURCE` is **read by nothing**. It is still set to `ehdb` on
//!   the prod Deployment, where it has no effect.
//! - [`EventSourceMode`] below is unused outside this module —
//!   [`EventSourceMode::from_env_value`] is called only from this file's own
//!   tests. Its `Nats` variant describes a path that no longer exists.
//!
//! Whether to delete the enum or re-wire it is a disposition decision tracked
//! on noetl/ai-meta#242; it is left in place rather than removed silently.
//!
//! **Why a hand-rolled SSE reader instead of depending on `ehdb-feed`.** The
//! gateway is a thin HTTP edge; pulling in the feed crate would drag the whole
//! L0 engine — the durable log, its substrate, Arrow — into a process that only
//! ever *reads a socket*. The wire format is deliberately minimal and is
//! documented as a stable contract in `ehdb-feed/src/sse.rs`:
//!
//! ```text
//! GET /feed?shard=0&cursor=0        (or Last-Event-ID: <sort_key> on reconnect)
//! -> Content-Type: text/event-stream
//!    id: 1
//!    data: {"global_sequence":1,...}
//! ```
//!
//! So this reads it directly. [`parse_sse_frame`] pins the parse, and the
//! resume contract below pins the reconnect behaviour.
//!
//! **Resume is the real upgrade over NATS here.** A core NATS subscriber sees
//! only what is published while it is connected — a gateway restart silently
//! loses every event in the gap, which is why an SPA can hang on
//! `Muno is planning…` after a redeploy. The feed cursor makes reconnect exact:
//! the reader remembers the last `id:` it saw and resumes from it, so the gap is
//! replayed rather than lost.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::connection_hub::ConnectionHub;
use crate::request_store::RequestStore;

/// Which transport feeds the gateway's lifecycle SSE forwarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EventSourceMode {
    /// Core NATS subscribe on `noetl.events.>` — today's path (default).
    #[default]
    Nats,
    /// The EHDB events feed's SSE broadcast face.
    Ehdb,
}

impl EventSourceMode {
    /// Parse an event-source value; anything unrecognised is `nats`.
    ///
    /// ⚠ The safety property this comment used to claim — *"a typo can never
    /// silently take the SPA's live updates off their working path"* — no
    /// longer holds, because `nats` is not a working path. NATS was deleted at
    /// T5. Nothing calls this outside the tests below; see the module header.
    pub fn from_env_value(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "ehdb" => Self::Ehdb,
            _ => Self::Nats,
        }
    }

    pub fn is_ehdb(self) -> bool {
        matches!(self, Self::Ehdb)
    }
}

/// One parsed SSE frame: the feed cursor and the event payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedFrame {
    pub id: Option<u64>,
    pub data: String,
}

/// Parse one SSE frame (the lines between blank-line separators).
///
/// Multi-line `data:` fields are joined with `\n` per the SSE spec. A frame with
/// no `data:` is not an event (it may be a comment/keepalive) and yields `None`.
pub fn parse_sse_frame(frame: &str) -> Option<FeedFrame> {
    let mut id = None;
    let mut data_lines: Vec<&str> = Vec::new();
    for line in frame.lines() {
        // A leading colon is an SSE comment — the keepalive shape.
        if line.starts_with(':') {
            continue;
        }
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "id" => id = value.trim().parse::<u64>().ok(),
            "data" => data_lines.push(value),
            _ => {}
        }
    }
    if data_lines.is_empty() {
        return None;
    }
    Some(FeedFrame {
        id,
        data: data_lines.join("\n"),
    })
}

/// The record the feed carries. Only `payload` matters to the gateway — it is
/// the same `to_stream_json()` body the server publishes to NATS, so the
/// downstream [`crate::playbook_state::build_state_message`] path is identical
/// on both transports.
fn payload_from_record(data: &str) -> Option<Value> {
    let record: Value = serde_json::from_str(data).ok()?;
    // `payload` is a JSON *string* holding the event object.
    match record.get("payload") {
        Some(Value::String(s)) => serde_json::from_str(s).ok(),
        Some(v @ Value::Object(_)) => Some(v.clone()),
        _ => None,
    }
}

/// Start the EHDB-sourced lifecycle listener. Reconnects forever with backoff,
/// resuming from the last cursor it saw.
pub async fn start_ehdb_feed_listener(
    feed_addr: &str,
    request_store: Arc<RequestStore>,
    connection_hub: Arc<ConnectionHub>,
) -> anyhow::Result<()> {
    let addr = feed_addr.to_string();
    tracing::info!(%addr, "Subscribing to execution lifecycle events on the EHDB feed");
    tokio::spawn(async move {
        // The resume cursor survives reconnects — that is the whole point.
        let mut cursor: u64 = 0;
        let mut backoff = Duration::from_millis(250);
        loop {
            match run_feed_connection(&addr, &mut cursor, &request_store, &connection_hub).await {
                Ok(()) => {
                    crate::ingress::record_event_feed_reconnect("ended");
                    tracing::warn!(%addr, cursor, "EHDB lifecycle feed ended; reconnecting");
                    backoff = Duration::from_millis(250);
                }
                Err(error) => {
                    crate::ingress::record_event_feed_reconnect("error");
                    tracing::warn!(%addr, cursor, %error, "EHDB lifecycle feed error; reconnecting");
                }
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(5));
        }
    });
    Ok(())
}

/// One connection's lifetime: request the feed from `cursor`, then forward
/// frames until the socket ends. Advances `cursor` as frames arrive so a
/// reconnect resumes exactly.
async fn run_feed_connection(
    addr: &str,
    cursor: &mut u64,
    request_store: &Arc<RequestStore>,
    connection_hub: &Arc<ConnectionHub>,
) -> anyhow::Result<()> {
    let mut sock = TcpStream::connect(addr).await?;
    sock.set_nodelay(true)?;
    // `Last-Event-ID` is the reconnect form; the writer gives it precedence over
    // the query cursor, and sending both is what the wire contract expects.
    let req = format!(
        "GET /feed?shard=0&cursor={c} HTTP/1.1\r\nHost: {addr}\r\nAccept: text/event-stream\r\n\
         Last-Event-ID: {c}\r\nConnection: keep-alive\r\n\r\n",
        c = *cursor
    );
    sock.write_all(req.as_bytes()).await?;
    sock.flush().await?;

    let mut reader = BufReader::new(sock);
    let mut line = String::new();
    let mut frame = String::new();
    let mut in_body = false;

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Ok(()); // clean EOF — reconnect
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);

        if !in_body {
            // Skip the HTTP response head; the blank line ends it.
            if trimmed.is_empty() {
                in_body = true;
            }
            continue;
        }

        if !trimmed.is_empty() {
            frame.push_str(trimmed);
            frame.push('\n');
            continue;
        }

        // Blank line — frame complete.
        if let Some(parsed) = parse_sse_frame(&frame) {
            if let Some(id) = parsed.id {
                *cursor = id;
            }
            if let Some(payload) = payload_from_record(&parsed.data) {
                forward(&payload, request_store, connection_hub).await;
            }
        }
        frame.clear();
    }
}

/// Forward one event payload to whichever SSE clients are waiting on its
/// execution — the same routing the NATS path performs, deliberately sharing
/// `build_state_message` so both transports produce identical client messages.
async fn forward(payload: &Value, request_store: &Arc<RequestStore>, connection_hub: &Arc<ConnectionHub>) {
    // `None` for the subject-derived id: the EHDB feed carries no subject tail,
    // and the payload's `execution_id` is the reliable source anyway — the NATS
    // path already prefers it (see playbook_state::execution_id_from_subject).
    let Some(message) = crate::playbook_state::build_state_message(None, payload) else {
        return;
    };
    let Some(execution_id) = message
        .params
        .as_ref()
        .and_then(|params| params.get("execution_id"))
        .and_then(|value| value.as_str())
        .map(ToString::to_string)
    else {
        return;
    };
    for (_, pending) in request_store.get_by_execution(&execution_id).await {
        let _ = connection_hub.send_to_client(&pending.client_id, message.clone()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_defaults_to_nats_and_falls_back_safely() {
        assert_eq!(EventSourceMode::from_env_value(""), EventSourceMode::Nats);
        assert_eq!(EventSourceMode::from_env_value("nats"), EventSourceMode::Nats);
        assert_eq!(EventSourceMode::from_env_value("ehdb"), EventSourceMode::Ehdb);
        assert_eq!(EventSourceMode::from_env_value(" EHDB "), EventSourceMode::Ehdb);
        // A typo must not take the SPA's live updates off their working path.
        assert_eq!(EventSourceMode::from_env_value("ehbd"), EventSourceMode::Nats);
        assert_eq!(EventSourceMode::default(), EventSourceMode::Nats);
    }

    #[test]
    fn parses_the_documented_frame_shape() {
        let f = parse_sse_frame("id: 7\ndata: {\"global_sequence\":7}\n").unwrap();
        assert_eq!(f.id, Some(7));
        assert_eq!(f.data, "{\"global_sequence\":7}");
    }

    #[test]
    fn joins_multiline_data_and_ignores_comments() {
        let f = parse_sse_frame(": keepalive\nid: 3\ndata: line1\ndata: line2\n").unwrap();
        assert_eq!(f.id, Some(3));
        assert_eq!(f.data, "line1\nline2");
    }

    #[test]
    fn a_frame_without_data_is_not_an_event() {
        // A bare keepalive must not be mistaken for an event.
        assert!(parse_sse_frame(": keepalive\n").is_none());
        assert!(parse_sse_frame("id: 9\n").is_none());
    }

    /// The record wraps the event as a JSON *string* in `payload` — the shape
    /// the server publishes. Getting this wrong would silently forward nothing.
    #[test]
    fn extracts_the_event_object_from_the_record_payload() {
        let record = serde_json::json!({
            "global_sequence": 12,
            "execution_id": "7",
            "payload": "{\"event_type\":\"step.exit\",\"execution_id\":\"7\"}"
        })
        .to_string();
        let payload = payload_from_record(&record).unwrap();
        assert_eq!(payload["event_type"], "step.exit");
        assert_eq!(payload["execution_id"], "7");
    }

    #[test]
    fn tolerates_a_record_whose_payload_is_already_an_object() {
        let record = serde_json::json!({
            "payload": {"event_type": "playbook.completed", "execution_id": "9"}
        })
        .to_string();
        let payload = payload_from_record(&record).unwrap();
        assert_eq!(payload["event_type"], "playbook.completed");
    }

    #[test]
    fn a_malformed_record_yields_no_payload_rather_than_panicking() {
        assert!(payload_from_record("not json").is_none());
        assert!(payload_from_record("{}").is_none());
        assert!(payload_from_record(r#"{"payload": 5}"#).is_none());
    }

    /// Both transports must produce the same client message for the same event,
    /// or a cutover would change what the SPA sees.
    #[test]
    fn ehdb_and_nats_paths_build_identical_client_messages() {
        let event = serde_json::json!({
            "event_type": "step.exit",
            "execution_id": "12345",
            "step_name": "plan",
        });
        // EHDB path: no subject, identity from the payload.
        let via_ehdb = crate::playbook_state::build_state_message(None, &event);
        // NATS path: a subject-derived id is available but the payload wins.
        let via_nats = crate::playbook_state::build_state_message(Some("12345"), &event);
        assert!(via_ehdb.is_some());

        // `at` is stamped at build time, so the two calls differ by microseconds.
        // The property under test is that the CONTENT matches, not the clock.
        let strip_at = |m: crate::connection_hub::JsonRpcMessage| {
            let mut v = serde_json::to_value(m).unwrap();
            if let Some(params) = v.get_mut("params").and_then(|p| p.as_object_mut()) {
                params.remove("at");
            }
            v
        };
        assert_eq!(strip_at(via_ehdb.unwrap()), strip_at(via_nats.unwrap()));
    }
}
