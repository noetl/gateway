//! NATS execution lifecycle forwarding for gateway SSE clients.

use async_nats::Client;
use futures::{FutureExt, StreamExt};
use serde_json::Value;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use crate::connection_hub::{ConnectionHub, JsonRpcMessage};
use crate::request_store::RequestStore;

const FORWARDED_EVENT_TYPES: &[&str] = &["step.exit", "playbook.completed", "playbook.failed", "calendar.event.touched"];

pub async fn start_playbook_state_listener(
    nats_url: &str,
    updates_subject_prefix: &str,
    request_store: Arc<RequestStore>,
    connection_hub: Arc<ConnectionHub>,
) -> anyhow::Result<()> {
    let client = connect_nats(nats_url).await?;
    let subject = format!("{}>", updates_subject_prefix);
    tracing::info!("Subscribing to execution lifecycle NATS events: {}", subject);
    let mut subscriber = client.subscribe(subject).await?;
    let prefix = updates_subject_prefix.to_string();

    tokio::spawn(async move {
        // Wrap the loop so that a panic in message handling is surfaced as an
        // ERROR log rather than silently killing the task.  Without this,
        // ``tokio::spawn`` swallows the panic and the subscription appears
        // alive (the "Subscribing" log fires but nothing follows) while in
        // fact the task died.
        let res = AssertUnwindSafe(async move {
            while let Some(msg) = subscriber.next().await {
                let subject = msg.subject.to_string();
                let payload_len = msg.payload.len();
                // Log every received message so we can confirm delivery.
                // Frequency is bounded by playbook lifecycle events (not a
                // poll loop) so INFO is acceptable per agents/rules/logging.md.
                let preview_len = payload_len.min(200);
                let preview = String::from_utf8_lossy(&msg.payload[..preview_len]);
                tracing::info!(
                    subject = %subject,
                    payload_bytes = payload_len,
                    payload_preview = %preview,
                    "Received execution lifecycle NATS message",
                );

                let execution_id = execution_id_from_subject(&subject, &prefix);
                let Ok(payload) = serde_json::from_slice::<Value>(&msg.payload) else {
                    tracing::warn!(subject, "Failed to parse lifecycle NATS payload as JSON");
                    continue;
                };
                let Some(message) = build_state_message(execution_id.as_deref(), &payload) else {
                    continue;
                };
                let Some(execution_id) = message
                    .params
                    .as_ref()
                    .and_then(|params| params.get("execution_id"))
                    .and_then(|value| value.as_str())
                    .map(ToString::to_string)
                else {
                    continue;
                };

                for (_, pending) in request_store.get_by_execution(&execution_id).await {
                    let _ = connection_hub.send_to_client(&pending.client_id, message.clone()).await;
                }
            }
            tracing::warn!("Execution lifecycle NATS subscription ended");
        })
        .catch_unwind()
        .await;

        if let Err(e) = res {
            // Attempt to extract a printable panic message.
            let panic_msg = e
                .downcast_ref::<&str>()
                .map(|s| *s)
                .or_else(|| e.downcast_ref::<String>().map(|s| s.as_str()))
                .unwrap_or("<non-string panic payload>");
            tracing::error!(
                panic_msg,
                "Execution lifecycle NATS subscription panicked — subscription is dead"
            );
        }
    });

    Ok(())
}

async fn connect_nats(nats_url: &str) -> anyhow::Result<Client> {
    if let Ok(url) = url::Url::parse(nats_url) {
        let host = url.host_str().unwrap_or("localhost");
        let port = url.port().unwrap_or(4222);
        let server_addr = format!("{}:{}", host, port);

        if !url.username().is_empty() {
            let user = url.username();
            let pass = url.password().unwrap_or("");
            return Ok(
                async_nats::ConnectOptions::with_user_and_password(user.to_string(), pass.to_string())
                    .connect(&server_addr)
                    .await?,
            );
        }
        return Ok(async_nats::connect(&server_addr).await?);
    }

    Ok(async_nats::connect(nats_url).await?)
}

fn execution_id_from_subject(subject: &str, prefix: &str) -> Option<String> {
    // The noetl event publisher (see
    // ``noetl/core/messaging/nats_client.py::subject_for_event``) builds
    // subjects of the form
    //
    //     {subject_prefix}.{tenant_id}.{organization_id}.{execution_id}.{shard}
    //
    // with ``subject_prefix`` defaulting to ``noetl.events``.  The gateway
    // subscribes to ``{NATS_UPDATES_SUBJECT_PREFIX}>`` so the prefix we
    // strip here MUST be the operator-configured prefix with a trailing
    // dot (e.g. ``"noetl.events."``).  After stripping it, the tail tokens
    // are ``{tenant}.{org}.{exec_id}.{shard}``, so the execution id lives
    // at position 2 (third token), not position 0.
    //
    // An earlier shape took position 0 directly.  That worked only with
    // the legacy ``"playbooks.executions."`` prefix where the subject was
    // ``{prefix}.{exec_id}.{step}.{event}``, but the noetl publisher does
    // not publish on that subject — it never has — so the previous
    // gateway image received zero ``playbook/state`` messages and the SPA
    // hung at ``Muno is planning…`` indefinitely.  See
    // ``handoffs/archive/2026-05-27-itinerary-planner-spa-hang/round-01-result.md``
    // in the ai-meta repo for the full diagnostic.
    //
    // ``build_state_message`` below prefers ``payload.execution_id`` over
    // any subject-derived value, so an empty / malformed subject tail is
    // a soft failure: this helper returns ``None`` and the payload field
    // still resolves the id.
    let tail = subject.strip_prefix(prefix)?;
    let mut parts = tail.split('.');
    let _tenant = parts.next()?;
    let _organization = parts.next()?;
    parts
        .next()
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

pub fn build_state_message(subject_execution_id: Option<&str>, payload: &Value) -> Option<JsonRpcMessage> {
    let event_type = first_string(payload, &["event_type", "type", "name"])?;
    if !FORWARDED_EVENT_TYPES.contains(&event_type.as_str()) {
        return None;
    }

    let execution_id = first_string(payload, &["execution_id", "executionId", "id"])
        .or_else(|| subject_execution_id.map(ToString::to_string))?;
    let step_name = first_string(payload, &["step_name", "stepName", "node_name", "nodeName", "step"]);
    let status = first_string(payload, &["status"]).unwrap_or_else(|| status_from_event_type(&event_type).to_string());
    let at = first_string(payload, &["at", "timestamp", "created_at", "createdAt"])
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

    Some(JsonRpcMessage::notification(
        "playbook/state",
        serde_json::json!({
            "execution_id": execution_id,
            "event_type": event_type,
            "step_name": step_name,
            "status": status,
            "at": at,
        }),
    ))
}

fn first_string(payload: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(value) = payload.get(*key).and_then(|value| value.as_str()) {
            if !value.trim().is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn status_from_event_type(event_type: &str) -> &'static str {
    match event_type {
        "playbook.failed" => "failed",
        "playbook.completed" => "completed",
        _ => "running",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_execution_id_from_subject_and_filters_events() {
        let payload = serde_json::json!({
            "event_type": "step.exit",
            "step_name": "render_widget_chat",
            "status": "completed",
            "at": "2026-05-24T17:00:00Z"
        });
        let message = build_state_message(Some("exec-1"), &payload).expect("state message");
        assert_eq!(message.method.as_deref(), Some("playbook/state"));
        let params = message.params.expect("params");
        assert_eq!(params["execution_id"], "exec-1");
        assert_eq!(params["event_type"], "step.exit");
        assert_eq!(params["step_name"], "render_widget_chat");

        assert!(build_state_message(Some("exec-1"), &serde_json::json!({ "event_type": "step.started" })).is_none());
    }

    #[test]
    fn parses_execution_id_from_noetl_events_subject() {
        // noetl event publisher subject shape:
        // {prefix}.{tenant}.{org}.{exec_id}.{shard}
        assert_eq!(
            execution_id_from_subject(
                "noetl.events.tenant1.org1.exec-1.0",
                "noetl.events.",
            ),
            Some("exec-1".to_string())
        );
    }

    #[test]
    fn parses_execution_id_with_none_tenant_org_tokens() {
        // ``_subject_token`` in nats_client.py emits the literal
        // ``"none"`` when tenant_id / organization_id are missing from an
        // event payload.  The subject is well-formed and the extraction
        // must still produce the exec_id.
        assert_eq!(
            execution_id_from_subject(
                "noetl.events.none.none.635758340626186455.7",
                "noetl.events.",
            ),
            Some("635758340626186455".to_string())
        );
    }

    #[test]
    fn returns_none_for_subject_without_prefix() {
        // Defensive: a stray message published on an unrelated subject
        // (or with the wrong prefix configured) must not produce an id.
        assert!(execution_id_from_subject(
            "playbooks.executions.exec-1.step.exit",
            "noetl.events.",
        )
        .is_none());
    }

    #[test]
    fn returns_none_for_subject_missing_exec_id_token() {
        // Subject tail has fewer than the expected 3 tokens
        // (tenant.org.exec_id) — return None so ``build_state_message``
        // falls back to ``payload.execution_id``.
        assert!(execution_id_from_subject("noetl.events.t.o", "noetl.events.").is_none());
        assert!(execution_id_from_subject("noetl.events.t", "noetl.events.").is_none());
        assert!(execution_id_from_subject("noetl.events.", "noetl.events.").is_none());
    }

    #[test]
    fn returns_none_for_empty_exec_id_token() {
        // Defensive: ``..`` should yield empty tenant/org/exec; we filter
        // empty exec_id and return None.
        assert!(execution_id_from_subject("noetl.events.t.o..0", "noetl.events.").is_none());
    }

    /// Regression: ``build_state_message`` must produce a valid
    /// ``playbook/state`` frame for a synthetic ``playbook.completed``
    /// envelope — the shape noetl publishes on ``noetl.events.*``.
    ///
    /// This test exercises the parser and forwarder without requiring a live
    /// NATS connection so the regression coverage stays tight even in CI
    /// environments with no broker.
    #[test]
    fn builds_playbook_completed_state_message_from_synthetic_envelope() {
        let payload = serde_json::json!({
            "event_type": "playbook.completed",
            "execution_id": "635758340626186455",
            "status": "completed",
            "at": "2026-05-27T15:00:00Z",
        });

        let msg = build_state_message(None, &payload).expect("should build state message for playbook.completed");

        assert_eq!(msg.method.as_deref(), Some("playbook/state"));
        let params = msg.params.expect("params present");
        assert_eq!(params["execution_id"], "635758340626186455");
        assert_eq!(params["event_type"], "playbook.completed");
        assert_eq!(params["status"], "completed");
        assert_eq!(params["at"], "2026-05-27T15:00:00Z");
        // step_name is absent in this envelope; must be present as JSON null
        // (serde_json::json! serialises Option::None as null).
        assert!(params["step_name"].is_null());
    }

    #[test]
    fn builds_playbook_failed_state_message_from_synthetic_envelope() {
        let payload = serde_json::json!({
            "event_type": "playbook.failed",
            "execution_id": "999000111222333444",
            "at": "2026-05-27T15:01:00Z",
        });

        let msg = build_state_message(None, &payload).expect("should build state message for playbook.failed");

        let params = msg.params.expect("params present");
        assert_eq!(params["execution_id"], "999000111222333444");
        assert_eq!(params["status"], "failed");
    }

    #[test]
    fn build_state_message_falls_back_to_subject_execution_id_when_payload_has_none() {
        // The payload lacks ``execution_id``; the subject-derived id is the
        // fallback.  This mirrors the code path hit when noetl publishes a
        // lean ``step.exit`` event without an explicit execution_id field.
        let payload = serde_json::json!({
            "event_type": "step.exit",
            "step_name": "some_step",
            "status": "completed",
            "at": "2026-05-27T15:02:00Z",
        });

        let msg = build_state_message(Some("fallback-exec-id"), &payload)
            .expect("should build state message with fallback exec id");

        let params = msg.params.expect("params present");
        assert_eq!(params["execution_id"], "fallback-exec-id");
    }
}
