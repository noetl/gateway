//! Execution-lifecycle message construction for gateway SSE clients.
//!
//! The NATS listener that used to live here is gone (noetl/ai-meta#212); the
//! EHDB feed reader in [`crate::event_feed`] took its place. What remains is
//! [`build_state_message`], which **both** transports always shared — it is the
//! one place a lifecycle event becomes a client-facing `playbook/state` frame,
//! and it is on the live path.

use futures::{FutureExt, StreamExt};
use serde_json::Value;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use crate::connection_hub::{ConnectionHub, JsonRpcMessage};
use crate::request_store::RequestStore;

const FORWARDED_EVENT_TYPES: &[&str] = &[
    "step.exit",
    "playbook.completed",
    "playbook.failed",
    "calendar.event.touched",
];

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
