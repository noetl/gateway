//! Header / attribute directive engine — gateway-side copy.
//!
//! Phase 3 of the subscription/listener RFC
//! ([noetl/ai-meta#90](https://github.com/noetl/ai-meta/issues/90), RFC §7).
//!
//! ## Vendored from `noetl-tools`
//!
//! This is a **faithful, serde-only port** of
//! `noetl-tools::tools::source::directives` (crate `noetl-tools` v3.3.0,
//! `repos/tools/src/tools/source/directives.rs`).  It is vendored rather than
//! depended-on because `noetl-tools` unconditionally pulls `duckdb` (bundled
//! C++), `kube`, and `tokio-postgres` — weight the internet-facing gateway
//! must not carry.  The logic here is identical to the worker's (Mode B)
//! engine so push (Mode C) and pull (Mode B) honor directives the same way.
//!
//! **Keep in sync** with the source module: the allowlist + value-allowlist
//! semantics are security-load-bearing (RFC §7.5).  A fast-follow extracts a
//! lean shared `noetl-directives` crate so both consume one source — see the
//! tracking note on noetl/ai-meta#90.
//!
//! ## Untrusted by default (RFC §7.5)
//!
//! Nothing here trusts an arbitrary inbound header.  A header acts as a
//! directive **only** if its key appears in the configured allowlist, and even
//! then a value allowlist (`allowed:` / `map:`) constrains the target.  For
//! **push** ingress the gateway runs this engine **only after** auth
//! verification passes (`super::verify`); an unauthenticated caller can never
//! drive routing.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The dispatch concern a directive header controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Control {
    #[serde(rename = "dispatch.playbook")]
    DispatchPlaybook,
    #[serde(rename = "dispatch.execution_pool")]
    DispatchExecutionPool,
    Priority,
    IdempotencyKey,
    ContentType,
    SchemaHint,
}

impl Control {
    pub fn as_str(&self) -> &'static str {
        match self {
            Control::DispatchPlaybook => "dispatch.playbook",
            Control::DispatchExecutionPool => "dispatch.execution_pool",
            Control::Priority => "priority",
            Control::IdempotencyKey => "idempotency_key",
            Control::ContentType => "content_type",
            Control::SchemaHint => "schema_hint",
        }
    }
}

/// One allowlisted directive rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectiveRule {
    pub header: String,
    pub controls: Control,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub map: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TracePropagation {
    #[default]
    None,
    W3c,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TraceConfig {
    #[serde(default)]
    pub propagate: TracePropagation,
    #[serde(default)]
    pub baggage_allowlist: Vec<String>,
}

impl TraceConfig {
    fn is_enabled(&self) -> bool {
        matches!(self.propagate, TracePropagation::W3c)
    }
}

/// The parsed `headers:` directive block (RFC §7.2).  Default is fully off.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DirectiveSpec {
    #[serde(default)]
    pub normalize: bool,
    #[serde(default)]
    pub directives: Vec<DirectiveRule>,
    #[serde(default)]
    pub trace: TraceConfig,
    #[serde(default = "default_passthrough")]
    pub passthrough: String,
}

fn default_passthrough() -> String {
    "data".to_string()
}

/// W3C trace context extracted from a message's headers (RFC §7.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TraceContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traceparent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracestate: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub baggage: BTreeMap<String, String>,
}

impl TraceContext {
    pub fn is_empty(&self) -> bool {
        self.traceparent.is_none() && self.tracestate.is_none() && self.baggage.is_empty()
    }
}

/// One directive that actually applied, for the audit event (RFC §7.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedDirective {
    pub header: String,
    pub controls: String,
    pub effective_value: String,
}

/// The resolved effect of a message's directives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DispatchPlan {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub playbook_override: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_pool_override: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<TraceContext>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applied: Vec<AppliedDirective>,
}

impl DispatchPlan {
    pub fn is_noop(&self) -> bool {
        self.playbook_override.is_none()
            && self.execution_pool_override.is_none()
            && self.idempotency_key.is_none()
            && self.content_type.is_none()
            && self.schema_hint.is_none()
            && self.trace.is_none()
            && self.applied.is_empty()
    }
}

impl DirectiveSpec {
    /// Parse a `headers:` block (a JSON object) into a [`DirectiveSpec`].
    /// Validates that routing controls carry the value constraint they require
    /// (RFC §7.5): `dispatch.playbook` / `dispatch.execution_pool` need
    /// `allowed:`, `priority` needs `map:`.
    pub fn parse(value: &serde_json::Value) -> anyhow::Result<DirectiveSpec> {
        let mut spec: DirectiveSpec = serde_json::from_value(value.clone())
            .map_err(|e| anyhow::anyhow!("Invalid subscription 'headers' block: {e}"))?;

        for rule in spec.directives.iter_mut() {
            rule.header = rule.header.to_ascii_lowercase();
            match rule.controls {
                Control::DispatchPlaybook | Control::DispatchExecutionPool => {
                    let ok = rule.allowed.as_ref().map(|a| !a.is_empty()).unwrap_or(false);
                    if !ok {
                        return Err(anyhow::anyhow!(
                            "directive header '{}' controls '{}' but declares no non-empty \
                             'allowed:' value list — a routing directive must constrain its \
                             targets (RFC §7.5)",
                            rule.header,
                            rule.controls.as_str()
                        ));
                    }
                }
                Control::Priority => {
                    let ok = rule.map.as_ref().map(|m| !m.is_empty()).unwrap_or(false);
                    if !ok {
                        return Err(anyhow::anyhow!(
                            "directive header '{}' controls 'priority' but declares no non-empty \
                             'map:' (value → pool) — a priority directive must map to allowed \
                             pools (RFC §7.5)",
                            rule.header
                        ));
                    }
                }
                Control::IdempotencyKey | Control::ContentType | Control::SchemaHint => {}
            }
        }

        Ok(spec)
    }

    /// Resolve this spec against a message's normalized headers map.  Only
    /// allowlisted keys are honored; routing controls are further constrained
    /// by their `allowed:` / `map:` value lists.  Multi-value headers are
    /// last-wins (RFC §10 OQ7).
    pub fn resolve(&self, headers: &serde_json::Map<String, serde_json::Value>) -> DispatchPlan {
        let mut plan = DispatchPlan::default();

        for rule in &self.directives {
            let Some(raw) = headers.get(&rule.header) else {
                continue;
            };
            let Some(value) = last_value(raw) else {
                continue;
            };

            match rule.controls {
                Control::DispatchPlaybook => {
                    if value_allowed(rule.allowed.as_ref(), &value) {
                        plan.playbook_override = Some(value.clone());
                        plan.applied.push(applied(rule, &value));
                    }
                }
                Control::DispatchExecutionPool => {
                    if value_allowed(rule.allowed.as_ref(), &value) {
                        plan.execution_pool_override = Some(value.clone());
                        plan.applied.push(applied(rule, &value));
                    }
                }
                Control::Priority => {
                    if let Some(map) = rule.map.as_ref() {
                        if let Some(pool) = map.get(&value) {
                            if plan.execution_pool_override.is_none() {
                                plan.execution_pool_override = Some(pool.clone());
                            }
                            plan.applied.push(AppliedDirective {
                                header: rule.header.clone(),
                                controls: rule.controls.as_str().to_string(),
                                effective_value: pool.clone(),
                            });
                        }
                    }
                }
                Control::IdempotencyKey => {
                    plan.idempotency_key = Some(value.clone());
                    plan.applied.push(applied(rule, &value));
                }
                Control::ContentType => {
                    plan.content_type = Some(value.clone());
                    plan.applied.push(applied(rule, &value));
                }
                Control::SchemaHint => {
                    plan.schema_hint = Some(value.clone());
                    plan.applied.push(applied(rule, &value));
                }
            }
        }

        // Precedence fix-up: an explicit `dispatch.execution_pool` directive
        // wins over a `priority` map even when priority was declared first.
        for rule in &self.directives {
            if rule.controls == Control::DispatchExecutionPool {
                if let Some(raw) = headers.get(&rule.header) {
                    if let Some(value) = last_value(raw) {
                        if value_allowed(rule.allowed.as_ref(), &value) {
                            plan.execution_pool_override = Some(value);
                        }
                    }
                }
            }
        }

        if self.trace.is_enabled() {
            let trace = extract_w3c_trace(headers, &self.trace.baggage_allowlist);
            if !trace.is_empty() {
                plan.trace = Some(trace);
            }
        }

        plan
    }
}

fn last_value(raw: &serde_json::Value) -> Option<String> {
    match raw {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Array(arr) => {
            arr.iter().rev().find_map(|v| v.as_str().map(str::to_string))
        }
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn value_allowed(allowed: Option<&Vec<String>>, value: &str) -> bool {
    match allowed {
        Some(list) => list.iter().any(|a| a == value),
        None => true,
    }
}

fn applied(rule: &DirectiveRule, value: &str) -> AppliedDirective {
    AppliedDirective {
        header: rule.header.clone(),
        controls: rule.controls.as_str().to_string(),
        effective_value: value.to_string(),
    }
}

/// Extract a W3C trace context from the normalized headers map.
pub fn extract_w3c_trace(
    headers: &serde_json::Map<String, serde_json::Value>,
    baggage_allowlist: &[String],
) -> TraceContext {
    let mut tc = TraceContext::default();

    if let Some(tp) = headers.get("traceparent").and_then(last_value_ref) {
        if is_plausible_traceparent(&tp) {
            tc.traceparent = Some(tp);
        }
    }
    if let Some(ts) = headers.get("tracestate").and_then(last_value_ref) {
        tc.tracestate = Some(ts);
    }
    if !baggage_allowlist.is_empty() {
        if let Some(raw) = headers.get("baggage").and_then(last_value_ref) {
            for item in raw.split(',') {
                let item = item.trim();
                if let Some((k, v)) = item.split_once('=') {
                    let key = k.trim();
                    let val = v.split(';').next().unwrap_or("").trim();
                    if baggage_allowlist.iter().any(|a| a == key) {
                        tc.baggage.insert(key.to_string(), val.to_string());
                    }
                }
            }
        }
    }

    tc
}

fn last_value_ref(raw: &serde_json::Value) -> Option<String> {
    last_value(raw)
}

fn is_plausible_traceparent(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 4
        && parts[0].len() == 2
        && parts[1].len() == 32
        && parts[2].len() == 16
        && parts[3].len() == 2
        && parts.iter().all(|p| p.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Normalize an HTTP header set into the uniform lowercased `message.headers`
/// map (RFC §7.1).  Multi-value headers collapse to an array.  This is the
/// HTTP-channel normalizer the gateway uses for push/webhook ingress, the
/// counterpart of `noetl-tools`' source-client `normalize_headers`.
pub fn normalize_http_headers(
    raw: &[(String, String)],
) -> serde_json::Map<String, serde_json::Value> {
    let mut acc: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (k, v) in raw {
        acc.entry(k.to_ascii_lowercase()).or_default().push(v.clone());
    }
    let mut out = serde_json::Map::new();
    for (k, mut vals) in acc {
        let value = if vals.len() == 1 {
            serde_json::Value::String(vals.pop().unwrap())
        } else {
            serde_json::Value::Array(vals.into_iter().map(serde_json::Value::String).collect())
        };
        out.insert(k, value);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn headers(v: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn empty_spec_is_noop() {
        let spec = DirectiveSpec::default();
        let plan = spec.resolve(&headers(json!({ "x-anything": "value" })));
        assert!(plan.is_noop());
    }

    #[test]
    fn parse_requires_allowed_for_routing() {
        let err = DirectiveSpec::parse(&json!({
            "directives": [{ "header": "x-route", "controls": "dispatch.playbook" }]
        }))
        .unwrap_err();
        assert!(format!("{err}").contains("allowed"));

        let err = DirectiveSpec::parse(&json!({
            "directives": [{ "header": "x-prio", "controls": "priority" }]
        }))
        .unwrap_err();
        assert!(format!("{err}").contains("map"));
    }

    #[test]
    fn parse_lowercases_header_keys() {
        let spec = DirectiveSpec::parse(&json!({
            "directives": [{ "header": "X-Idempotency-Key", "controls": "idempotency_key" }]
        }))
        .unwrap();
        assert_eq!(spec.directives[0].header, "x-idempotency-key");
    }

    #[test]
    fn redirect_playbook_respects_allowlist() {
        let spec = DirectiveSpec::parse(&json!({
            "directives": [{
                "header": "x-noetl-route",
                "controls": "dispatch.playbook",
                "allowed": ["domain/handle_billing", "domain/handle_fraud"]
            }]
        }))
        .unwrap();

        let plan = spec.resolve(&headers(json!({ "x-noetl-route": "domain/handle_fraud" })));
        assert_eq!(plan.playbook_override.as_deref(), Some("domain/handle_fraud"));
        assert_eq!(plan.applied.len(), 1);

        // Non-allowlisted value is ignored — never routes to an arbitrary playbook.
        let plan = spec.resolve(&headers(json!({ "x-noetl-route": "domain/evil" })));
        assert!(plan.playbook_override.is_none());
        assert!(plan.applied.is_empty());
    }

    #[test]
    fn execution_pool_priority_precedence() {
        let spec = DirectiveSpec::parse(&json!({
            "directives": [
                { "header": "x-priority", "controls": "priority", "map": { "high": "priority", "normal": "shared" } },
                { "header": "x-noetl-pool", "controls": "dispatch.execution_pool", "allowed": ["iot", "priority", "shared"] }
            ]
        }))
        .unwrap();
        let plan = spec.resolve(&headers(json!({ "x-priority": "high", "x-noetl-pool": "iot" })));
        assert_eq!(plan.execution_pool_override.as_deref(), Some("iot"));
    }

    #[test]
    fn w3c_trace_extracted_when_enabled() {
        let spec = DirectiveSpec::parse(&json!({
            "trace": { "propagate": "w3c", "baggage_allowlist": ["tenant"] }
        }))
        .unwrap();
        let plan = spec.resolve(&headers(json!({
            "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            "baggage": "tenant=acme,secret=nope"
        })));
        let tc = plan.trace.unwrap();
        assert!(tc.traceparent.is_some());
        assert_eq!(tc.baggage.get("tenant").map(String::as_str), Some("acme"));
        assert!(!tc.baggage.contains_key("secret"));
    }

    #[test]
    fn normalize_http_headers_lowercases_and_groups() {
        let raw = vec![
            ("X-Noetl-Route".to_string(), "domain/x".to_string()),
            ("Accept".to_string(), "a".to_string()),
            ("Accept".to_string(), "b".to_string()),
        ];
        let m = normalize_http_headers(&raw);
        assert_eq!(m.get("x-noetl-route").unwrap(), "domain/x");
        assert_eq!(m.get("accept").unwrap(), &json!(["a", "b"]));
    }
}
