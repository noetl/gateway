//! Push-ingress config — the verify + dispatch + directive spec the gateway
//! fetches from the server's `GET /api/internal/ingress/{listener}` endpoint
//! (noetl/ai-meta#90 Phase 3, RFC §6).
//!
//! The gateway holds **no** DB connection (data-access-boundary.md); it learns
//! a subscription's verify scheme, the Wallet-resolved verify secret, the
//! dispatch target, and the directive allowlist by calling the server (gated by
//! the shared internal service-account token).  Results are cached briefly so a
//! burst of deliveries to the same listener resolves config once.

use serde::Deserialize;

/// Verify config (mirror of the server's `VerifyConfig`).
#[derive(Debug, Clone, Deserialize)]
pub struct VerifyConfig {
    #[serde(rename = "type")]
    pub verify_type: String,
    #[serde(default)]
    pub header: Option<String>,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub service_account: Option<String>,
}

/// Dispatch config (mirror of the server's `DispatchConfig`).
#[derive(Debug, Clone, Deserialize)]
pub struct DispatchConfig {
    pub playbook: String,
    #[serde(default = "default_payload_from")]
    pub payload_from: String,
    #[serde(default)]
    pub execution_pool: Option<String>,
}

fn default_payload_from() -> String {
    "message.json".to_string()
}

fn default_source() -> String {
    "webhook".to_string()
}

/// The full ingress config returned by the server.
#[derive(Debug, Clone, Deserialize)]
pub struct IngressConfig {
    pub listener: String,
    pub catalog_path: String,
    /// Source backend (`webhook` | `pubsub`) — selects the Pub/Sub-push
    /// envelope unwrap vs. generic-webhook body handling.
    #[serde(default = "default_source")]
    pub source: String,
    pub subscription_id: String,
    pub verify: VerifyConfig,
    pub dispatch: DispatchConfig,
    /// Raw `spec.headers` directive allowlist — parsed by the gateway's own
    /// directive engine and applied ONLY after verification (RFC §7.5).
    #[serde(default)]
    pub directives: Option<serde_json::Value>,
}

/// Fetch the ingress config for a listener from the server.  Returns
/// `Ok(None)` when the server reports no such push subscription (404), so the
/// handler can answer 404 without treating it as an error.
pub async fn fetch_ingress_config(
    http: &reqwest::Client,
    server_base_url: &str,
    internal_token: &str,
    listener: &str,
) -> anyhow::Result<Option<IngressConfig>> {
    let url = format!(
        "{}/api/internal/ingress/{}",
        server_base_url.trim_end_matches('/'),
        urlencoding_segment(listener)
    );
    let resp = http
        .get(&url)
        .bearer_auth(internal_token)
        .send()
        .await?;

    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!("ingress config fetch failed: {} - {}", status, body);
    }
    let cfg: IngressConfig = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("parse ingress config: {e} (body: {body})"))?;
    Ok(Some(cfg))
}

/// Google's public OIDC signing keys endpoint (for `pubsub_oidc` verification).
pub const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

/// Fetch Google's JWKS for OIDC verification.
pub async fn fetch_google_jwks(http: &reqwest::Client) -> anyhow::Result<super::verify::Jwks> {
    let jwks: super::verify::Jwks = http
        .get(GOOGLE_JWKS_URL)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(jwks)
}

/// Minimal path-segment percent-encoding for the listener (it is a single path
/// segment; subscriptions use simple slugs, but encode `/` and spaces defensively).
fn urlencoding_segment(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u32),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_ingress_config() {
        let cfg: IngressConfig = serde_json::from_str(
            r#"{
              "listener": "stripe",
              "catalog_path": "subscriptions/stripe",
              "subscription_id": "12345",
              "verify": { "type": "hmac_sha256", "header": "stripe-signature", "secret": "whsec" },
              "dispatch": { "playbook": "domain/handle", "payload_from": "message.body", "execution_pool": "subscription" },
              "directives": { "directives": [] }
            }"#,
        )
        .unwrap();
        assert_eq!(cfg.verify.verify_type, "hmac_sha256");
        assert_eq!(cfg.dispatch.execution_pool.as_deref(), Some("subscription"));
        assert!(cfg.directives.is_some());
    }

    #[test]
    fn payload_from_defaults() {
        let cfg: IngressConfig = serde_json::from_str(
            r#"{"listener":"x","catalog_path":"p","subscription_id":"1",
                "verify":{"type":"bearer","secret":"t"},
                "dispatch":{"playbook":"d"}}"#,
        )
        .unwrap();
        assert_eq!(cfg.dispatch.payload_from, "message.json");
        assert!(cfg.directives.is_none());
    }

    #[test]
    fn segment_encoding() {
        assert_eq!(urlencoding_segment("stripe-events"), "stripe-events");
        assert_eq!(urlencoding_segment("a/b"), "a%2Fb");
    }
}
