//! Push / webhook authenticity verification — the gatekeeper's core job.
//!
//! Phase 3 of the subscription/listener RFC
//! ([noetl/ai-meta#90](https://github.com/noetl/ai-meta/issues/90), RFC §6).
//!
//! The gateway is the only component that terminates untrusted inbound push
//! traffic, so verification lives here.  Four schemes (RFC §6 table):
//!
//! | `verify.type` | Check |
//! |---|---|
//! | `hmac_sha256` | Recompute `HMAC-SHA256(secret, raw_body)`, constant-time compare against the signature header (optional `sha256=` prefix). |
//! | `bearer`      | Constant-time compare the bearer token against the expected token. |
//! | `stripe_signature` | Stripe webhook scheme: parse `t=<unix>,v1=<hex>[,v1=…]` from the signature header (default `stripe-signature`), recompute `HMAC-SHA256(secret, "{t}.{raw_body}")`, constant-time compare against every `v1`, and reject when `|now - t|` exceeds `tolerance_secs` (default 300). |
//! | `pubsub_oidc` | Validate the Google-signed OIDC JWT: RS256 signature vs Google JWKS, `aud == audience`, `email == service_account`, `email_verified`, not expired. |
//!
//! **Security ordering (RFC §7.5):** a caller that fails verification is
//! rejected here, *before* any header directive is parsed.  `verify()` returns
//! `Err(_)` and the handler stops — it never reaches the directive engine.

use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::config::VerifyConfig;

type HmacSha256 = Hmac<Sha256>;

/// A verification failure.  `reason` is a low-cardinality label safe for the
/// `noetl_ingress_rejected_total{reason}` metric; `detail` is for the log.
#[derive(Debug, Clone)]
pub struct VerifyRejection {
    /// HTTP status to return (401 unauthenticated / 403 forbidden).
    pub status: u16,
    /// Stable, low-cardinality reason (metric label).
    pub reason: &'static str,
    /// Human detail (log only — never leaks the secret).
    pub detail: String,
}

impl VerifyRejection {
    fn unauthorized(reason: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status: 401,
            reason,
            detail: detail.into(),
        }
    }
    fn forbidden(reason: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status: 403,
            reason,
            detail: detail.into(),
        }
    }
}

/// Look up a single header value (case-insensitive) from the normalized map.
fn header_str<'a>(headers: &'a serde_json::Map<String, serde_json::Value>, name: &str) -> Option<&'a str> {
    match headers.get(&name.to_ascii_lowercase())? {
        serde_json::Value::String(s) => Some(s.as_str()),
        // Multi-value: take the first (verification headers are single-valued).
        serde_json::Value::Array(a) => a.first().and_then(|v| v.as_str()),
        _ => None,
    }
}

/// Verify a delivery against the subscription's configured scheme.
///
/// `headers` is the normalized (lowercased) HTTP header map; `body` is the raw
/// request body bytes (HMAC is computed over the exact bytes).  For
/// `pubsub_oidc`, `jwks` must carry the fetched Google signing keys.
pub fn verify(
    cfg: &VerifyConfig,
    headers: &serde_json::Map<String, serde_json::Value>,
    body: &[u8],
    jwks: Option<&Jwks>,
) -> Result<(), VerifyRejection> {
    match cfg.verify_type.as_str() {
        "hmac_sha256" => verify_hmac(cfg, headers, body),
        "bearer" => verify_bearer(cfg, headers),
        "stripe_signature" => verify_stripe(cfg, headers, body, unix_now()),
        "pubsub_oidc" => {
            let jwks =
                jwks.ok_or_else(|| VerifyRejection::unauthorized("oidc_no_jwks", "no JWKS available for OIDC verify"))?;
            verify_oidc(cfg, headers, jwks)
        }
        other => Err(VerifyRejection::forbidden(
            "unsupported",
            format!("unsupported verify.type '{other}'"),
        )),
    }
}

/// HMAC-SHA256 over the raw body, constant-time vs the signature header.
fn verify_hmac(
    cfg: &VerifyConfig,
    headers: &serde_json::Map<String, serde_json::Value>,
    body: &[u8],
) -> Result<(), VerifyRejection> {
    let header_name = cfg.header.as_deref().unwrap_or("x-signature");
    let secret = cfg
        .secret
        .as_deref()
        .ok_or_else(|| VerifyRejection::forbidden("misconfigured", "hmac_sha256 verify has no resolved secret"))?;

    let provided = header_str(headers, header_name).ok_or_else(|| {
        VerifyRejection::unauthorized("missing_signature", format!("missing signature header '{header_name}'"))
    })?;
    // Accept an optional `sha256=` prefix (GitHub-style) on the header value.
    let provided = provided
        .strip_prefix("sha256=")
        .or_else(|| provided.strip_prefix("SHA256="))
        .unwrap_or(provided)
        .trim();

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| VerifyRejection::forbidden("misconfigured", format!("hmac key: {e}")))?;
    mac.update(body);
    let expected_hex = hex::encode(mac.finalize().into_bytes());

    // Constant-time compare (lowercased hex on both sides).
    let a = expected_hex.as_bytes();
    let b = provided.to_ascii_lowercase();
    let b = b.as_bytes();
    if a.len() == b.len() && bool::from(a.ct_eq(b)) {
        Ok(())
    } else {
        Err(VerifyRejection::unauthorized(
            "bad_signature",
            "HMAC signature mismatch",
        ))
    }
}

/// Default replay window for `stripe_signature` (Stripe's own SDK default).
pub const STRIPE_DEFAULT_TOLERANCE_SECS: u64 = 300;

/// The header that carries the signature/token for a verify config, with the
/// per-scheme default applied.  Used to scrub it from the forwarded workload
/// even when the subscription relies on the default header name.
pub fn signature_header(cfg: &VerifyConfig) -> Option<String> {
    let default = match cfg.verify_type.as_str() {
        "hmac_sha256" => "x-signature",
        "stripe_signature" => "stripe-signature",
        "bearer" | "pubsub_oidc" => "authorization",
        _ => return cfg.header.as_ref().map(|h| h.to_ascii_lowercase()),
    };
    Some(cfg.header.as_deref().unwrap_or(default).to_ascii_lowercase())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Stripe webhook signature (`Stripe-Signature: t=…,v1=…`).
///
/// Signed payload is `"{t}.{raw_body}"`, keyed with the full endpoint secret
/// (`whsec_…`, prefix included, exactly as Stripe's SDKs do).  Passes when ANY
/// `v1` matches (Stripe sends several during secret rotation); `v0` and
/// unknown keys are ignored.  `now` is injected so tests are deterministic.
fn verify_stripe(
    cfg: &VerifyConfig,
    headers: &serde_json::Map<String, serde_json::Value>,
    body: &[u8],
    now: i64,
) -> Result<(), VerifyRejection> {
    let header_name = cfg.header.as_deref().unwrap_or("stripe-signature");
    let secret =
        cfg.secret.as_deref().filter(|s| !s.is_empty()).ok_or_else(|| {
            VerifyRejection::forbidden("misconfigured", "stripe_signature verify has no resolved secret")
        })?;
    let raw = header_str(headers, header_name).ok_or_else(|| {
        VerifyRejection::unauthorized("missing_signature", format!("missing signature header '{header_name}'"))
    })?;

    let mut timestamp: Option<&str> = None;
    let mut v1: Vec<&str> = Vec::new();
    for part in raw.split(',') {
        let Some((k, v)) = part.trim().split_once('=') else {
            continue;
        };
        match k.trim() {
            "t" => timestamp = Some(v.trim()),
            "v1" => v1.push(v.trim()),
            _ => {}
        }
    }
    let ts_str = timestamp.ok_or_else(|| {
        VerifyRejection::unauthorized("malformed_signature", "stripe signature header has no timestamp")
    })?;
    let ts: i64 = ts_str.parse().map_err(|_| {
        VerifyRejection::unauthorized("malformed_signature", "stripe signature timestamp is not an integer")
    })?;
    if v1.is_empty() {
        return Err(VerifyRejection::unauthorized(
            "malformed_signature",
            "stripe signature header has no v1 signature",
        ));
    }

    let tolerance = cfg.tolerance_secs.unwrap_or(STRIPE_DEFAULT_TOLERANCE_SECS) as i64;
    if (now - ts).abs() > tolerance {
        return Err(VerifyRejection::unauthorized(
            "stale_timestamp",
            format!("stripe signature timestamp outside {tolerance}s tolerance"),
        ));
    }

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| VerifyRejection::forbidden("misconfigured", format!("hmac key: {e}")))?;
    mac.update(ts_str.as_bytes());
    mac.update(b".");
    mac.update(body);
    let expected_hex = hex::encode(mac.finalize().into_bytes());
    let a = expected_hex.as_bytes();

    // Check every candidate without short-circuiting on the first match.
    let mut matched = subtle::Choice::from(0u8);
    for sig in &v1 {
        let b = sig.to_ascii_lowercase();
        if b.len() == a.len() {
            matched |= a.ct_eq(b.as_bytes());
        }
    }
    if bool::from(matched) {
        Ok(())
    } else {
        Err(VerifyRejection::unauthorized(
            "bad_signature",
            "stripe signature mismatch",
        ))
    }
}

/// Constant-time bearer-token compare.
fn verify_bearer(
    cfg: &VerifyConfig,
    headers: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), VerifyRejection> {
    let header_name = cfg.header.as_deref().unwrap_or("authorization");
    let secret = cfg
        .secret
        .as_deref()
        .ok_or_else(|| VerifyRejection::forbidden("misconfigured", "bearer verify has no resolved token"))?;

    let raw = header_str(headers, header_name)
        .ok_or_else(|| VerifyRejection::unauthorized("missing_token", format!("missing '{header_name}' header")))?;
    // Strip an optional `Bearer ` scheme.
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
        .unwrap_or(raw)
        .trim();

    let a = token.as_bytes();
    let b = secret.as_bytes();
    if a.len() == b.len() && bool::from(a.ct_eq(b)) {
        Ok(())
    } else {
        Err(VerifyRejection::unauthorized("bad_token", "bearer token mismatch"))
    }
}

// ---------------------------------------------------------------------------
// Google Pub/Sub OIDC (JWT) verification
// ---------------------------------------------------------------------------

/// A minimal JWKS (JSON Web Key Set) — the RSA public keys Google publishes at
/// `https://www.googleapis.com/oauth2/v3/certs`.
#[derive(Debug, Clone, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kid: String,
    pub n: String,
    pub e: String,
    #[serde(default)]
    pub alg: Option<String>,
}

impl Jwks {
    fn find(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid == kid)
    }
}

/// Claims we assert on the Google OIDC token.
#[derive(Debug, Deserialize)]
struct OidcClaims {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<bool>,
}

/// Validate the Google-signed OIDC JWT carried in the `Authorization: Bearer`
/// header (RFC §6 `pubsub_oidc`).  Checks: RS256 signature vs the JWKS key
/// named by the token's `kid`, `aud == audience`, `exp` not passed (60s
/// leeway), `email == service_account`, `email_verified == true`.
fn verify_oidc(
    cfg: &VerifyConfig,
    headers: &serde_json::Map<String, serde_json::Value>,
    jwks: &Jwks,
) -> Result<(), VerifyRejection> {
    let raw = header_str(headers, "authorization")
        .ok_or_else(|| VerifyRejection::unauthorized("missing_token", "missing Authorization header for OIDC"))?;
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
        .unwrap_or(raw)
        .trim();

    let audience = cfg
        .audience
        .as_deref()
        .ok_or_else(|| VerifyRejection::forbidden("misconfigured", "pubsub_oidc verify has no audience"))?;
    let expected_sa = cfg
        .service_account
        .as_deref()
        .ok_or_else(|| VerifyRejection::forbidden("misconfigured", "pubsub_oidc verify has no service_account"))?;

    validate_oidc_jwt(token, jwks, audience, expected_sa)
}

/// Pure JWT validation — separated from header extraction + JWKS fetch so it is
/// unit-testable with a self-minted RSA key + JWKS (no network, no clock dep
/// beyond `jsonwebtoken`'s own `exp` check).
pub fn validate_oidc_jwt(token: &str, jwks: &Jwks, audience: &str, expected_sa: &str) -> Result<(), VerifyRejection> {
    use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

    let header = decode_header(token)
        .map_err(|e| VerifyRejection::unauthorized("oidc_malformed", format!("jwt header: {e}")))?;
    let kid = header
        .kid
        .ok_or_else(|| VerifyRejection::unauthorized("oidc_malformed", "jwt has no 'kid'"))?;
    let jwk = jwks
        .find(&kid)
        .ok_or_else(|| VerifyRejection::unauthorized("oidc_unknown_kid", format!("no JWKS key for kid '{kid}'")))?;

    let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
        .map_err(|e| VerifyRejection::forbidden("oidc_bad_key", format!("jwk rsa: {e}")))?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[audience]);
    validation.validate_exp = true;
    validation.leeway = 60;

    let data = decode::<OidcClaims>(token, &key, &validation).map_err(|e| {
        use jsonwebtoken::errors::ErrorKind;
        match e.kind() {
            ErrorKind::ExpiredSignature => VerifyRejection::unauthorized("oidc_expired", "OIDC token expired"),
            ErrorKind::InvalidAudience => VerifyRejection::forbidden("oidc_wrong_audience", "OIDC audience mismatch"),
            ErrorKind::InvalidSignature => {
                VerifyRejection::unauthorized("oidc_bad_signature", "OIDC signature invalid")
            }
            _ => VerifyRejection::unauthorized("oidc_invalid", format!("OIDC validation: {e}")),
        }
    })?;

    // Pub/Sub push identity: the token's email must be the configured push SA
    // and must be verified.
    match (data.claims.email.as_deref(), data.claims.email_verified) {
        (Some(email), Some(true)) if email == expected_sa => Ok(()),
        (Some(email), _) if email != expected_sa => Err(VerifyRejection::forbidden(
            "oidc_wrong_sa",
            "OIDC email != configured service_account",
        )),
        _ => Err(VerifyRejection::forbidden(
            "oidc_unverified_email",
            "OIDC email missing or not verified",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn hdrs(v: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        v.as_object().unwrap().clone()
    }

    fn hmac_hex(secret: &str, body: &[u8]) -> String {
        let mut m = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        m.update(body);
        hex::encode(m.finalize().into_bytes())
    }

    fn hmac_cfg() -> VerifyConfig {
        VerifyConfig {
            verify_type: "hmac_sha256".into(),
            header: Some("x-signature".into()),
            secret: Some("shhh".into()),
            audience: None,
            service_account: None,
            tolerance_secs: None,
        }
    }

    #[test]
    fn hmac_good_signature_passes() {
        let body = b"{\"event\":\"ok\"}";
        let sig = hmac_hex("shhh", body);
        let h = hdrs(json!({ "x-signature": sig }));
        assert!(verify(&hmac_cfg(), &h, body, None).is_ok());
    }

    #[test]
    fn hmac_good_signature_with_prefix_passes() {
        let body = b"payload";
        let sig = format!("sha256={}", hmac_hex("shhh", body));
        let h = hdrs(json!({ "x-signature": sig }));
        assert!(verify(&hmac_cfg(), &h, body, None).is_ok());
    }

    #[test]
    fn hmac_bad_signature_rejected() {
        let body = b"payload";
        let h = hdrs(json!({ "x-signature": "deadbeef" }));
        let err = verify(&hmac_cfg(), &h, body, None).unwrap_err();
        assert_eq!(err.reason, "bad_signature");
        assert_eq!(err.status, 401);
    }

    #[test]
    fn hmac_tampered_body_rejected() {
        let sig = hmac_hex("shhh", b"original");
        let h = hdrs(json!({ "x-signature": sig }));
        // Body changed after signing → mismatch.
        let err = verify(&hmac_cfg(), &h, b"tampered", None).unwrap_err();
        assert_eq!(err.reason, "bad_signature");
    }

    #[test]
    fn hmac_missing_header_rejected() {
        let err = verify(&hmac_cfg(), &hdrs(json!({})), b"x", None).unwrap_err();
        assert_eq!(err.reason, "missing_signature");
    }

    fn bearer_cfg() -> VerifyConfig {
        VerifyConfig {
            verify_type: "bearer".into(),
            header: None,
            secret: Some("tok-123".into()),
            audience: None,
            service_account: None,
            tolerance_secs: None,
        }
    }

    #[test]
    fn bearer_good_token_passes() {
        let h = hdrs(json!({ "authorization": "Bearer tok-123" }));
        assert!(verify(&bearer_cfg(), &h, b"", None).is_ok());
    }

    #[test]
    fn bearer_wrong_token_rejected() {
        let h = hdrs(json!({ "authorization": "Bearer nope" }));
        let err = verify(&bearer_cfg(), &h, b"", None).unwrap_err();
        assert_eq!(err.reason, "bad_token");
    }

    #[test]
    fn bearer_missing_header_rejected() {
        let err = verify(&bearer_cfg(), &hdrs(json!({})), b"", None).unwrap_err();
        assert_eq!(err.reason, "missing_token");
    }

    // ---- Pub/Sub OIDC (RS256 JWT) ----

    const TEST_KID: &str = "test-kid";
    const TEST_AUD: &str = "https://gw.noetl.acme/ingress/billing";
    const TEST_SA: &str = "pubsub-push@acme.iam.gserviceaccount.com";
    const TEST_JWK_N: &str = "lsAfI7sfCAqEkQDzd2lLPCHs51B71yET4fOb-AHicydrRTeJjlTGJ8PO6fuQtcT5CB4Qj208yES3wI7F46SftCSNCzkdRNZPuP1RNdUf-6Af3i6GEv-DMwP2iKTyyIkn2LUbY46W4lGRDgKYfs79yTPsW7xh5OB6bcmMGQ5Xzc4gUdcWLBJ3ONWNtyV0zW6pT5sBzFRBE4BfdzulTupnLtzncWWSU8BPNf4VVmolM0ZEniTwij2kPsoy2jOecTNjaW6zo7rw-ftHSxb6U838e0ggTNOGM-jkziGJf-h0VidBfM8GWVbIIRs5RJWqh4FN1Jf6UsMWFA1S2d_F7Hh7dw";
    const TEST_JWK_E: &str = "AQAB";

    /// Test-only RSA private key (matches `TEST_JWK_N`/`TEST_JWK_E`).  Not a
    /// real credential — generated for these unit tests.
    const TEST_PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCWwB8jux8ICoSR
APN3aUs8IeznUHvXIRPh85v4AeJzJ2tFN4mOVMYnw87p+5C1xPkIHhCPbTzIRLfA
jsXjpJ+0JI0LOR1E1k+4/VE11R/7oB/eLoYS/4MzA/aIpPLIiSfYtRtjjpbiUZEO
Aph+zv3JM+xbvGHk4HptyYwZDlfNziBR1xYsEnc41Y23JXTNbqlPmwHMVEETgF93
O6VO6mcu3OdxZZJTwE81/hVWaiUzRkSeJPCKPaQ+yjLaM55xM2NpbrOjuvD5+0dL
FvpTzfx7SCBM04Yz6OTOIYl/6HRWJ0F8zwZZVsghGzlElaqHgU3Ul/pSwxYUDVLZ
38XseHt3AgMBAAECggEAMgoPzBJ+2HJ1UpSYPFjtKkawlo+2q9BFA0mTyh0GB+db
yhwHQwGMzQJIGo7wmAWMDE++e31tIaT9waMiuM+aW3eOgd0xg/oHeIZNgKr/9MxQ
B7Y1tvStni+AlBb8p+gvG9XyA3f/SZx9o8Lkz6Lxxum/WSwM6qZAvVSbdm22Y4+3
2Q4sv7dQVkpTCv/7V0fPN3IkeEzXajCnvRkki8I+0r2gnrVri8yn9pr/2bzuPUXZ
md7bD/XDMUrpSC+UYmMalNfXM2gqDBgciZqB/RRjus8FOgbbYdYhJb11p0mE8jZQ
azVNu0/fM+mKeC+yJEvR9PZGOABgAiZOtMltpihMcQKBgQDLG+vcbsxkm5g0rlPQ
XcrfYt3/G+2Lhao0wrLcZGjasfn1bCsqy+yk889nBTWlFc+SzTJIDOlrbaM+keRk
vkCOCgEsBnkYaeBwDdHi8iZdpq0nG0mgQTb1S7qrSUuWh66AKxfxBIzhcGq4CeZM
sg9+fW0Pwrc9nwuHOgEIVR5FswKBgQC+AcNVoXQbui5W+KM/whiXcvKURuXafkdO
AxAw6RuttXwr8DXJ01/rFchFVqH3WHeUJAY0nNt+JC+DuIrDtsR01EFOJgId/aOZ
uEedTjuy5Hu3ojpCe6f96jYn5Tw/sgyNnc9cfxxjbtnOSfs+D3YFFljYLYqiIUk9
hn8uAOlZLQKBgQCzJLFn/6Hvqv0Ymhn60n85gK5lcHCYexCg8IlpsnZ5Tjk1qm54
lNzosNLh/spODWrEBJCw1BKdWlp9uZhE8zllDpXyCtOMIPaAXvAcx4/nUjevInZS
DrM2r9C5ezBcWNgk292GC4lm3gyCvtiOFQ9tdZtYJ1oP09QLNbHrc4f72QKBgESP
nkxn1d2rcM0xKrb28qizcZTPgGE278PWlyEO/E3SDtxL8RzCiPnrAjkC6a623W83
EIYrk4gQxpRhIrE8YedGL8pjLKBlxYLSXAUHFcOXboz0nNEgjZ2xxZjfvr29IYp4
Rzq5IyU9+pnVWDMsoQl05toalMur9yGcRofzDECBAoGAbMwPy9hLxOVsFmzNXyD4
XZUH4kS0pGGBLtI+qtYpN3/mll8NX4D1ODM9k9PZl49wQXR44g7x7kW9qDGRMrOq
lFO21bDlxABcQoPC4GwHh61UrN/dlS9nsZxVz0fH5D/gWj++BLI8EMYFObkkEGHV
5pGVC7vGYrVINGUl/oT3GOs=
-----END PRIVATE KEY-----";

    fn test_jwks() -> Jwks {
        Jwks {
            keys: vec![Jwk {
                kid: TEST_KID.to_string(),
                n: TEST_JWK_N.to_string(),
                e: TEST_JWK_E.to_string(),
                alg: Some("RS256".to_string()),
            }],
        }
    }

    fn now_unix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Mint a signed RS256 JWT with the test key.  `kid` lets us forge an
    /// unknown-key token.
    fn mint(aud: &str, email: &str, email_verified: bool, exp: u64, kid: &str) -> String {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        #[derive(serde::Serialize)]
        struct Claims<'a> {
            aud: &'a str,
            email: &'a str,
            email_verified: bool,
            iss: &'a str,
            exp: u64,
        }
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        let claims = Claims {
            aud,
            email,
            email_verified,
            iss: "https://accounts.google.com",
            exp,
        };
        let key = EncodingKey::from_rsa_pem(TEST_PRIV_PEM.as_bytes()).unwrap();
        encode(&header, &claims, &key).unwrap()
    }

    #[test]
    fn oidc_valid_token_passes() {
        let jwt = mint(TEST_AUD, TEST_SA, true, now_unix() + 3600, TEST_KID);
        assert!(validate_oidc_jwt(&jwt, &test_jwks(), TEST_AUD, TEST_SA).is_ok());
    }

    #[test]
    fn oidc_expired_token_rejected() {
        let jwt = mint(TEST_AUD, TEST_SA, true, now_unix() - 3600, TEST_KID);
        let err = validate_oidc_jwt(&jwt, &test_jwks(), TEST_AUD, TEST_SA).unwrap_err();
        assert_eq!(err.reason, "oidc_expired");
    }

    #[test]
    fn oidc_wrong_audience_rejected() {
        let jwt = mint(
            "https://evil.example/ingress",
            TEST_SA,
            true,
            now_unix() + 3600,
            TEST_KID,
        );
        let err = validate_oidc_jwt(&jwt, &test_jwks(), TEST_AUD, TEST_SA).unwrap_err();
        assert_eq!(err.reason, "oidc_wrong_audience");
    }

    #[test]
    fn oidc_wrong_service_account_rejected() {
        let jwt = mint(
            TEST_AUD,
            "attacker@evil.iam.gserviceaccount.com",
            true,
            now_unix() + 3600,
            TEST_KID,
        );
        let err = validate_oidc_jwt(&jwt, &test_jwks(), TEST_AUD, TEST_SA).unwrap_err();
        assert_eq!(err.reason, "oidc_wrong_sa");
    }

    #[test]
    fn oidc_unverified_email_rejected() {
        let jwt = mint(TEST_AUD, TEST_SA, false, now_unix() + 3600, TEST_KID);
        let err = validate_oidc_jwt(&jwt, &test_jwks(), TEST_AUD, TEST_SA).unwrap_err();
        assert_eq!(err.reason, "oidc_unverified_email");
    }

    #[test]
    fn oidc_unknown_kid_rejected() {
        let jwt = mint(TEST_AUD, TEST_SA, true, now_unix() + 3600, "some-other-kid");
        let err = validate_oidc_jwt(&jwt, &test_jwks(), TEST_AUD, TEST_SA).unwrap_err();
        assert_eq!(err.reason, "oidc_unknown_kid");
    }

    #[test]
    fn oidc_bad_signature_rejected() {
        // Mint a valid token, then corrupt the signature segment.
        //
        // Tamper in the MIDDLE, not at the end.  An RS256 signature is 256 bytes
        // → 342 base64url chars, and the final char encodes only the trailing 2
        // bits, so most substitutions there produce a string that fails to
        // *decode*.  The old version flipped the last char and so exercised the
        // decode path, asserting `oidc_bad_signature` while actually getting
        // `oidc_invalid` — a red test that looked like a signature-verification
        // regression and was only a bad tamper.  A middle char stays valid
        // base64url, so the signature decodes cleanly and genuinely fails
        // verification, which is the path this test exists to cover.
        let jwt = mint(TEST_AUD, TEST_SA, true, now_unix() + 3600, TEST_KID);
        let parts: Vec<&str> = jwt.split('.').collect();
        let sig = parts[2];
        let mid = sig.len() / 2;
        let orig = &sig[mid..mid + 1];
        let replacement = if orig == "A" { "B" } else { "A" };
        let flipped = format!("{}{}{}", &sig[..mid], replacement, &sig[mid + 1..]);
        assert_ne!(flipped, sig, "the tamper must actually change the signature");
        let tampered = format!("{}.{}.{}", parts[0], parts[1], flipped);

        let err = validate_oidc_jwt(&tampered, &test_jwks(), TEST_AUD, TEST_SA).unwrap_err();
        assert_eq!(
            err.reason, "oidc_bad_signature",
            "a decodable-but-wrong signature must fail signature verification"
        );
    }

    /// The end-flip case the old test accidentally exercised: an undecodable
    /// signature. It must still be **rejected** — just under a different reason.
    /// Pinned so nobody "fixes" the reason code back and reintroduces the
    /// confusion, and so a regression that started *accepting* it would fail.
    #[test]
    fn oidc_undecodable_signature_is_still_rejected() {
        let jwt = mint(TEST_AUD, TEST_SA, true, now_unix() + 3600, TEST_KID);
        let parts: Vec<&str> = jwt.split('.').collect();
        let tampered = format!("{}.{}.{}!!!", parts[0], parts[1], parts[2]);
        let err = validate_oidc_jwt(&tampered, &test_jwks(), TEST_AUD, TEST_SA).unwrap_err();
        assert_eq!(err.reason, "oidc_invalid");
    }

    // ---- LIVE Pub/Sub OIDC validation against the REAL Google JWKS ----
    //
    // noetl/ai-meta#91 — the positive signature path against a genuinely
    // Google-signed token, deferred in Phase 3 for lack of a real one.  Every
    // test above runs against a self-minted RSA key + an in-memory JWKS (no
    // network).  This test fetches Google's LIVE signing keys through the same
    // `fetch_google_jwks` the gateway uses in production and validates a real
    // OIDC identity token, proving the RS256 path works against Google's actual
    // public keys — not just a key we control.
    //
    // `#[ignore]` because it needs network + a fresh real token; ordinary
    // `cargo test` and CI skip it.  The token is supplied by env and is NEVER
    // committed.  Mint a true Pub/Sub-push-shaped token (email = the push SA,
    // a custom audience) by impersonating the push service account:
    //
    //   SA=noetl-subscription-runtime@<project>.iam.gserviceaccount.com
    //   AUD=https://gw.noetl.example/ingress/billing
    //   export NOETL_LIVE_OIDC_TOKEN="$(gcloud auth print-identity-token \
    //     --impersonate-service-account=$SA --audiences=$AUD --include-email)"
    //   export NOETL_LIVE_OIDC_AUD=$AUD
    //   export NOETL_LIVE_OIDC_SA=$SA
    //   cargo test --bin noetl-gateway -- --ignored --nocapture oidc_live
    //
    // Driven by noetl/e2e scripts/live_validate_oidc_verify.sh.
    #[tokio::test]
    #[ignore = "needs network + a real Google OIDC token in NOETL_LIVE_OIDC_TOKEN"]
    async fn oidc_live_google_token_against_real_jwks() {
        let token = std::env::var("NOETL_LIVE_OIDC_TOKEN")
            .expect("set NOETL_LIVE_OIDC_TOKEN to a real Google-signed OIDC token");
        let aud = std::env::var("NOETL_LIVE_OIDC_AUD").expect("set NOETL_LIVE_OIDC_AUD to the token's audience");
        let sa =
            std::env::var("NOETL_LIVE_OIDC_SA").expect("set NOETL_LIVE_OIDC_SA to the token's service-account email");

        // Fetch Google's LIVE signing keys via the gateway's own code path.
        let http = reqwest::Client::new();
        let jwks = crate::ingress::config::fetch_google_jwks(&http)
            .await
            .expect("fetch live Google JWKS");
        assert!(!jwks.keys.is_empty(), "live Google JWKS came back empty");

        // 1. POSITIVE — real token, real keys, correct aud + SA → verified.
        validate_oidc_jwt(&token, &jwks, &aud, &sa)
            .expect("real Google-signed token must verify against the live JWKS");

        // 2. NEGATIVE — wrong audience → rejected (real signature, live JWKS).
        let err = validate_oidc_jwt(&token, &jwks, "https://wrong.example/ingress/x", &sa)
            .expect_err("wrong audience must be rejected");
        assert_eq!(err.reason, "oidc_wrong_audience");

        // 3. NEGATIVE — wrong service-account email → rejected.
        let err = validate_oidc_jwt(&token, &jwks, &aud, "attacker@evil.iam.gserviceaccount.com")
            .expect_err("wrong service account must be rejected");
        assert_eq!(err.reason, "oidc_wrong_sa");

        // 4. NEGATIVE — tampered signature → rejected by the REAL Google key.
        // Flip a character in the MIDDLE of the signature segment (a full
        // base64url byte) so the corruption is a valid-base64 wrong signature,
        // not a malformed final-char bit pattern — that reliably surfaces as an
        // RSA signature mismatch rather than a base64 decode error.
        let mut parts: Vec<&str> = token.split('.').collect();
        let sig = parts[2].to_string();
        let mid = sig.len() / 2;
        let ch = &sig[mid..mid + 1];
        let repl = if ch == "A" { "B" } else { "A" };
        let flipped = format!("{}{}{}", &sig[..mid], repl, &sig[mid + 1..]);
        parts[2] = &flipped;
        let tampered = parts.join(".");
        let err = validate_oidc_jwt(&tampered, &jwks, &aud, &sa)
            .expect_err("tampered signature must be rejected by the live Google key");
        assert_eq!(err.reason, "oidc_bad_signature");
    }

    // ---- stripe_signature ----

    const WHSEC: &str = "whsec_test_secret";
    const NOW: i64 = 1_764_000_000;

    fn stripe_cfg() -> VerifyConfig {
        VerifyConfig {
            verify_type: "stripe_signature".into(),
            header: None,
            secret: Some(WHSEC.into()),
            audience: None,
            service_account: None,
            tolerance_secs: None,
        }
    }

    fn stripe_sig(secret: &str, t: i64, body: &[u8]) -> String {
        let mut signed = format!("{t}.").into_bytes();
        signed.extend_from_slice(body);
        hmac_hex(secret, &signed)
    }

    fn stripe_hdr(value: String) -> serde_json::Map<String, serde_json::Value> {
        hdrs(json!({ "stripe-signature": value }))
    }

    #[test]
    fn stripe_valid_signature_passes() {
        let body = br#"{"id":"evt_1","livemode":false}"#;
        let h = stripe_hdr(format!("t={NOW},v1={}", stripe_sig(WHSEC, NOW, body)));
        assert!(verify_stripe(&stripe_cfg(), &h, body, NOW).is_ok());
    }

    #[test]
    fn stripe_dispatch_through_verify_uses_scheme() {
        // Through the public entry point with the real clock.
        let body = b"{}";
        let now = unix_now();
        let h = stripe_hdr(format!("t={now},v1={}", stripe_sig(WHSEC, now, body)));
        assert!(verify(&stripe_cfg(), &h, body, None).is_ok());
    }

    #[test]
    fn stripe_multiple_v1_one_matching_passes() {
        let body = b"{\"id\":\"evt_2\"}";
        let good = stripe_sig(WHSEC, NOW, body);
        let old = stripe_sig("whsec_rotated_out", NOW, body);
        let h = stripe_hdr(format!("t={NOW},v1={old},v1={good},v0=deadbeef"));
        assert!(verify_stripe(&stripe_cfg(), &h, body, NOW).is_ok());
    }

    #[test]
    fn stripe_tampered_body_rejected() {
        let h = stripe_hdr(format!("t={NOW},v1={}", stripe_sig(WHSEC, NOW, b"original")));
        let err = verify_stripe(&stripe_cfg(), &h, b"tampered", NOW).unwrap_err();
        assert_eq!((err.status, err.reason), (401, "bad_signature"));
    }

    #[test]
    fn stripe_wrong_secret_rejected() {
        let body = b"{}";
        let h = stripe_hdr(format!("t={NOW},v1={}", stripe_sig("whsec_other", NOW, body)));
        let err = verify_stripe(&stripe_cfg(), &h, body, NOW).unwrap_err();
        assert_eq!(err.reason, "bad_signature");
    }

    #[test]
    fn stripe_signature_over_body_alone_rejected() {
        // A plain hmac_sha256 of the body (no "{t}." prefix) must not pass.
        let body = b"{}";
        let h = stripe_hdr(format!("t={NOW},v1={}", hmac_hex(WHSEC, body)));
        assert_eq!(
            verify_stripe(&stripe_cfg(), &h, body, NOW).unwrap_err().reason,
            "bad_signature"
        );
    }

    #[test]
    fn stripe_stale_timestamp_rejected() {
        let body = b"{}";
        let t = NOW - 301;
        let h = stripe_hdr(format!("t={t},v1={}", stripe_sig(WHSEC, t, body)));
        let err = verify_stripe(&stripe_cfg(), &h, body, NOW).unwrap_err();
        assert_eq!((err.status, err.reason), (401, "stale_timestamp"));
        // Exactly at the edge is still inside the window.
        let t = NOW - 300;
        let h = stripe_hdr(format!("t={t},v1={}", stripe_sig(WHSEC, t, body)));
        assert!(verify_stripe(&stripe_cfg(), &h, body, NOW).is_ok());
    }

    #[test]
    fn stripe_future_timestamp_beyond_tolerance_rejected() {
        let body = b"{}";
        let t = NOW + 301;
        let h = stripe_hdr(format!("t={t},v1={}", stripe_sig(WHSEC, t, body)));
        assert_eq!(
            verify_stripe(&stripe_cfg(), &h, body, NOW).unwrap_err().reason,
            "stale_timestamp"
        );
    }

    #[test]
    fn stripe_custom_tolerance_honoured() {
        let body = b"{}";
        let t = NOW - 60;
        let h = stripe_hdr(format!("t={t},v1={}", stripe_sig(WHSEC, t, body)));
        let mut cfg = stripe_cfg();
        cfg.tolerance_secs = Some(30);
        assert_eq!(
            verify_stripe(&cfg, &h, body, NOW).unwrap_err().reason,
            "stale_timestamp"
        );
        cfg.tolerance_secs = Some(120);
        assert!(verify_stripe(&cfg, &h, body, NOW).is_ok());
    }

    #[test]
    fn stripe_malformed_header_rejected() {
        let body = b"{}";
        let sig = stripe_sig(WHSEC, NOW, body);
        for bad in [
            format!("v1={sig}"),              // no timestamp
            format!("t=notanumber,v1={sig}"), // non-integer timestamp
            format!("t={NOW}"),               // no v1
            format!("t={NOW},v0={sig}"),      // only legacy v0
            "garbage".to_string(),
        ] {
            let err = verify_stripe(&stripe_cfg(), &stripe_hdr(bad.clone()), body, NOW).unwrap_err();
            assert_eq!((err.status, err.reason), (401, "malformed_signature"), "header {bad:?}");
        }
    }

    #[test]
    fn stripe_missing_header_rejected() {
        let err = verify_stripe(&stripe_cfg(), &hdrs(json!({})), b"{}", NOW).unwrap_err();
        assert_eq!((err.status, err.reason), (401, "missing_signature"));
    }

    #[test]
    fn stripe_missing_secret_is_misconfigured() {
        let mut cfg = stripe_cfg();
        cfg.secret = None;
        let body = b"{}";
        let h = stripe_hdr(format!("t={NOW},v1={}", stripe_sig(WHSEC, NOW, body)));
        let err = verify_stripe(&cfg, &h, body, NOW).unwrap_err();
        assert_eq!((err.status, err.reason), (403, "misconfigured"));
    }

    #[test]
    fn signature_header_defaults_per_scheme() {
        assert_eq!(signature_header(&stripe_cfg()).as_deref(), Some("stripe-signature"));
        let mut c = hmac_cfg();
        c.header = None;
        assert_eq!(signature_header(&c).as_deref(), Some("x-signature"));
        c.header = Some("X-Sig".into());
        assert_eq!(signature_header(&c).as_deref(), Some("x-sig"));
    }
}
