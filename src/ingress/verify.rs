//! Push / webhook authenticity verification — the gatekeeper's core job.
//!
//! Phase 3 of the subscription/listener RFC
//! ([noetl/ai-meta#90](https://github.com/noetl/ai-meta/issues/90), RFC §6).
//!
//! The gateway is the only component that terminates untrusted inbound push
//! traffic, so verification lives here.  Three schemes (RFC §6 table):
//!
//! | `verify.type` | Check |
//! |---|---|
//! | `hmac_sha256` | Recompute `HMAC-SHA256(secret, raw_body)`, constant-time compare against the signature header (optional `sha256=` prefix). |
//! | `bearer`      | Constant-time compare the bearer token against the expected token. |
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
        Self { status: 401, reason, detail: detail.into() }
    }
    fn forbidden(reason: &'static str, detail: impl Into<String>) -> Self {
        Self { status: 403, reason, detail: detail.into() }
    }
}

/// Look up a single header value (case-insensitive) from the normalized map.
fn header_str<'a>(
    headers: &'a serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Option<&'a str> {
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
        "pubsub_oidc" => {
            let jwks = jwks.ok_or_else(|| {
                VerifyRejection::unauthorized("oidc_no_jwks", "no JWKS available for OIDC verify")
            })?;
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
    let secret = cfg.secret.as_deref().ok_or_else(|| {
        VerifyRejection::forbidden("misconfigured", "hmac_sha256 verify has no resolved secret")
    })?;

    let provided = header_str(headers, header_name).ok_or_else(|| {
        VerifyRejection::unauthorized(
            "missing_signature",
            format!("missing signature header '{header_name}'"),
        )
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

/// Constant-time bearer-token compare.
fn verify_bearer(
    cfg: &VerifyConfig,
    headers: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), VerifyRejection> {
    let header_name = cfg.header.as_deref().unwrap_or("authorization");
    let secret = cfg.secret.as_deref().ok_or_else(|| {
        VerifyRejection::forbidden("misconfigured", "bearer verify has no resolved token")
    })?;

    let raw = header_str(headers, header_name).ok_or_else(|| {
        VerifyRejection::unauthorized("missing_token", format!("missing '{header_name}' header"))
    })?;
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
    let raw = header_str(headers, "authorization").ok_or_else(|| {
        VerifyRejection::unauthorized("missing_token", "missing Authorization header for OIDC")
    })?;
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
        .unwrap_or(raw)
        .trim();

    let audience = cfg.audience.as_deref().ok_or_else(|| {
        VerifyRejection::forbidden("misconfigured", "pubsub_oidc verify has no audience")
    })?;
    let expected_sa = cfg.service_account.as_deref().ok_or_else(|| {
        VerifyRejection::forbidden("misconfigured", "pubsub_oidc verify has no service_account")
    })?;

    validate_oidc_jwt(token, jwks, audience, expected_sa)
}

/// Pure JWT validation — separated from header extraction + JWKS fetch so it is
/// unit-testable with a self-minted RSA key + JWKS (no network, no clock dep
/// beyond `jsonwebtoken`'s own `exp` check).
pub fn validate_oidc_jwt(
    token: &str,
    jwks: &Jwks,
    audience: &str,
    expected_sa: &str,
) -> Result<(), VerifyRejection> {
    use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

    let header = decode_header(token)
        .map_err(|e| VerifyRejection::unauthorized("oidc_malformed", format!("jwt header: {e}")))?;
    let kid = header.kid.ok_or_else(|| {
        VerifyRejection::unauthorized("oidc_malformed", "jwt has no 'kid'")
    })?;
    let jwk = jwks.find(&kid).ok_or_else(|| {
        VerifyRejection::unauthorized("oidc_unknown_kid", format!("no JWKS key for kid '{kid}'"))
    })?;

    let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
        .map_err(|e| VerifyRejection::forbidden("oidc_bad_key", format!("jwk rsa: {e}")))?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[audience]);
    validation.validate_exp = true;
    validation.leeway = 60;

    let data = decode::<OidcClaims>(token, &key, &validation).map_err(|e| {
        use jsonwebtoken::errors::ErrorKind;
        match e.kind() {
            ErrorKind::ExpiredSignature => {
                VerifyRejection::unauthorized("oidc_expired", "OIDC token expired")
            }
            ErrorKind::InvalidAudience => {
                VerifyRejection::forbidden("oidc_wrong_audience", "OIDC audience mismatch")
            }
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
        let jwt = mint("https://evil.example/ingress", TEST_SA, true, now_unix() + 3600, TEST_KID);
        let err = validate_oidc_jwt(&jwt, &test_jwks(), TEST_AUD, TEST_SA).unwrap_err();
        assert_eq!(err.reason, "oidc_wrong_audience");
    }

    #[test]
    fn oidc_wrong_service_account_rejected() {
        let jwt = mint(TEST_AUD, "attacker@evil.iam.gserviceaccount.com", true, now_unix() + 3600, TEST_KID);
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
        let jwt = mint(TEST_AUD, TEST_SA, true, now_unix() + 3600, TEST_KID);
        let mut parts: Vec<&str> = jwt.split('.').collect();
        // Flip the last character of the signature.
        let sig = parts[2].to_string();
        let flipped = if sig.ends_with('A') {
            format!("{}B", &sig[..sig.len() - 1])
        } else {
            format!("{}A", &sig[..sig.len() - 1])
        };
        parts[2] = &flipped;
        let tampered = parts.join(".");
        let err = validate_oidc_jwt(&tampered, &test_jwks(), TEST_AUD, TEST_SA).unwrap_err();
        assert_eq!(err.reason, "oidc_bad_signature");
    }
}
