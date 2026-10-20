//! Guest sessions: signed-out visitors running allowlisted public playbooks.
//!
//! Off unless `GATEWAY_GUEST_PLAYBOOKS` is set. Then `POST /api/auth/guest`
//! mints a short-lived, self-verifying guest token and the gateway accepts it
//! like a session token on `/graphql`, `/noetl/{*path}` and `/events`:
//!
//! * The token is `ng1.<payload>.<mac>`: base64url JSON `{gid, exp}` and an
//!   HMAC-SHA256 over `ng1.<payload>` with `GATEWAY_GUEST_TOKEN_KEY`. Nothing
//!   is stored; revoking every guest is a key rotation.
//! * A guest is a `UserContext` with `user_id = 0`, no `auth0_sub`, no roles
//!   and `guest = Some(..)`. `crate::authorization::Policy` lets it start only
//!   `GATEWAY_GUEST_PLAYBOOKS` and read or cancel only executions it started;
//!   `crate::identity` keeps refusing a non-null `uid` (no subject).
//! * Abuse bounds, all per rolling hour and per gateway pod: executions per
//!   guest, per client IP and in total, and guest mints per client IP.
//!
//! Spec: noetl/ai-meta `specs/active/2026-10-19-gateway-guest-sessions`.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{ConnectInfo, State},
    http::{header::RETRY_AFTER, HeaderMap, HeaderName, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Prefix of every guest token; tells the auth middleware to verify locally.
pub const TOKEN_PREFIX: &str = "ng1.";
const MIN_KEY_BYTES: usize = 32;
const WINDOW_SECS: u64 = 3600;
/// Prune idle limiter keys once the map grows past this.
const SWEEP_AT: usize = 4096;

type HmacSha256 = Hmac<Sha256>;

/// Who a guest session is, carried on `UserContext::guest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Guest {
    /// Random per guest session (UUID v4); owns the guest's executions.
    pub id: String,
    /// Client IP the request came from (rate limits only; never logged at INFO).
    pub ip: String,
}

#[derive(Debug, Clone)]
pub struct GuestConfig {
    pub playbooks: Vec<String>,
    key: Vec<u8>,
    pub ttl_secs: u64,
    pub runs_per_guest: usize,
    pub runs_per_ip: usize,
    pub mints_per_ip: usize,
    pub total_runs: usize,
    pub ip_header: Option<HeaderName>,
}

impl GuestConfig {
    /// `Ok(None)` when guest mode is off (`GATEWAY_GUEST_PLAYBOOKS` unset or
    /// blank). With playbooks set, a missing or short key is an error: the
    /// gateway must not start half-configured.
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> anyhow::Result<Option<Self>> {
        let playbooks = crate::authorization::csv(&get("GATEWAY_GUEST_PLAYBOOKS").unwrap_or_default());
        if playbooks.is_empty() {
            return Ok(None);
        }
        let key = get("GATEWAY_GUEST_TOKEN_KEY").unwrap_or_default().into_bytes();
        if key.len() < MIN_KEY_BYTES {
            anyhow::bail!("GATEWAY_GUEST_PLAYBOOKS is set but GATEWAY_GUEST_TOKEN_KEY is missing or shorter than {MIN_KEY_BYTES} bytes");
        }
        let num = |name: &str, default: u64| -> anyhow::Result<u64> {
            match get(name).map(|v| v.trim().to_string()).filter(|v| !v.is_empty()) {
                None => Ok(default),
                Some(v) => v.parse::<u64>().map_err(|e| anyhow::anyhow!("{name}={v:?}: {e}")),
            }
        };
        let ip_header = match get("GATEWAY_CLIENT_IP_HEADER")
            .map(|v| v.trim().to_ascii_lowercase())
            .filter(|v| !v.is_empty())
        {
            None => None,
            Some(h) => Some(
                HeaderName::try_from(h.as_str()).map_err(|e| anyhow::anyhow!("GATEWAY_CLIENT_IP_HEADER={h:?}: {e}"))?,
            ),
        };
        Ok(Some(Self {
            playbooks,
            key,
            ttl_secs: num("GATEWAY_GUEST_TTL_SECS", 3600)?.max(60),
            runs_per_guest: num("GATEWAY_GUEST_RUNS_PER_HOUR", 20)? as usize,
            runs_per_ip: num("GATEWAY_GUEST_IP_RUNS_PER_HOUR", 60)? as usize,
            mints_per_ip: num("GATEWAY_GUEST_IP_SESSIONS_PER_HOUR", 20)? as usize,
            total_runs: num("GATEWAY_GUEST_TOTAL_RUNS_PER_HOUR", 600)? as usize,
            ip_header,
        }))
    }
}

#[derive(Serialize, Deserialize)]
struct Payload {
    gid: String,
    exp: u64,
}

/// Sliding-window counters: timestamps (unix secs) per key, last hour only.
#[derive(Default)]
struct Limiter {
    hits: HashMap<String, VecDeque<u64>>,
}

impl Limiter {
    fn prune(q: &mut VecDeque<u64>, now: u64) {
        while q.front().is_some_and(|&t| t + WINDOW_SECS <= now) {
            q.pop_front();
        }
    }

    /// Admit one event against every `(key, limit)` or none of them. On
    /// refusal, the seconds until the tightest window frees a slot.
    fn admit(&mut self, keys: &[(String, usize)], now: u64) -> Result<(), u64> {
        if self.hits.len() > SWEEP_AT {
            self.hits.retain(|_, q| {
                Self::prune(q, now);
                !q.is_empty()
            });
        }
        let mut wait = 0;
        for (key, limit) in keys {
            let q = self.hits.entry(key.clone()).or_default();
            Self::prune(q, now);
            if q.len() >= *limit {
                // limit 0 refuses everything; wait a full window.
                let oldest = q.front().copied().unwrap_or(now);
                wait = wait.max((oldest + WINDOW_SECS).saturating_sub(now).max(1));
            }
        }
        if wait > 0 {
            return Err(wait);
        }
        for (key, _) in keys {
            self.hits.entry(key.clone()).or_default().push_back(now);
        }
        Ok(())
    }
}

pub struct GuestSessions {
    pub config: GuestConfig,
    limiter: Mutex<Limiter>,
}

/// A refused guest request: retry after this many seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimited(pub u64);

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl GuestSessions {
    pub fn new(config: GuestConfig) -> Self {
        Self {
            config,
            limiter: Mutex::new(Limiter::default()),
        }
    }

    pub fn from_env() -> anyhow::Result<Option<Arc<Self>>> {
        Ok(GuestConfig::from_env()?.map(|c| Arc::new(Self::new(c))))
    }

    fn mac(&self, signed: &str) -> HmacSha256 {
        let mut mac = HmacSha256::new_from_slice(&self.config.key).expect("HMAC accepts any key length");
        mac.update(signed.as_bytes());
        mac
    }

    /// A new guest token, its guest id and expiry (unix secs).
    pub fn mint_at(&self, now: u64) -> (String, String, u64) {
        let gid = uuid::Uuid::new_v4().to_string();
        let exp = now + self.config.ttl_secs;
        let payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&Payload { gid: gid.clone(), exp }).unwrap_or_default());
        let signed = format!("{TOKEN_PREFIX}{payload}");
        let tag = URL_SAFE_NO_PAD.encode(self.mac(&signed).finalize().into_bytes());
        (format!("{signed}.{tag}"), gid, exp)
    }

    /// The guest id of a valid, unexpired token signed with this key.
    pub fn verify_at(&self, token: &str, now: u64) -> Option<String> {
        let rest = token.strip_prefix(TOKEN_PREFIX)?;
        let (payload, tag) = rest.split_once('.')?;
        let tag = URL_SAFE_NO_PAD.decode(tag).ok()?;
        self.mac(&format!("{TOKEN_PREFIX}{payload}")).verify_slice(&tag).ok()?;
        let p: Payload = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
        (p.exp > now && uuid::Uuid::parse_str(&p.gid).is_ok()).then_some(p.gid)
    }

    pub fn verify(&self, token: &str) -> Option<String> {
        self.verify_at(token, now_secs())
    }

    /// The client IP: the configured trusted header (first entry of a list),
    /// else the socket peer, else "unknown".
    pub fn client_ip(&self, headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
        if let Some(h) = &self.config.ip_header {
            if let Some(ip) = headers
                .get(h)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
                .map(str::trim)
                .filter(|v| !v.is_empty())
            {
                return ip.to_string();
            }
        }
        peer.map(|p| p.ip().to_string()).unwrap_or_else(|| "unknown".into())
    }

    fn limit(&self, keys: &[(String, usize)], now: u64) -> Result<(), RateLimited> {
        let mut limiter = self.limiter.lock().unwrap_or_else(|e| e.into_inner());
        limiter.admit(keys, now).map_err(RateLimited)
    }

    pub fn admit_mint_at(&self, ip: &str, now: u64) -> Result<(), RateLimited> {
        self.limit(&[(format!("mint:{ip}"), self.config.mints_per_ip)], now)
    }

    /// One guest execution: per guest, per client IP and the global ceiling.
    pub fn admit_run_at(&self, guest: &Guest, now: u64) -> Result<(), RateLimited> {
        self.limit(
            &[
                (format!("run:g:{}", guest.id), self.config.runs_per_guest),
                (format!("run:ip:{}", guest.ip), self.config.runs_per_ip),
                ("run:all".to_string(), self.config.total_runs),
            ],
            now,
        )
    }

    pub fn admit_run(&self, guest: &Guest) -> Result<(), RateLimited> {
        self.admit_run_at(guest, now_secs())
    }
}

#[derive(Serialize)]
struct MintResponse {
    status: &'static str,
    session_token: String,
    guest_id: String,
    /// Unix seconds.
    expires_at: u64,
}

/// `POST /api/auth/guest`: a new guest session. Public; rate-limited per client IP.
pub async fn mint(State(guests): State<Arc<GuestSessions>>, request: axum::extract::Request) -> Response {
    let peer = request.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0);
    let ip = guests.client_ip(request.headers(), peer);
    let now = now_secs();
    if let Err(RateLimited(wait)) = guests.admit_mint_at(&ip, now) {
        crate::ingress::record_session_check("guest_mint_limited");
        tracing::debug!(retry_after = wait, "guest session refused: rate limit");
        return too_many(wait, "Too many guest sessions from this address");
    }
    let (session_token, guest_id, expires_at) = guests.mint_at(now);
    crate::ingress::record_session_check("guest_minted");
    tracing::debug!(guest = &guest_id[..8], "guest session minted");
    Json(MintResponse {
        status: "guest",
        session_token,
        guest_id,
        expires_at,
    })
    .into_response()
}

pub fn too_many(wait: u64, message: &'static str) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(RETRY_AFTER, wait.to_string())],
        message,
    )
        .into_response()
}

#[cfg(test)]
pub fn test_sessions(playbooks: &[&str]) -> GuestSessions {
    GuestSessions::new(test_config(playbooks))
}

#[cfg(test)]
pub fn test_config(playbooks: &[&str]) -> GuestConfig {
    let env: HashMap<&str, String> = HashMap::from([
        ("GATEWAY_GUEST_PLAYBOOKS", playbooks.join(",")),
        ("GATEWAY_GUEST_TOKEN_KEY", "k".repeat(32)),
    ]);
    GuestConfig::from_lookup(|k| env.get(k).cloned()).unwrap().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(pairs: &[(&str, &str)]) -> anyhow::Result<Option<GuestConfig>> {
        let env: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        GuestConfig::from_lookup(|k| env.get(k).cloned())
    }

    #[test]
    fn guest_mode_is_off_without_playbooks() {
        assert!(cfg(&[]).unwrap().is_none());
        assert!(cfg(&[
            ("GATEWAY_GUEST_PLAYBOOKS", " , "),
            ("GATEWAY_GUEST_TOKEN_KEY", &"k".repeat(32))
        ])
        .unwrap()
        .is_none());
    }

    #[test]
    fn playbooks_without_a_strong_key_refuse_to_start() {
        assert!(cfg(&[("GATEWAY_GUEST_PLAYBOOKS", "a/b")]).is_err());
        assert!(cfg(&[("GATEWAY_GUEST_PLAYBOOKS", "a/b"), ("GATEWAY_GUEST_TOKEN_KEY", "short")]).is_err());
        assert!(cfg(&[
            ("GATEWAY_GUEST_PLAYBOOKS", "a/b"),
            ("GATEWAY_GUEST_TOKEN_KEY", &"k".repeat(32)),
            ("GATEWAY_GUEST_RUNS_PER_HOUR", "x")
        ])
        .is_err());
    }

    #[test]
    fn defaults_match_the_spec() {
        let c = test_config(&["a/b"]);
        assert_eq!(c.playbooks, vec!["a/b"]);
        assert_eq!(
            (
                c.ttl_secs,
                c.runs_per_guest,
                c.runs_per_ip,
                c.mints_per_ip,
                c.total_runs
            ),
            (3600, 20, 60, 20, 600)
        );
        assert!(c.ip_header.is_none());
    }

    #[test]
    fn a_minted_token_verifies_until_it_expires() {
        let g = test_sessions(&["a/b"]);
        let (token, gid, exp) = g.mint_at(1_000);
        assert!(token.starts_with(TOKEN_PREFIX));
        assert_eq!(exp, 1_000 + 3600);
        assert_eq!(g.verify_at(&token, 1_001).as_deref(), Some(gid.as_str()));
        assert_eq!(g.verify_at(&token, exp), None);
    }

    #[test]
    fn a_tampered_or_foreign_token_is_rejected() {
        let g = test_sessions(&["a/b"]);
        let (token, _, _) = g.mint_at(1_000);
        let (signed, tag) = token.rsplit_once('.').unwrap();
        // Another payload under the same tag.
        let forged_payload =
            URL_SAFE_NO_PAD.encode(br#"{"gid":"00000000-0000-4000-8000-000000000000","exp":99999999999}"#);
        assert_eq!(
            g.verify_at(&format!("{TOKEN_PREFIX}{forged_payload}.{tag}"), 1_001),
            None
        );
        // A flipped tag.
        let mut bad = tag.to_string();
        bad.replace_range(0..1, if bad.starts_with('A') { "B" } else { "A" });
        assert_eq!(g.verify_at(&format!("{signed}.{bad}"), 1_001), None);
        // Signed with another key.
        let mut other = test_config(&["a/b"]);
        other.key = b"x".repeat(32);
        let (theirs, _, _) = GuestSessions::new(other).mint_at(1_000);
        assert_eq!(g.verify_at(&theirs, 1_001), None);
        // Not a guest token at all.
        for junk in ["", "ng1.", "ng1.a", "ng1..", "session-token", "ng2.x.y"] {
            assert_eq!(g.verify_at(junk, 1_001), None, "{junk:?}");
        }
    }

    #[test]
    fn the_client_ip_comes_from_the_trusted_header_only_when_configured() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", "203.0.113.7".parse().unwrap());
        headers.insert("x-forwarded-for", "198.51.100.1, 10.0.0.1".parse().unwrap());
        let peer: SocketAddr = "10.1.2.3:5555".parse().unwrap();
        let mut c = test_config(&["a/b"]);
        assert_eq!(
            GuestSessions::new(c.clone()).client_ip(&headers, Some(peer)),
            "10.1.2.3"
        );
        c.ip_header = Some(HeaderName::from_static("cf-connecting-ip"));
        assert_eq!(
            GuestSessions::new(c.clone()).client_ip(&headers, Some(peer)),
            "203.0.113.7"
        );
        c.ip_header = Some(HeaderName::from_static("x-forwarded-for"));
        assert_eq!(
            GuestSessions::new(c.clone()).client_ip(&headers, Some(peer)),
            "198.51.100.1"
        );
        assert_eq!(GuestSessions::new(c).client_ip(&HeaderMap::new(), None), "unknown");
    }

    #[test]
    fn runs_are_limited_per_guest_per_ip_and_in_total() {
        let mut c = test_config(&["a/b"]);
        (c.runs_per_guest, c.runs_per_ip, c.total_runs) = (2, 3, 4);
        let g = GuestSessions::new(c);
        let a = Guest {
            id: "a".into(),
            ip: "1.1.1.1".into(),
        };
        let b = Guest {
            id: "b".into(),
            ip: "1.1.1.1".into(),
        };
        let c2 = Guest {
            id: "c".into(),
            ip: "2.2.2.2".into(),
        };
        assert!(g.admit_run_at(&a, 100).is_ok());
        assert!(g.admit_run_at(&a, 110).is_ok());
        // Per guest: the third run waits until the first leaves the window.
        assert_eq!(g.admit_run_at(&a, 120), Err(RateLimited(3600 - 20)));
        // Per IP: b shares a's address (2 used of 3).
        assert!(g.admit_run_at(&b, 130).is_ok());
        assert!(g.admit_run_at(&b, 131).is_err());
        // Total: 3 used of 4.
        assert!(g.admit_run_at(&c2, 140).is_ok());
        assert!(g
            .admit_run_at(
                &Guest {
                    id: "d".into(),
                    ip: "3.3.3.3".into()
                },
                150
            )
            .is_err());
        // A refused run consumed nothing: an hour after the first run, a may run again.
        assert!(g.admit_run_at(&a, 100 + 3600).is_ok());
    }

    #[test]
    fn mints_are_limited_per_ip() {
        let mut c = test_config(&["a/b"]);
        c.mints_per_ip = 2;
        let g = GuestSessions::new(c);
        assert!(g.admit_mint_at("1.1.1.1", 0).is_ok());
        assert!(g.admit_mint_at("1.1.1.1", 1).is_ok());
        assert!(g.admit_mint_at("1.1.1.1", 2).is_err());
        assert!(g.admit_mint_at("2.2.2.2", 2).is_ok());
        assert!(g.admit_mint_at("1.1.1.1", 3600).is_ok());
    }

    #[test]
    fn a_zero_limit_refuses_everything() {
        let mut c = test_config(&["a/b"]);
        c.total_runs = 0;
        let g = GuestSessions::new(c);
        assert_eq!(
            g.admit_run_at(
                &Guest {
                    id: "a".into(),
                    ip: "x".into()
                },
                5
            ),
            Err(RateLimited(3600))
        );
    }
}
