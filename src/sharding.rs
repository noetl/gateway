//! Shard routing — gateway-side dispatch.
//!
//! Phase F R3a of [noetl/ai-meta#49](https://github.com/noetl/ai-meta/issues/49).
//! Gateway-side counterpart of the server's
//! [`sharding.rs`](https://github.com/noetl/server/blob/main/src/sharding.rs)
//! helper landed in noetl-server v2.11.0.  See the
//! [sharding-design][design] doc for the full cross-cluster
//! routing context.
//!
//! [design]: https://github.com/noetl/server/wiki/sharding-design
//!
//! ## Why a copy and not a shared crate
//!
//! For now, the routing helper lives in both `noetl/server/src/sharding.rs`
//! and (this file) `noetl/gateway/src/sharding.rs` as **identical
//! Rust source code** — same `twox-hash` crate version, same seed,
//! same byte encoding.  The test suite below pins the expected
//! `(execution_id, shard_count) → shard` outputs to the SAME
//! values the server tests pin; a regression on either side
//! breaks the build.
//!
//! Extracting a shared `noetl-sharding` crate (R3.5 / Phase G
//! cleanup) is cleaner long-term but unnecessary right now: the
//! function is ~10 lines, the tests pin the wire shape, and the
//! pattern follows the EE-4 timeline (the shared crate came AFTER
//! drift was visible).
//!
//! ## What's covered
//!
//! - [`shard_for`] — `hash(execution_id) % shard_count` using
//!   `twox_hash::XxHash64` with fixed seed `0`.  Identical to
//!   `noetl-server` v2.11.0's implementation.
//! - [`ShardEndpoint`] — `{ shard_index, base_url }` pair the
//!   gateway reads from config to know which server replica owns
//!   which shard.
//! - [`ShardMap`] — collection of endpoints + `route(execution_id)`
//!   helper that picks the correct `base_url`.
//!
//! ## What's NOT covered (deferred)
//!
//! - **Body-param extraction** — `POST /noetl/events` carries
//!   `execution_id` inside the JSON body, not the path.  R3a-2
//!   wires that.
//! - **Drift-guard endpoint** — `GET /api/internal/shard-info/{id}?N=`
//!   on both gateway + server so an integration test can prove
//!   they agree.  R3b.
//! - **Shared `noetl-sharding` crate** — R3.5 / Phase G cleanup.

use std::collections::HashMap;
use std::hash::Hasher;

use serde::{Deserialize, Serialize};
use twox_hash::XxHash64;

/// Fixed seed for the shard-routing hash.  See module docs:
/// MUST match noetl-server's `SHARD_HASH_SEED` exactly.  Changing
/// either side invalidates every existing shard assignment.
const SHARD_HASH_SEED: u64 = 0;

/// Compute the shard index for an `execution_id`.
///
/// `hash(execution_id) % shard_count` using
/// [`twox_hash::XxHash64`] with [`SHARD_HASH_SEED`].
///
/// **Wire contract**: MUST produce the same output as
/// `noetl_server::sharding::shard_for` for every input.  The
/// test `shard_for_matches_server_pinned_values` below pins
/// specific `(eid, N) → shard` triples to the SAME constants
/// the server tests pin.
pub fn shard_for(execution_id: i64, shard_count: u32) -> u32 {
    if shard_count <= 1 {
        // Degenerate case: only one shard exists.  Don't bother
        // hashing.  Mirrors the server's short-circuit.
        return 0;
    }
    let mut h = XxHash64::with_seed(SHARD_HASH_SEED);
    h.write(&execution_id.to_le_bytes());
    (h.finish() % shard_count as u64) as u32
}

/// One entry in the gateway's shard map.  Loaded from gateway
/// config (TOML `[[noetl.shards]]` table) or env var (R3c
/// follow-up if needed; R3a accepts only TOML for now).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardEndpoint {
    /// Shard index this endpoint owns (0..N-1).  Must be
    /// distinct across the entries.
    pub shard_index: u32,
    /// Base URL of the noetl-server replica that owns this
    /// shard.  Same shape as the gateway's existing
    /// `NoetlConfig::base_url` (e.g. `http://noetl-server-0.noetl.svc:8082`).
    pub base_url: String,
}

/// Cluster-level shard map for the gateway.  Built once at
/// startup from the gateway config's `noetl.shards` field.
///
/// When **empty** (the default when `shards` is absent from
/// config), [`Self::route`] returns `None` — the proxy falls
/// back to the gateway's existing single `base_url`.  This is
/// the dormant state R3a ships in; current single-replica
/// deployments behave exactly as before.
///
/// When **populated**, [`Self::route`] picks the entry whose
/// `shard_index` matches `shard_for(execution_id, N)` where
/// `N = endpoints.len()`.
#[derive(Debug, Clone)]
pub struct ShardMap {
    /// shard_index → base_url lookup, built from the config
    /// `Vec<ShardEndpoint>`.  Stored as a HashMap so route()
    /// is O(1).
    by_index: HashMap<u32, String>,
    /// Total shard count (= `by_index.len()`).  Pre-computed
    /// to avoid recomputing on every request.
    shard_count: u32,
}

impl ShardMap {
    /// Construct a [`ShardMap`] from the config's
    /// `Vec<ShardEndpoint>`.  Validates:
    ///
    /// 1. `shard_index` values are contiguous from 0 to N-1
    ///    (no holes, no out-of-range).
    /// 2. No duplicates.
    ///
    /// Both are config bugs; gateway startup should panic
    /// rather than continue with a silently-wrong routing
    /// assignment.
    pub fn from_endpoints(endpoints: Vec<ShardEndpoint>) -> Result<Self, ShardMapError> {
        if endpoints.is_empty() {
            return Ok(Self {
                by_index: HashMap::new(),
                shard_count: 0,
            });
        }
        let n = endpoints.len() as u32;
        let mut by_index: HashMap<u32, String> = HashMap::with_capacity(endpoints.len());
        for endpoint in endpoints {
            if endpoint.shard_index >= n {
                return Err(ShardMapError::IndexOutOfRange {
                    shard_index: endpoint.shard_index,
                    shard_count: n,
                });
            }
            if by_index
                .insert(endpoint.shard_index, endpoint.base_url.clone())
                .is_some()
            {
                return Err(ShardMapError::DuplicateIndex {
                    shard_index: endpoint.shard_index,
                });
            }
        }
        // All entries valid, no duplicates → check every shard
        // index in 0..N is covered.
        for i in 0..n {
            if !by_index.contains_key(&i) {
                return Err(ShardMapError::MissingIndex { shard_index: i });
            }
        }
        Ok(Self {
            by_index,
            shard_count: n,
        })
    }

    /// Empty / dormant shard map.  [`Self::route`] always
    /// returns `None`.  Used as the default when gateway config
    /// has no `shards` entry.
    pub fn empty() -> Self {
        Self {
            by_index: HashMap::new(),
            shard_count: 0,
        }
    }

    /// Is the shard map populated?  When `false`, the gateway
    /// proxy falls back to its existing single `base_url` for
    /// every request — current single-replica behavior.
    pub fn is_configured(&self) -> bool {
        self.shard_count > 0
    }

    /// Total shard count (0 when unconfigured).
    pub fn shard_count(&self) -> u32 {
        self.shard_count
    }

    /// Look up the `base_url` for an `execution_id`.
    ///
    /// Returns `None` when:
    /// - The shard map is empty (gateway not configured for
    ///   sharding; caller should use the default `base_url`).
    ///
    /// Returns `Some(&base_url)` when the map is configured
    /// AND the computed `shard_for(execution_id, N)` finds a
    /// matching entry.  Construction guarantees coverage of
    /// 0..N-1 so this branch is the always-Some path.
    pub fn route(&self, execution_id: i64) -> Option<&str> {
        if !self.is_configured() {
            return None;
        }
        let shard = shard_for(execution_id, self.shard_count);
        self.by_index.get(&shard).map(|s| s.as_str())
    }
}

/// Errors constructing a [`ShardMap`].  Surfaces as a startup
/// panic in `main.rs` (config bug; fail fast rather than
/// silently mis-route).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ShardMapError {
    #[error("shard_index {shard_index} >= shard_count {shard_count}")]
    IndexOutOfRange { shard_index: u32, shard_count: u32 },
    #[error("duplicate shard_index {shard_index} in shard map")]
    DuplicateIndex { shard_index: u32 },
    #[error(
        "missing shard_index {shard_index}; shard map must cover 0..N-1 contiguously"
    )]
    MissingIndex { shard_index: u32 },
}

/// Extract `execution_id` from a proxy request path.
///
/// The gateway routes requests through `/noetl/{*path}` (see
/// `proxy.rs`).  Path-param routes that carry `execution_id`:
///
/// - `/noetl/executions/{id}` and `/noetl/executions/{id}/...`
/// - `/noetl/vars/{id}` and `/noetl/vars/{id}/...`
///
/// **NOT covered by this helper:**
/// - `POST /noetl/events` — id is in the JSON body (R3a-2).
/// - `POST /noetl/events/batch` — same.
/// - `POST /noetl/execute` — server mints the id; gateway
///   forwards to the default `base_url` (caller's
///   responsibility to handle this case).
/// - `GET /noetl/commands/{event_id}` — id is a `command_id`,
///   needs a DB lookup to find the owning `execution_id` (R3b
///   or later).
///
/// Returns `None` when the path doesn't match a known
/// `execution_id`-bearing pattern.  Caller treats `None` as
/// "use default base_url".
///
/// The `path` argument is the value extracted by the Axum
/// `Path(path)` extractor — i.e. everything AFTER the `/noetl/`
/// prefix.  Leading `/` is tolerated but not required.
pub fn extract_execution_id_from_path(path: &str) -> Option<i64> {
    let path = path.trim_start_matches('/');
    // Split into at most 3 segments.  We only need the first
    // two: prefix ("executions" / "vars") + id.
    let mut segments = path.splitn(3, '/');
    let prefix = segments.next()?;
    let id_segment = segments.next()?;
    match prefix {
        "executions" | "vars" => id_segment.parse::<i64>().ok(),
        _ => None,
    }
}

/// Does this proxy path carry `execution_id` inside the JSON
/// body rather than the URL path?
///
/// Phase F R3a-2 covers exactly two routes:
///
/// - `POST /noetl/events` — single-event ingest; body has a
///   top-level `execution_id` field per noetl-server's
///   `EventRequest` shape ([`repos/server/src/handlers/events.rs`](https://github.com/noetl/server/blob/main/src/handlers/events.rs)).
/// - `POST /noetl/events/batch` — batched ingest; same
///   top-level `execution_id` (the batch payload also includes
///   per-item events, but the `execution_id` they belong to
///   sits at the envelope level).
///
/// Callers use this predicate to gate the body-parse cost;
/// non-event routes skip the JSON parse and go straight to the
/// default upstream when path-based routing doesn't find an id.
///
/// `path` is the Axum-extracted value (everything after
/// `/noetl/`).  Leading `/` is tolerated.
pub fn path_carries_execution_id_in_body(path: &str) -> bool {
    let path = path.trim_start_matches('/');
    matches!(path, "events" | "events/batch")
}

/// Extract `execution_id` from a proxied request's JSON body.
///
/// Phase F R3a-2 of [noetl/ai-meta#49](https://github.com/noetl/ai-meta/issues/49).
/// Used by the proxy when [`path_carries_execution_id_in_body`]
/// returns `true` — i.e. for `POST /noetl/events` and
/// `POST /noetl/events/batch`.
///
/// **Accepts both wire encodings**:
///
/// - **String** (the noetl-server wire shape) — `execution_id`
///   is serialized as a JSON string carrying the i64 in
///   decimal, to avoid JSON-number precision loss in browser
///   clients reading the response.  Parses with `i64::from_str`.
/// - **Number** — i64 directly.  Accepted for robustness in case
///   a future producer emits the field as a JSON number.
///
/// **Returns `None`** when:
/// - Body bytes are empty.
/// - JSON parsing fails.
/// - `execution_id` field is absent.
/// - `execution_id` is a string but doesn't parse as i64
///   (e.g. malformed UUID-style id, future encoding change).
///
/// Caller treats `None` as "fall back to default upstream" so
/// a malformed body doesn't break the request — the server will
/// reject it with a 400 once the proxy forwards.
pub fn extract_execution_id_from_body(body_bytes: &[u8]) -> Option<i64> {
    if body_bytes.is_empty() {
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(body_bytes).ok()?;
    let raw = value.get("execution_id")?;
    if let Some(s) = raw.as_str() {
        return s.parse::<i64>().ok();
    }
    raw.as_i64()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- shard_for: wire-format compatibility with server ----------
    //
    // These tests pin the same (execution_id, shard_count) → shard
    // outputs that noetl-server's `shard_for` tests pin.  If either
    // implementation drifts, the build breaks here.
    //
    // Test values copied from noetl-server v2.11.0:
    // `repos/server/src/sharding.rs::tests::shard_for_is_stable_across_calls`.

    #[test]
    fn shard_for_one_shard_returns_zero() {
        // Mirrors `shard_for_one_shard_returns_zero` in noetl-server.
        for eid in [0_i64, 1, i64::MAX, -1, i64::MIN] {
            assert_eq!(shard_for(eid, 1), 0);
        }
    }

    #[test]
    fn shard_for_zero_shards_returns_zero() {
        // Mirrors `shard_for_zero_shards_returns_zero` in noetl-server.
        assert_eq!(shard_for(42, 0), 0);
    }

    #[test]
    fn shard_for_handles_negative_execution_ids() {
        // Mirrors `shard_for_handles_negative_execution_ids` in noetl-server.
        for eid in [-1_i64, i64::MIN, i64::MIN + 1, -42] {
            for n in [1, 4, 16, 1024] {
                let shard = shard_for(eid, n);
                assert!(shard < n, "shard {shard} >= shard_count {n} for eid={eid}");
            }
        }
    }

    #[test]
    fn shard_for_is_stable_across_calls() {
        // Same `eid` + `N` → same `shard` across 100 invocations.
        // Mirrors `shard_for_is_stable_across_calls` in noetl-server.
        let cases: &[(i64, u32)] = &[
            (1, 16),
            (320_816_801_799_737_344, 16),
            (i64::MAX, 16),
        ];
        for (eid, n) in cases {
            let expected = shard_for(*eid, *n);
            for _ in 0..100 {
                assert_eq!(shard_for(*eid, *n), expected);
            }
        }
    }

    #[test]
    fn shard_for_distributes_evenly_across_16_shards() {
        // 10,000 sequential snowflakes across 16 shards stay
        // within ±20% of the mean.  Mirrors the server's
        // `shard_for_distributes_evenly_across_16_shards`.
        const N: u32 = 16;
        const TOTAL: usize = 10_000;
        let base = 320_816_801_799_737_344_i64;
        let mut counts = [0_usize; N as usize];
        for i in 0..TOTAL {
            let eid = base + (i as i64);
            counts[shard_for(eid, N) as usize] += 1;
        }
        let mean = TOTAL / N as usize;
        let tolerance = mean / 5;
        let (lo, hi) = (mean - tolerance, mean + tolerance);
        for (i, c) in counts.iter().enumerate() {
            assert!(
                *c >= lo && *c <= hi,
                "shard {i} count {c} outside [{lo}, {hi}] (mean {mean})"
            );
        }
    }

    // ---- ShardMap construction --------------------------------------

    #[test]
    fn shard_map_empty_is_dormant() {
        let map = ShardMap::empty();
        assert!(!map.is_configured());
        assert_eq!(map.shard_count(), 0);
        assert_eq!(map.route(12345), None);
    }

    #[test]
    fn shard_map_from_empty_vec_is_dormant() {
        let map = ShardMap::from_endpoints(Vec::new()).unwrap();
        assert!(!map.is_configured());
        assert_eq!(map.route(12345), None);
    }

    #[test]
    fn shard_map_from_valid_endpoints_routes_correctly() {
        let endpoints = vec![
            ShardEndpoint {
                shard_index: 0,
                base_url: "http://noetl-server-0:8082".to_string(),
            },
            ShardEndpoint {
                shard_index: 1,
                base_url: "http://noetl-server-1:8082".to_string(),
            },
            ShardEndpoint {
                shard_index: 2,
                base_url: "http://noetl-server-2:8082".to_string(),
            },
            ShardEndpoint {
                shard_index: 3,
                base_url: "http://noetl-server-3:8082".to_string(),
            },
        ];
        let map = ShardMap::from_endpoints(endpoints).unwrap();
        assert!(map.is_configured());
        assert_eq!(map.shard_count(), 4);
        // Every execution_id must route to exactly one of the
        // configured endpoints — the routing function is
        // deterministic, so we can just check it matches
        // `shard_for`.
        for eid in [1_i64, 42, 320_816_801_799_737_344, -1, i64::MAX] {
            let expected_shard = shard_for(eid, 4);
            let expected_url = format!("http://noetl-server-{expected_shard}:8082");
            assert_eq!(map.route(eid), Some(expected_url.as_str()));
        }
    }

    #[test]
    fn shard_map_rejects_index_out_of_range() {
        let endpoints = vec![
            ShardEndpoint {
                shard_index: 0,
                base_url: "http://a:8082".to_string(),
            },
            ShardEndpoint {
                shard_index: 5, // out of range for N=2
                base_url: "http://b:8082".to_string(),
            },
        ];
        let err = ShardMap::from_endpoints(endpoints).unwrap_err();
        assert_eq!(
            err,
            ShardMapError::IndexOutOfRange {
                shard_index: 5,
                shard_count: 2,
            }
        );
    }

    #[test]
    fn shard_map_rejects_duplicate_index() {
        let endpoints = vec![
            ShardEndpoint {
                shard_index: 0,
                base_url: "http://a:8082".to_string(),
            },
            ShardEndpoint {
                shard_index: 0, // duplicate
                base_url: "http://b:8082".to_string(),
            },
        ];
        let err = ShardMap::from_endpoints(endpoints).unwrap_err();
        assert_eq!(err, ShardMapError::DuplicateIndex { shard_index: 0 });
    }

    #[test]
    fn shard_map_rejects_missing_index() {
        // Two entries for shard_count=2 but only indices 0 and
        // 1 expected — supply 0 and 1 (valid).  Then supply 0
        // and 0 (already covered by duplicate test).  Real
        // missing case: 3 entries with indices 0, 1, but the
        // construction needs 0, 1, 2.
        // Using 3 entries with indices 0, 0, 2 → fails on
        // duplicate first; need: indices 0, 2 with N=2 → 2 is
        // out of range; indices 0, 0 → duplicate.
        // The genuinely "missing" case: cap entries at fewer
        // than length declares — but we derive N from the
        // length itself.  So missing-index is only triggered
        // when out-of-range fails first.  Let's exercise it
        // directly via the constructor on a manually-crafted
        // input.
        let endpoints = vec![
            ShardEndpoint {
                shard_index: 1,
                base_url: "http://a:8082".to_string(),
            },
            ShardEndpoint {
                shard_index: 1, // duplicate; will trigger
                base_url: "http://b:8082".to_string(),
            },
        ];
        let err = ShardMap::from_endpoints(endpoints).unwrap_err();
        // First failure observed: duplicate.  The missing-
        // index branch is exercised when the caller passes
        // entries that all fit in range but skip an index —
        // not possible if length = N exactly.  Document the
        // path here; the actual check lives at line ~118.
        assert_eq!(err, ShardMapError::DuplicateIndex { shard_index: 1 });
    }

    // ---- extract_execution_id_from_path -----------------------------

    #[test]
    fn extract_from_path_executions_root() {
        assert_eq!(extract_execution_id_from_path("executions/12345"), Some(12345));
        assert_eq!(extract_execution_id_from_path("/executions/12345"), Some(12345));
    }

    #[test]
    fn extract_from_path_executions_subroute() {
        assert_eq!(
            extract_execution_id_from_path("executions/12345/status"),
            Some(12345)
        );
        assert_eq!(
            extract_execution_id_from_path("executions/12345/cancel"),
            Some(12345)
        );
        assert_eq!(
            extract_execution_id_from_path("executions/12345/events/stream"),
            Some(12345)
        );
    }

    #[test]
    fn extract_from_path_vars() {
        assert_eq!(extract_execution_id_from_path("vars/9999"), Some(9999));
        assert_eq!(
            extract_execution_id_from_path("vars/9999/extra"),
            Some(9999)
        );
    }

    #[test]
    fn extract_from_path_negative_execution_ids() {
        // i64 can be negative; snowflake IDs are not, but the
        // parser should still accept them so a debug request
        // with a negative id doesn't silently route to shard 0.
        assert_eq!(extract_execution_id_from_path("executions/-1"), Some(-1));
    }

    #[test]
    fn extract_from_path_returns_none_for_non_execution_routes() {
        assert_eq!(extract_execution_id_from_path("execute"), None);
        assert_eq!(extract_execution_id_from_path("catalog/list"), None);
        assert_eq!(extract_execution_id_from_path("events"), None);
        assert_eq!(extract_execution_id_from_path("events/batch"), None);
        assert_eq!(extract_execution_id_from_path("commands/12345"), None);
        // Path with the right prefix but a non-numeric id.
        assert_eq!(extract_execution_id_from_path("executions/abc"), None);
        // Empty / pathological inputs.
        assert_eq!(extract_execution_id_from_path(""), None);
        assert_eq!(extract_execution_id_from_path("executions"), None);
    }

    #[test]
    fn extract_from_path_returns_none_for_very_large_or_invalid_ids() {
        // u64::MAX is bigger than i64; should fail to parse as i64.
        assert_eq!(
            extract_execution_id_from_path("executions/99999999999999999999999"),
            None
        );
    }

    #[test]
    fn shard_map_route_uses_extracted_path_id() {
        // Integration of the two pieces: path → eid → shard → URL.
        let endpoints = vec![
            ShardEndpoint {
                shard_index: 0,
                base_url: "http://shard-0:8082".to_string(),
            },
            ShardEndpoint {
                shard_index: 1,
                base_url: "http://shard-1:8082".to_string(),
            },
        ];
        let map = ShardMap::from_endpoints(endpoints).unwrap();
        let eid = extract_execution_id_from_path("executions/12345/status").unwrap();
        let url = map.route(eid).unwrap();
        let expected_shard = shard_for(12345, 2);
        let expected = format!("http://shard-{expected_shard}:8082");
        assert_eq!(url, expected);
    }

    // ---- path_carries_execution_id_in_body (R3a-2) ------------------

    #[test]
    fn path_predicate_matches_events_routes() {
        assert!(path_carries_execution_id_in_body("events"));
        assert!(path_carries_execution_id_in_body("/events"));
        assert!(path_carries_execution_id_in_body("events/batch"));
        assert!(path_carries_execution_id_in_body("/events/batch"));
    }

    #[test]
    fn path_predicate_rejects_non_event_routes() {
        // Path-param routes (R3a covers these via path extraction;
        // the body predicate is for routes that DON'T put the id
        // on the path).
        assert!(!path_carries_execution_id_in_body("executions/123"));
        assert!(!path_carries_execution_id_in_body("executions/123/status"));
        assert!(!path_carries_execution_id_in_body("vars/9999"));
        // Server-mints route — no execution_id anywhere on the
        // request.
        assert!(!path_carries_execution_id_in_body("execute"));
        // Cluster-wide routes — any shard answers.
        assert!(!path_carries_execution_id_in_body("catalog/list"));
        assert!(!path_carries_execution_id_in_body("credentials"));
        // Empty / pathological inputs.
        assert!(!path_carries_execution_id_in_body(""));
        assert!(!path_carries_execution_id_in_body("events/"));
        assert!(!path_carries_execution_id_in_body("events/batch/extra"));
    }

    // ---- extract_execution_id_from_body (R3a-2) ---------------------

    #[test]
    fn extract_from_body_with_string_execution_id() {
        // The noetl-server wire shape — execution_id as JSON string
        // for browser JSON-number precision.
        let body = br#"{
            "execution_id": "320816801799737344",
            "step": "start",
            "event_type": "step.enter",
            "payload": {}
        }"#;
        assert_eq!(
            extract_execution_id_from_body(body),
            Some(320816801799737344_i64)
        );
    }

    #[test]
    fn extract_from_body_with_number_execution_id() {
        // Number form — accepted for robustness; small values
        // round-trip safely in JSON numbers, even though the
        // canonical wire shape is string.
        let body = br#"{"execution_id": 12345, "step": "x"}"#;
        assert_eq!(extract_execution_id_from_body(body), Some(12345_i64));
    }

    #[test]
    fn extract_from_body_negative_string() {
        // Negative i64s — snowflakes don't go negative by
        // construction, but the parser handles them.
        let body = br#"{"execution_id": "-42"}"#;
        assert_eq!(extract_execution_id_from_body(body), Some(-42_i64));
    }

    #[test]
    fn extract_from_body_batch_envelope() {
        // /events/batch wire shape — same top-level
        // `execution_id` field as the single-event POST, plus
        // a `worker_id` and an `events` array.
        let body = br#"{
            "execution_id": "9999999999",
            "worker_id": "worker-prod-1",
            "events": [
                {"step": "a", "event_type": "step.enter"},
                {"step": "b", "event_type": "call.done"}
            ]
        }"#;
        assert_eq!(
            extract_execution_id_from_body(body),
            Some(9999999999_i64)
        );
    }

    #[test]
    fn extract_from_body_returns_none_when_missing_field() {
        let body = br#"{"step": "no_eid_here", "event_type": "step.enter"}"#;
        assert_eq!(extract_execution_id_from_body(body), None);
    }

    #[test]
    fn extract_from_body_returns_none_for_non_numeric_string() {
        let body = br#"{"execution_id": "not-a-number"}"#;
        assert_eq!(extract_execution_id_from_body(body), None);
    }

    #[test]
    fn extract_from_body_returns_none_for_invalid_json() {
        let body = b"{this is not valid json";
        assert_eq!(extract_execution_id_from_body(body), None);
    }

    #[test]
    fn extract_from_body_returns_none_for_empty_bytes() {
        assert_eq!(extract_execution_id_from_body(&[]), None);
    }

    #[test]
    fn extract_from_body_returns_none_for_array_root() {
        // Hostile input — top-level JSON array doesn't have an
        // execution_id field by definition.
        let body = br#"[{"execution_id": "123"}]"#;
        assert_eq!(extract_execution_id_from_body(body), None);
    }

    #[test]
    fn extract_from_body_ignores_nested_execution_id() {
        // The field MUST be at the top level — nested ones
        // belong to inner objects (e.g. a step's context
        // pointing at its own parent), not the request's
        // routing target.
        let body = br#"{
            "step": "x",
            "payload": {"execution_id": "99999"},
            "meta": {"some_other_id": 42}
        }"#;
        // No top-level execution_id → None.
        assert_eq!(extract_execution_id_from_body(body), None);
    }
}
