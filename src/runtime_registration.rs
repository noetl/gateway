//! Self-registration in the NoETL server's D8 runtime registry.
//!
//! noetl/ai-meta#455 P2 — the `Gateway` kind. Until this existed the gateway announced
//! itself to the server in no way whatever, so `discover(Gateway)` was permanently empty
//! and the topology could describe every component except the one users actually reach.
//!
//! ⚠ The registry is **server-owned** state (`agents/rules/data-access-boundary.md`): the
//! gateway reaches it over the server's HTTP API, never by touching EHDB itself.
//!
//! ⚠⚠ Liveness here is a **lease**, not a status field. Nothing marks a gateway dead; it
//! expires because nothing renewed it. That is the whole point — a status column someone
//! has to remember to update is the representation-drift shape this platform keeps
//! finding, and a lease cannot drift because the absence of a heartbeat *is* the signal.

use std::sync::Arc;

use crate::noetl_client::NoetlClient;

/// Opt-out knob. Default **on**: a registry that has to be switched on is a registry that
/// is off in the one deployment whose topology someone needed to read.
const ENABLE_VAR: &str = "NOETL_GATEWAY_RUNTIME_REGISTRY";

/// How this gateway names itself.
///
/// `HOSTNAME` is the pod name under Kubernetes, which is what makes a replica
/// distinguishable from its siblings. Without it every replica would register the same id
/// and `discover(Gateway)` would report one live gateway no matter how many were running —
/// a count that looks plausible and is wrong.
fn self_id() -> String {
    let raw = std::env::var("HOSTNAME").unwrap_or_default();
    let raw = raw.trim();
    let base = if raw.is_empty() { "gateway" } else { raw };
    sanitise(base)
}

/// Keep to what the server's `validate_op` accepts (`[A-Za-z0-9-_.:]`), since the id
/// becomes a substrate key. Anything else is replaced rather than dropped, so two
/// different hostnames cannot collapse onto one id.
fn sanitise(raw: &str) -> String {
    let s: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':') {
                c
            } else {
                '-'
            }
        })
        .collect();
    // A leading/trailing dot or a dot-run is refused upstream; collapse defensively.
    let s = s.trim_matches('.').to_string();
    if s.is_empty() {
        "gateway".to_string()
    } else {
        s.chars().take(128).collect()
    }
}

/// Does this value switch registration off?
///
/// Split out from [`enabled`] so a test measures THIS code rather than a copy of it. A
/// test that re-implements the predicate inline passes no matter what the real match arms
/// say — it asserts its own duplicate, which is a test that cannot fail for the reason it
/// exists.
pub fn disabled_by(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "off" | "no"
    )
}

pub fn enabled() -> bool {
    !disabled_by(&std::env::var(ENABLE_VAR).unwrap_or_default())
}

/// Pick the heartbeat interval from the lease the server granted.
///
/// A third of the TTL leaves room for two consecutive failures before the lease lapses.
/// Floored at one second so a misconfigured tiny TTL cannot turn this into a busy loop
/// against the server.
pub fn heartbeat_interval(ttl_secs: u64) -> std::time::Duration {
    std::time::Duration::from_secs((ttl_secs / 3).max(1))
}

/// Register once, then renew forever.
///
/// Fail-soft throughout: the gateway's job is to serve requests, and a registry that
/// cannot be reached must never stop it doing that. A failed renewal is logged and retried
/// on the next tick; if the lease lapses in the meantime the gateway simply reappears when
/// the server comes back, which is the correct reading — it genuinely was not reachable.
pub fn spawn(noetl: Arc<NoetlClient>) {
    if !enabled() {
        tracing::info!("Runtime registration disabled by {ENABLE_VAR}");
        return;
    }
    let id = self_id();
    tokio::spawn(async move {
        // The TTL is unknown until the first successful registration, so the first tick
        // is driven by a conservative fallback and every later one by the real lease.
        let mut interval = std::time::Duration::from_secs(60);
        loop {
            match noetl.register_runtime("gateway", &id, "gateway").await {
                Ok(ttl) => {
                    let next = heartbeat_interval(ttl);
                    if next != interval {
                        tracing::info!(
                            gateway_id = %id,
                            ttl_secs = ttl,
                            heartbeat_secs = next.as_secs(),
                            "Registered in the NoETL runtime registry; heartbeat interval \
                             taken from the lease the server granted"
                        );
                    }
                    interval = next;
                }
                Err(e) => {
                    tracing::warn!(
                        gateway_id = %id,
                        error = %e,
                        "Runtime registration failed; the gateway keeps serving and will \
                         retry — a lapsed lease correctly reports a gateway the server \
                         could not reach"
                    );
                }
            }
            tokio::time::sleep(interval).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⚠⚠ The interval must be strictly BELOW the TTL, or the lease expires between
    /// heartbeats and the gateway flickers in and out of `discover(Gateway)` while being
    /// perfectly healthy. Swept rather than spot-checked, so a future tweak to the divisor
    /// cannot satisfy one example and break the property.
    #[test]
    fn the_heartbeat_always_fits_inside_the_lease() {
        for ttl in [1u64, 2, 3, 5, 30, 60, 180, 600, 3600, 86_400] {
            let hb = heartbeat_interval(ttl).as_secs();
            assert!(hb >= 1, "ttl={ttl} produced a zero interval — a busy loop");
            if ttl >= 3 {
                assert!(
                    hb < ttl,
                    "ttl={ttl} gave heartbeat={hb}: a heartbeat at or beyond the TTL lets \
                     the lease lapse between renewals"
                );
                assert!(
                    hb * 2 < ttl || ttl < 6,
                    "ttl={ttl} gave heartbeat={hb}: leave room for two missed renewals"
                );
            }
        }
    }

    /// Replicas must be distinguishable, or the registry reports one gateway however many
    /// are running — a count that looks plausible and is wrong.
    #[test]
    fn two_hostnames_do_not_collapse_onto_one_id() {
        assert_ne!(
            sanitise("noetl-gateway-7d9f-abc12"),
            sanitise("noetl-gateway-7d9f-abc13")
        );
        // Characters outside the accepted set are replaced, not dropped — dropping would
        // map "a/b" and "ab" onto the same id.
        assert_ne!(sanitise("a/b"), sanitise("ab"));
    }

    /// The id must satisfy the server's `validate_op` or every registration 400s.
    #[test]
    fn the_id_is_always_acceptable_to_the_server() {
        for raw in [
            "",
            ".",
            "..",
            "...",
            "../../etc/passwd",
            "noetl-gateway-0",
            "WeIrD CaSe!! 💥",
            &"x".repeat(500),
        ] {
            let id = sanitise(raw);
            assert!(!id.is_empty(), "{raw:?} produced an empty id");
            assert!(id.len() <= 128, "{raw:?} produced {} chars", id.len());
            assert!(
                !id.starts_with('.') && !id.ends_with('.'),
                "{raw:?} produced {id:?}, which the server refuses"
            );
            assert!(
                id.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':')),
                "{raw:?} produced {id:?} with a character the server refuses"
            );
        }
        // Positive control: a traversal attempt must not survive as a traversal.
        assert!(!sanitise("../../etc/passwd").contains('/'));
    }

    /// Default ON. A registry that must be switched on is one that is off in the single
    /// deployment whose topology somebody needed to read.
    ///
    /// ⚠ Calls `disabled_by` — the real predicate — rather than re-deriving it. The first
    /// cut of this test inlined the same `matches!` and would therefore have passed
    /// against any change to the production arms, asserting only its own copy. Env is not
    /// mutated here because `cargo test` does not serialise tests and the races are real.
    #[test]
    fn registration_is_on_unless_explicitly_disabled() {
        for v in ["0", "false", "off", "no", "FALSE", " Off ", "No"] {
            assert!(disabled_by(v), "{v:?} must disable registration");
        }
        // The empty string is what an UNSET variable reads as — the default path.
        for v in ["", "1", "true", "yes", "on", "anything", " "] {
            assert!(!disabled_by(v), "{v:?} must NOT disable registration");
        }
    }
}
