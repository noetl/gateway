//! Which routes an authenticated session may reach.
//!
//! Authentication (`auth::middleware`) establishes WHO is calling. This module
//! decides WHAT that caller may do, on the two surfaces that reach the NoETL
//! API on a session's behalf: the REST proxy (`/noetl/{*path}`) and the GraphQL
//! mutations.
//!
//! There are exactly two roles:
//!
//! * **Admin** — the session's user holds the `admin` role. The GUI and the
//!   CLI's gateway mode run as admin and keep the full proxy surface and every
//!   GraphQL mutation, as before.
//! * **Regular user** — everyone else. Deny by default. A regular user may:
//!   - start one of the allowlisted playbooks (`GATEWAY_USER_PLAYBOOKS`)
//!     through `executePlaybook`;
//!   - read (`GET executions/{id}`) or cancel (`POST executions/{id}/cancel`)
//!     an execution THEY started, recorded by [`ExecutionOwners`].
//!
//! Nothing else: no other proxy route, no `rerunExecution`, no `proxyRequest`,
//! no agents. Any role other than `admin` grants nothing beyond a regular user.
//!
//! Development auth bypass (`GATEWAY_AUTH_BYPASS`) is treated as admin; it
//! already accepts any token.

use std::collections::HashMap;
use std::sync::Arc;

use axum::http::Method;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::auth::types::UserContext;

/// Playbooks a regular user may start when `GATEWAY_USER_PLAYBOOKS` is unset:
/// the travel apps' complete set.
pub const DEFAULT_USER_PLAYBOOKS: &[&str] = &[
    "muno/playbooks/itinerary-planner",
    "muno/playbooks/hotel-cards",
    "muno/playbooks/flights-details",
    "muno/playbooks/profile",
    "travel/playbooks/catalog/calendar/list",
    // The caller's own thread index (noetl/travel#148); `uid` is bound to the session.
    "muno/playbooks/threads",
];

/// The one role with broad access. Not configurable: there is no other tier.
pub const ADMIN_ROLE: &str = "admin";

/// The authorization policy. Built once from the environment at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub user_playbooks: Vec<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            user_playbooks: DEFAULT_USER_PLAYBOOKS.iter().map(|s| s.to_string()).collect(),
        }
    }
}

fn csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

impl Policy {
    /// `GATEWAY_USER_PLAYBOOKS` is comma-separated. Unset or blank keeps the
    /// default.
    pub fn from_env() -> Self {
        let mut policy = Self::default();
        if let Ok(v) = std::env::var("GATEWAY_USER_PLAYBOOKS") {
            let playbooks = csv(&v);
            if !playbooks.is_empty() {
                policy.user_playbooks = playbooks;
            }
        }
        policy
    }

    /// Admin or regular user: the only distinction this gateway makes.
    pub fn is_admin(&self, user: &UserContext) -> bool {
        crate::auth::middleware::is_auth_bypass_enabled() || user.roles.iter().any(|r| r.trim() == ADMIN_ROLE)
    }

    /// May `user` start catalog entry `name` of `kind` through `executePlaybook`?
    pub fn may_execute(&self, user: &UserContext, name: &str, kind: &str) -> bool {
        self.is_admin(user) || (kind == "playbook" && self.user_playbooks.iter().any(|p| p == name))
    }

    /// What `user` may do with proxy route `method path` (`path` as captured
    /// after `/noetl/`).
    pub fn proxy_access(&self, user: &UserContext, method: &Method, path: &str) -> ProxyAccess {
        if self.is_admin(user) {
            return ProxyAccess::Granted;
        }
        match user_execution_route(method, path) {
            Some(id) => ProxyAccess::OwnerOnly(id.to_string()),
            None => ProxyAccess::Denied,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyAccess {
    /// Admin: forward as-is.
    Granted,
    /// Regular user: forward only if the session's user started this execution.
    OwnerOnly(String),
    /// Regular user, route not on the allowlist.
    Denied,
}

/// A NoETL execution id: a positive decimal integer.
fn execution_id(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()) && s.parse::<i64>().is_ok_and(|id| id > 0)
}

/// The two execution routes a regular user may reach, matched exactly: no extra
/// segments, no empty or dot segments, and an id that is a bare decimal number.
/// Returns the execution id.
fn user_execution_route<'a>(method: &Method, path: &'a str) -> Option<&'a str> {
    let segments: Vec<&str> = path.split('/').collect();
    match (method, segments.as_slice()) {
        (&Method::GET, ["executions", id]) if execution_id(id) => Some(id),
        (&Method::POST, ["executions", id, "cancel"]) if execution_id(id) => Some(id),
        _ => None,
    }
}

/// Who started an execution, as recorded when the gateway started it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionOwner {
    pub user_id: i32,
}

enum OwnerBackend {
    Ehdb(crate::ehdb_kv::EhdbKvClient),
    #[cfg_attr(not(test), allow(dead_code))]
    Memory(Mutex<HashMap<String, String>>),
}

/// `execution_id -> owner` for executions the gateway started on a session's
/// behalf, on the same EHDB KV face as the session cache and request store.
///
/// An entry lives `ttl_secs`; after that the execution reads as unowned and an
/// regular user can no longer poll or cancel it (admins still can).
pub struct ExecutionOwners {
    backend: OwnerBackend,
    bucket: String,
    ttl_secs: u64,
}

impl ExecutionOwners {
    pub fn new(bucket: String, ttl_secs: u64, addr: &str) -> Self {
        Self {
            backend: OwnerBackend::Ehdb(crate::ehdb_kv::EhdbKvClient::new(addr)),
            bucket,
            ttl_secs,
        }
    }

    #[cfg(test)]
    pub fn in_memory() -> Self {
        Self {
            backend: OwnerBackend::Memory(Mutex::new(HashMap::new())),
            bucket: "execution_owners".into(),
            ttl_secs: 0,
        }
    }

    /// Record that `user` started `execution_id`. Sessions without a real user
    /// (dev bypass, `user_id <= 0`) are not recorded: nothing could match them.
    pub async fn record(&self, execution_id: &str, user: &UserContext) -> anyhow::Result<()> {
        if user.user_id <= 0 || execution_id.is_empty() {
            return Ok(());
        }
        let body = serde_json::to_string(&ExecutionOwner { user_id: user.user_id })?;
        match &self.backend {
            OwnerBackend::Ehdb(kv) => kv.put(&self.bucket, execution_id, &body, self.ttl_secs).await,
            OwnerBackend::Memory(m) => {
                m.lock().await.insert(execution_id.to_string(), body);
                Ok(())
            }
        }
    }

    /// Did `user` start `execution_id`? `Err` when the store could not answer;
    /// the caller must then refuse rather than guess.
    pub async fn is_owner(&self, execution_id: &str, user: &UserContext) -> anyhow::Result<bool> {
        if user.user_id <= 0 {
            return Ok(false);
        }
        let body = match &self.backend {
            OwnerBackend::Ehdb(kv) => kv.get(&self.bucket, execution_id).await?,
            OwnerBackend::Memory(m) => m.lock().await.get(execution_id).cloned(),
        };
        Ok(body
            .and_then(|b| serde_json::from_str::<ExecutionOwner>(&b).ok())
            .is_some_and(|o| o.user_id == user.user_id))
    }
}

/// Record ownership after the gateway started an execution. A failure is
/// logged, not returned: the execution is already running, and the user still
/// gets its result over SSE; only polling and cancel by id are refused.
pub async fn record_owner(owners: Option<&Arc<ExecutionOwners>>, execution_id: &str, user: Option<&UserContext>) {
    let (Some(owners), Some(user)) = (owners, user) else {
        return;
    };
    if let Err(e) = owners.record(execution_id, user).await {
        crate::ingress::record_route_authz("owner_record_failed");
        tracing::error!(
            execution_id = execution_id,
            user_id = user.user_id,
            "failed to record execution owner; the user cannot poll or cancel it: {}",
            e
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(roles: &[&str]) -> UserContext {
        UserContext {
            user_id: 7,
            email: "user@example.invalid".into(),
            display_name: "User".into(),
            session_token: "synthetic".into(),
            auth0_sub: Some("auth0|user".into()),
            roles: roles.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn the_default_user_allowlist_is_exactly_the_travel_apps_set() {
        let p = Policy::default();
        assert_eq!(p.user_playbooks.len(), 6);
        let user = session(&[]);
        for name in DEFAULT_USER_PLAYBOOKS {
            assert!(p.may_execute(&user, name, "playbook"), "{name}");
        }
    }

    #[test]
    fn a_regular_user_may_not_start_anything_else() {
        let p = Policy::default();
        let user = session(&[]);
        for name in [
            "automation/agents/mcp/firestore",
            "muno/playbooks/profile/",
            " muno/playbooks/profile",
            "muno/playbooks",
            "muno/playbooks/profile@1",
            "",
        ] {
            assert!(!p.may_execute(&user, name, "playbook"), "{name:?}");
        }
        // An allowlisted path run as an agent is still not allowed.
        assert!(!p.may_execute(&user, "muno/playbooks/profile", "agent"));
    }

    #[test]
    fn an_admin_may_start_anything() {
        let p = Policy::default();
        let admin = session(&["admin"]);
        assert!(p.may_execute(&admin, "automation/agents/mcp/firestore", "playbook"));
        assert!(p.may_execute(&admin, "some/agent", "agent"));
    }

    /// Two roles only: `admin`, or a regular user. Any other role name a
    /// database may still hold grants nothing extra.
    #[test]
    fn only_the_admin_role_is_admin() {
        let p = Policy::default();
        assert!(p.is_admin(&session(&["admin"])));
        assert!(p.is_admin(&session(&[" admin "])));
        assert!(!p.is_admin(&session(&[])));
        for other in ["developer", "operator", "analyst", "viewer", "Admin", "admins"] {
            assert!(!p.is_admin(&session(&[other])), "{other}");
        }
    }

    #[test]
    fn csv_ignores_blanks() {
        assert_eq!(csv(" a/b, ,c/d ,"), vec!["a/b", "c/d"]);
        assert!(csv(" , ").is_empty());
    }

    #[test]
    fn a_regular_user_reaches_only_the_two_execution_routes_and_only_as_owner() {
        let p = Policy::default();
        let u = session(&[]);
        assert_eq!(
            p.proxy_access(&u, &Method::GET, "executions/736128496593797232"),
            ProxyAccess::OwnerOnly("736128496593797232".into())
        );
        assert_eq!(
            p.proxy_access(&u, &Method::POST, "executions/42/cancel"),
            ProxyAccess::OwnerOnly("42".into())
        );
    }

    #[test]
    fn every_other_route_is_denied_to_a_regular_user() {
        let p = Policy::default();
        let u = session(&[]);
        for (method, path) in [
            (Method::POST, "execute"),
            (Method::POST, "execute/batch"),
            (Method::POST, "executions/42/rerun"),
            (Method::POST, "catalog/register"),
            (Method::POST, "catalog/list"),
            (Method::GET, "credentials"),
            (Method::GET, "executions"),
            (Method::GET, "executions/42/events"),
            (Method::GET, "executions/42/cancel"),
            (Method::POST, "executions/42"),
            (Method::DELETE, "executions/42"),
            (Method::PUT, "executions/42/cancel"),
            // Shapes that could be resolved upstream into another route.
            (Method::GET, "executions/42/.."),
            (Method::GET, "executions/../catalog/list"),
            (Method::GET, "executions/42/"),
            (Method::GET, "/executions/42"),
            (Method::GET, "executions//42"),
            (Method::GET, "executions/0"),
            (Method::GET, "executions/-1"),
            (Method::GET, "executions/42abc"),
            (Method::GET, "executions/%34%32"),
            (Method::POST, "executions/42/cancel/../../../catalog/register"),
            (Method::GET, "executions/99999999999999999999"),
        ] {
            assert_eq!(p.proxy_access(&u, &method, path), ProxyAccess::Denied, "{method} {path}");
        }
    }

    #[test]
    fn an_admin_keeps_the_whole_proxy() {
        let p = Policy::default();
        let admin = session(&["admin"]);
        assert_eq!(p.proxy_access(&admin, &Method::POST, "catalog/register"), ProxyAccess::Granted);
        assert_eq!(p.proxy_access(&admin, &Method::GET, "executions/42"), ProxyAccess::Granted);
    }

    #[tokio::test]
    async fn ownership_is_per_user() {
        let owners = ExecutionOwners::in_memory();
        let alice = UserContext { user_id: 1, ..session(&[]) };
        let bob = UserContext { user_id: 2, ..session(&[]) };
        owners.record("42", &alice).await.unwrap();
        assert!(owners.is_owner("42", &alice).await.unwrap());
        assert!(!owners.is_owner("42", &bob).await.unwrap());
        assert!(!owners.is_owner("43", &alice).await.unwrap());
    }

    #[tokio::test]
    async fn a_session_without_a_real_user_owns_nothing() {
        let owners = ExecutionOwners::in_memory();
        let nobody = UserContext { user_id: 0, ..session(&[]) };
        owners.record("42", &nobody).await.unwrap();
        assert!(!owners.is_owner("42", &nobody).await.unwrap());
    }
}
