//! Per-playbook rate limits for signed-in (non-admin) users.
//!
//! Off unless `GATEWAY_USER_PLAYBOOK_LIMITS` is set. Each entry
//! `path=per_user/total` limits how often one user, and all users together,
//! may start that playbook per rolling hour (per gateway pod), like
//! `GATEWAY_GUEST_PLAYBOOK_LIMITS` does for guests (`crate::guest`). Playbooks
//! not listed are not limited here. Admins are never limited: the admin
//! pages poll the same playbooks.
//!
//! A refusal is the guests' `RATE_LIMITED` GraphQL error with `retryAfter`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::guest::{Limiter, RateLimited};

/// Per-hour limits of one playbook for signed-in users.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserPlaybookLimits {
    pub per_user: usize,
    pub total: usize,
}

pub struct UserLimits {
    pub limits: HashMap<String, UserPlaybookLimits>,
    limiter: Mutex<Limiter>,
}

impl UserLimits {
    /// `Ok(None)` when `GATEWAY_USER_PLAYBOOK_LIMITS` is unset or blank.
    pub fn from_env() -> anyhow::Result<Option<Arc<Self>>> {
        Self::from_spec(&std::env::var("GATEWAY_USER_PLAYBOOK_LIMITS").unwrap_or_default())
    }

    /// `path=per_user/total,...`; each path at most once.
    pub fn from_spec(spec: &str) -> anyhow::Result<Option<Arc<Self>>> {
        let mut limits = HashMap::new();
        for entry in crate::authorization::csv(spec) {
            let bad = || anyhow::anyhow!("GATEWAY_USER_PLAYBOOK_LIMITS: {entry:?} is not path=per_user/total");
            let (path, nums) = entry.split_once('=').ok_or_else(bad)?;
            let path = path.trim();
            if path.is_empty() {
                return Err(bad());
            }
            let n: Vec<usize> = nums
                .split('/')
                .map(|v| v.trim().parse::<usize>())
                .collect::<Result<_, _>>()
                .map_err(|_| bad())?;
            let [per_user, total] = n[..] else {
                return Err(bad());
            };
            if limits.insert(path.to_string(), UserPlaybookLimits { per_user, total }).is_some() {
                anyhow::bail!("GATEWAY_USER_PLAYBOOK_LIMITS: {path} is listed twice");
            }
        }
        if limits.is_empty() {
            return Ok(None);
        }
        Ok(Some(Arc::new(Self { limits, limiter: Mutex::new(Limiter::default()) })))
    }

    /// Admit one start of `playbook` by user `user_id` at `now`; playbooks
    /// without limits always pass.
    pub fn admit_at(&self, user_id: i32, playbook: &str, now: u64) -> Result<(), RateLimited> {
        let Some(l) = self.limits.get(playbook) else {
            return Ok(());
        };
        let keys = [
            (format!("user:{user_id}:{playbook}"), l.per_user),
            (format!("total:{playbook}"), l.total),
        ];
        let mut limiter = self.limiter.lock().unwrap_or_else(|e| e.into_inner());
        limiter.admit(&keys, now).map_err(RateLimited)
    }

    pub fn admit(&self, user_id: i32, playbook: &str) -> Result<(), RateLimited> {
        self.admit_at(user_id, playbook, crate::guest::now_secs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(spec: &str) -> Arc<UserLimits> {
        UserLimits::from_spec(spec).unwrap().unwrap()
    }

    #[test]
    fn off_when_unset() {
        assert!(UserLimits::from_spec("").unwrap().is_none());
        assert!(UserLimits::from_spec(" , ").unwrap().is_none());
    }

    #[test]
    fn parses_entries() {
        let l = limits(" site/inbox = 2/5 , site/form=1/9");
        assert_eq!(l.limits["site/inbox"], UserPlaybookLimits { per_user: 2, total: 5 });
        assert_eq!(l.limits["site/form"], UserPlaybookLimits { per_user: 1, total: 9 });
        assert_eq!(l.limits.len(), 2);
    }

    #[test]
    fn rejects_bad_entries() {
        for bad in ["site/inbox", "site/inbox=2", "site/inbox=2/3/4", "site/inbox=a/3", "=1/2", "site/inbox=-1/2"] {
            assert!(UserLimits::from_spec(bad).is_err(), "{bad} should be refused");
        }
        assert!(UserLimits::from_spec("a/b=1/2,a/b=3/4").is_err());
    }

    #[test]
    fn per_user_limit_then_window_frees() {
        let l = limits("a/b=2/100");
        assert!(l.admit_at(7, "a/b", 100).is_ok());
        assert!(l.admit_at(7, "a/b", 110).is_ok());
        assert_eq!(l.admit_at(7, "a/b", 120), Err(RateLimited(3600 - 20)));
        // another user has their own budget
        assert!(l.admit_at(8, "a/b", 120).is_ok());
        // a refused start does not count; after the hour the first slot frees
        assert!(l.admit_at(7, "a/b", 3700).is_ok());
        assert!(l.admit_at(7, "a/b", 3709).is_err());
    }

    #[test]
    fn total_limit_across_users() {
        let l = limits("a/b=5/2");
        assert!(l.admit_at(1, "a/b", 10).is_ok());
        assert!(l.admit_at(2, "a/b", 11).is_ok());
        assert_eq!(l.admit_at(3, "a/b", 12), Err(RateLimited(3600 - 2)));
    }

    #[test]
    fn unlisted_playbooks_pass_and_budgets_are_per_playbook() {
        let l = limits("a/b=1/1");
        for t in 0..50 {
            assert!(l.admit_at(1, "c/d", t).is_ok());
        }
        assert!(l.admit_at(1, "a/b", 60).is_ok());
        assert!(l.admit_at(1, "a/b", 61).is_err());
    }

    #[test]
    fn zero_refuses() {
        let l = limits("a/b=0/10");
        assert_eq!(l.admit_at(1, "a/b", 5), Err(RateLimited(3600)));
    }
}
