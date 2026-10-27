# Per-playbook limits for signed-in users

Off unless `GATEWAY_USER_PLAYBOOK_LIMITS` is set (`src/user_limits.rs`).

| Variable | Default | Meaning |
|---|---|---|
| `GATEWAY_USER_PLAYBOOK_LIMITS` | unset | `path=per_user/total,...`: how often one signed-in user, and all signed-in users together, may start each listed playbook per rolling hour. Unlisted playbooks are not limited here. Each path at most once; anything malformed refuses to start. |

- Checked in `executePlaybook` after authorization (the playbook must still be
  on `GATEWAY_USER_PLAYBOOKS` or an app list), next to the guest limits.
- Admins are never limited (the admin pages poll the same playbooks); guests
  keep their own limits (`docs/guest-sessions.md`).
- A refusal is a GraphQL error with `code: RATE_LIMITED` and `retryAfter`
  (seconds), like a guest's; the start never reaches NoETL.
- Limits are kept in memory per gateway pod, so N replicas allow up to N times
  each limit.

Example (mountshastaranch.com: reply polling, the message form and "my
conversations" for signed-in guests):

```
GATEWAY_USER_PLAYBOOK_LIMITS=shastaranch/chats/inbox=40/1200,shastaranch/chats/mine=20/400,shastaranch/contact/submit=10/200
```

## Tests

`cargo test --locked user_limits`: unit tests in `src/user_limits.rs`, end to
end through the real GraphQL handler in `src/user_limits_routes_tests.rs`.
