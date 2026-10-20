# Guest sessions

Optional: lets signed-out visitors of a public site run a short, operator-chosen list of playbooks (for example a website assistant) through the normal GraphQL, SSE and polling flow, without an Auth0 login. Business data access stays in the playbooks; the gateway only authenticates, authorizes and rate-limits.

Off by default. A gateway with no guest configuration behaves exactly as before: `POST /api/auth/guest` is not mounted and a `ng1.` token is just an unknown session token.

## Configuration

| Env | Default | Meaning |
|---|---|---|
| `GATEWAY_GUEST_PLAYBOOKS` | unset | Comma-separated catalog paths a guest may execute. Unset or blank = guest mode off. |
| `GATEWAY_GUEST_TOKEN_KEY` | — | HMAC-SHA256 signing key, at least 32 bytes. Required when playbooks are set (the gateway refuses to start otherwise). Keep it in the deployment secret store. Rotating it ends every guest session. |
| `GATEWAY_GUEST_TTL_SECS` | 3600 | Guest session lifetime (minimum 60). |
| `GATEWAY_GUEST_RUNS_PER_HOUR` | 20 | Executions per guest session per rolling hour. |
| `GATEWAY_GUEST_IP_RUNS_PER_HOUR` | 60 | Guest executions per client IP per rolling hour. |
| `GATEWAY_GUEST_IP_SESSIONS_PER_HOUR` | 20 | Guest sessions minted per client IP per rolling hour. |
| `GATEWAY_GUEST_TOTAL_RUNS_PER_HOUR` | 600 | Ceiling on all guest executions per rolling hour. |
| `GATEWAY_CLIENT_IP_HEADER` | unset | Trusted header carrying the client IP (first entry of a list), e.g. `cf-connecting-ip`. Unset = the TCP peer address. |

Limits are kept in memory per gateway pod, so N replicas allow up to N times each limit. If the origin also accepts traffic that bypasses the proxy setting `GATEWAY_CLIENT_IP_HEADER`, that header can be forged; the per-guest and total limits still apply.

## Flow

1. `POST /api/auth/guest` (no body) → `{"status":"guest","session_token":"ng1....","guest_id":"<uuid>","expires_at":<unix secs>}`. Too many from one address → `429` with `Retry-After`.
2. Use `session_token` exactly like a signed-in session token: `Authorization: Bearer`, `x-session-token`, the `session_token` cookie, or `GET /events?session_token=...&client_id=...`.
3. `executePlaybook` accepts only `GATEWAY_GUEST_PLAYBOOKS` (kind `playbook`). Over a limit, the mutation fails with `extensions.code = "RATE_LIMITED"` and `extensions.retryAfter` (seconds).
4. Poll `GET /noetl/executions/{id}` or cancel with `POST /noetl/executions/{id}/cancel`, for executions this guest session started only (owned by its guest id). Everything else is `403`/`404`.

The token is `ng1.<base64url {gid, exp}>.<base64url HMAC>`. Nothing is stored server side; the gateway verifies it locally and never sends it to the session cache or the NoETL auth API.

## What a guest is

A `UserContext` with `user_id = 0`, empty email, no `auth0_sub`, no roles and `guest = {id, ip}`:

- never admin, even under `GATEWAY_AUTH_BYPASS`;
- not on the regular-user allowlist (`GATEWAY_USER_PLAYBOOKS`), only on the guest list;
- identity binding (`crate::identity`) still fails closed: a guest passing a non-null `uid` or `user_uid` is refused, an explicit `null` is anonymous. Playbooks run for guests must not rely on a per-user identity.

Scoped-application mode (`docs/scoped-applications.md`) never mounts the guest route.

## Tests

`cargo test --locked`: unit tests in `src/guest.rs` and `src/authorization.rs`, end to end through the real middleware, GraphQL and proxy in `src/guest_routes_tests.rs`. Spec: noetl/ai-meta `specs/active/2026-10-19-gateway-guest-sessions`.
