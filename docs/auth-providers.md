# Auth providers

*Spec: noetl/ai-meta `specs/active/2026-10-21-gateway-auth-providers`.*

Opt-in, pluggable sign-in: each **auth provider** is a playbook that proves who
the caller is (an emailed one-time code, Google, Apple, …) and returns only a
verified identity. The gateway turns that identity into an ordinary session,
created by the server, and returns the token in its HTTP response. Sessions are
validated and authorized like any other. Off unless `GATEWAY_AUTH_PROVIDERS`
is set; without it nothing changes (`/api/auth/providers/*` isn't mounted).
Scoped-app mode never mounts it. Auth0 login (`/api/auth/login`) is unchanged.

Code: [`src/auth_providers.rs`](../src/auth_providers.rs) (config, route,
result contract, logout), per-app rules in
[`src/authorization.rs`](../src/authorization.rs), the mint call in
[`src/noetl_client.rs`](../src/noetl_client.rs). Server side:
`POST /api/auth/provider-session` and `POST /api/auth/logout`
(noetl/server `src/handlers/auth_provider.rs`).

## Flow

```
browser ──POST /api/auth/providers/{provider}/{action} {input}──▶ gateway
            (configured provider + declared action, JSON object ≤ 4 KB,
             per-IP and per-key_field limits → 429 + Retry-After)
gateway ──POST /api/execute {action, input, provider, client_ip, user_agent}──▶ server
gateway ──GET /api/executions/{id} (poll) ──▶ server   result = call.done of `result_step`
  pending       → 200 {status:"pending", message, data}
  denied        → 401 {status:"denied", message}
  authenticated → gateway ──POST /api/auth/provider-session (X-NoETL-Auth-Mint)──▶ server
                  ◀─ {session_token, user, expires_at}   (cached like a login)
                → 200 {status:"authenticated", session_token, user, expires_at}
  anything else / failed / timeout → 502, no session
```

The result is read from the server's execution record, not from
`/api/internal/callback`: that route is public, so an identity delivered
through it could be forged by anyone who learned the request id.

## Result contract

The provider playbook's `result` step (configurable) returns exactly one of:

```json
{"status": "pending", "message": "We emailed a code", "data": {"resend_in": 30}}
{"status": "denied", "message": "That code is wrong or expired"}
{"status": "authenticated", "identity": {"subject": "…", "email": "…", "email_verified": true, "name": "…", "picture": "…"}}
```

Any other field is a contract violation (502). `data` is an object ≤ 2 KB.
`subject` is the provider's stable id for the person (≤ 200 chars); the
server refuses an unverified email. Never put a code, key or token in the
result: results are kept in execution history.

## Configuration

| Env | Meaning |
|---|---|
| `GATEWAY_AUTH_PROVIDERS` | JSON `{provider: {playbook, actions, app, session_hours?, result_step?, timeout_secs?, limits?}}`. Provider names 2-32 chars `a-z0-9-`; actions 1-32 chars `a-z0-9_`; `session_hours` 1-2160 (default 24); `result_step` default `result`; `timeout_secs` 1-120 (default 30); `limits: {ip_per_hour (30), key_field, key_per_hour (10)}`. Unknown fields are a startup error. |
| `NOETL_AUTH_MINT_KEY` / `_FILE` | ≥ 32 bytes; the same value on the server. Required when providers are set. Only the gateway and the server hold it. |
| `GATEWAY_APP_USER_PLAYBOOKS` | JSON `{app: [playbook, …]}`: what each app's users may start. |
| `GATEWAY_CLIENT_IP_HEADER` | Trusted client-IP header (shared with guest sessions). |

Example:

```json
{
  "msr-email":  {"playbook": "shastaranch/auth/email_code", "actions": ["start", "verify"], "app": "mountshastaranch", "session_hours": 720, "limits": {"key_field": "email", "key_per_hour": 5}},
  "msr-google": {"playbook": "shastaranch/auth/google", "actions": ["callback"], "app": "mountshastaranch", "session_hours": 720}
}
```

## Identity and authorization

- The user key is `ap:<provider>|<subject>` (`auth.users.auth0_id`). Auth0
  subjects are `strategy|id` with no `:`, so they can't collide. `uid` /
  `user_uid` binding works as for Auth0 users.
- `auth.users.email` is unique: an email already used by another account is
  refused (`email_in_use`), never merged. Separate sign-in methods are
  separate accounts.
- A provider user belongs to its provider's `app`. Unless admin it may start
  only that app's `GATEWAY_APP_USER_PLAYBOOKS` (plus the guest playbooks),
  never the global `GATEWAY_USER_PLAYBOOKS`. A provider user whose provider is
  no longer configured may start nothing. Roles stay manual in
  `auth.user_roles`; provider users start with none.

## Logout

`POST /api/auth/logout` with the session as `Authorization: Bearer` (or
`X-Session-Token`): the server deactivates it and the gateway evicts it from
the session cache. Any session kind; a guest token just returns 200.

## Limits

In memory, per pod, per rolling hour (`crate::guest`'s limiter): per client
IP per provider, and per value of `key_field` (lowercased). Over a limit:
`429` + `Retry-After`; the playbook doesn't run.
