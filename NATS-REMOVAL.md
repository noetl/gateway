# NATS removal — operator notes (gateway)

The NATS code is gone (noetl/ai-meta#212).

**Two env vars are now required; an empty value is a startup error, not a
fallback.** There is nothing left to fall back to, and the failure mode of a
gateway that starts anyway is an SPA that receives nothing with no error
anywhere:

- `NOETL_EVENT_FEED_ADDR` — the events writer's SSE face (`…:9105`).
- `NOETL_KV_ADDR` — the events writer's KV face (`…:9107`). This backs the
  request store, which routes **every** SSE message.

Config renamed `NatsConfig` → `KvConfig`: its bucket names and TTLs were always
EHDB KV settings, not NATS ones. Env overrides follow
(`NATS_SESSION_BUCKET` → `NOETL_KV_SESSION_BUCKET`, etc.); defaults are
unchanged, so a deployment that never set them is unaffected.
