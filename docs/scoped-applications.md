# Scoped application actions

An optional restricted gateway mode exposes approved application workflows without giving signed-in users a generic NoETL proxy. This is a gatekeeping/transport feature; business data access remains in NoETL playbooks.

`GATEWAY_SCOPED_APPS_FILE` points to operator-controlled JSON:

```json
{"bindings":{"7":{"reservations":"101","availability":"102"}}}
```

Keys are positive validated gateway user IDs; action names contain lowercase letters/digits/underscores; values are immutable catalog IDs represented as decimal strings. Require `NOETL_INTERNAL_API_TOKEN` and a random `GATEWAY_SCOPED_RECEIPT_KEY` of at least 32 bytes in the deployment secret mechanism. Auth bypass is forbidden. Changing a mapping requires restarting this gateway instance.

- `POST /api/scoped/{action}` accepts only `{"request":{...}}`. The action/catalog mapping comes from the validated session, not the request. Returns decimal-string execution ID and signed receipt.
- `POST /api/scoped/{action}/result` accepts only `{"receipt":"..."}`. The receipt expires after one hour and binds the current session/user/action/catalog/execution. Returns status and projected business rows only; upstream errors, SQL, workload and events are never forwarded.

The current contract supports reviewed one-step PostgreSQL playbooks whose `start` step emits `rows[].result` JSON objects. Missing/mismatched result shape fails closed. Catalog bindings must reference fixed provider-specific credentials, never a shared mutable alias. Operators must prohibit catalog mutation for application callers.

Setting scoped configuration omits generic proxy, GraphQL, SSE and push-ingress routers. Existing routes are unchanged when unset. Deploy a separate restricted instance for this application. Public auth routes and internal callbacks remain available to support the existing session flow; external ingress must expose only the intended auth and scoped paths and restrict callbacks/operator/upstream endpoints. This change relies on the existing session validator and its issuer/revocation/cache configuration. It does not upgrade or bypass that authentication backend. TLS and allowed-origin configuration remain required deployment concerns. Single upstream base URL only; sharded result routing is not implemented.

Tests: `cargo test --locked`. The ignored `real_runtime_scoped_actions` test runs against the isolated NoETL stack prepared by `noetl/travel/adiona/tests/front-desk-runtime.mjs`; it uses real workflow/database execution but injects a synthetic validated identity at the HTTP test boundary. It is not an OIDC authentication test. The travel front-desk guide documents setup, mapping and deployment limits.
