# NoETL Gateway (`noetl-gateway`)

Rust API gateway for authenticated access to NoETL services. Gateway authenticates callers and forwards canonical NoETL API requests; it does not execute tools or call MCP servers itself.

## Distribution Channels

- **Crates.io**: `noetl-gateway`
- **Container image**: recommended primary runtime channel (GHCR/GCR)
- **Cloud Build**: recommended for image builds and GKE deploy pipelines

## Release Checklist

1. Bump `version` in `Cargo.toml`.
2. Build and verify:
   - `cargo build --release`
3. Publish crate:
   - `cargo publish`
4. Build and push container image (`gateway`).
5. Deploy and verify:
   - `/health` endpoint returns `200`
  - upstream proxy routes function with valid auth/session.
  - `/api/runtime/contract` reports the current `/noetl/*` execution contract.

## Notes

- Gateway is externally exposed, so deploy checks must include service type/load balancer validation.

## CLI Context and Registration Path

Use the CLI with a gateway context when you want to register credentials/playbooks without direct API port-forwarding.

1. Configure a gateway context:
```bash
noetl context add gateway-prod \
  --server-url https://gateway.mestumre.dev \
  --runtime distributed \
  --auth0-domain mestumre-development.us.auth0.com \
  --set-current
```

2. Exchange Auth0 token for gateway session token:
```bash
noetl auth login --auth0-callback-url 'https://mestumre.dev/login#id_token=...'
```

3. Register resources via gateway protected proxy:
```bash
noetl --gateway catalog register tests/fixtures/credentials/pg_k8s.json
noetl --gateway catalog register tests/fixtures/playbooks/api_integration/auth0/provision_auth_schema.yaml
```

4. Validate through gateway:
```bash
noetl --gateway catalog list Credential --json
noetl --gateway catalog list Playbook --json
```

Gateway endpoints involved:
- `POST /api/auth/login` for token exchange
- `GET /api/runtime/contract` for current gateway runtime/proxy contract
- `POST /noetl/catalog/register` for resource registration

## Agent and MCP Path

For MCP-backed operations, clients should execute NoETL agent playbooks through Gateway:

```bash
curl -X POST https://gateway.example.com/noetl/execute \
  -H "Authorization: Bearer $NOETL_SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "automation/agents/kubernetes/runtime",
    "workload": {
      "method": "tools/call",
      "tool": "pods_list_in_namespace",
      "arguments": { "namespace": "noetl" }
    },
    "resource_kind": "agent"
  }'
```

The NoETL worker owns the MCP call via `kind: mcp`, so activity is visible in execution detail, events, and reruns.
The typed GraphQL `executePlaybook` mutation accepts `resourceKind`; pass `agent` for catalog entries registered as agent playbooks.

References:
- https://noetl.dev/docs/reference/noetl_cli_usage
- https://noetl.dev/docs/cli/
- https://noetl.dev/docs/gateway/
