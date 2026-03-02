# NoETL Gateway (`noetl-gateway`)

GraphQL/API gateway for authenticated access to NoETL services.

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

## Notes

- Gateway is externally exposed, so deploy checks must include service type/load balancer validation.
