# bifrostd

Headless Bifrost daemon target.

- Wraps `bifrost-node` + `bifrost-transport-ws`.
- Exposes local JSON-RPC over a Unix socket.
- Designed for service/process-manager operation.

Run:

```bash
cargo run -p bifrostd -- --config ./dev/data/daemon-alice.json
```

Config notes:

- `auth.token`: required unless `auth.insecure_no_auth=true` is explicitly set for local development.
- `auth.allow_unauthenticated_read` (default `false`): allows unauthenticated `negotiate`/`health`/`status`/`events` when `auth.token` is set.
- `auth.insecure_no_auth` (default `false`): explicit dev-only bypass that disables auth checks when no token is configured.
- RPC version compatibility is enforced via `rpc_version` and can be queried with `method=Negotiate`.
- RPC input framing is bounded to `64 KiB` per request line.
