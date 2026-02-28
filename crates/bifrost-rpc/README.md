# bifrost-rpc

Shared local RPC schema and client helpers for `bifrostd`, `bifrost-cli`, and `bifrost-tui`.

- Transport: newline-delimited JSON over Unix sockets.
- Envelope: `RpcRequestEnvelope` / `RpcResponseEnvelope`.
- Envelope fields include:
  - `rpc_version` (defaults to `1`)
  - `auth_token` (optional; sourced from `BIFROST_RPC_TOKEN` by client helper)
- Methods: negotiate/health/status/events/echo/ping/onboard/sign/ecdh/shutdown.
- High-level app client: `DaemonClient` for CLI/TUI-style request workflows.
