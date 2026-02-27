# bifrost-rpc

Shared local RPC schema and client helpers for `bifrostd`, `bifrost-cli`, and `bifrost-tui`.

- Transport: newline-delimited JSON over Unix sockets.
- Envelope: `RpcRequestEnvelope` / `RpcResponseEnvelope`.
- Methods: health/status/events/echo/ping/onboard/sign/ecdh/shutdown.
