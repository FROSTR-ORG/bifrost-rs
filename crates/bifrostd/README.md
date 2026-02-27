# bifrostd

Headless Bifrost daemon target.

- Wraps `bifrost-node` + `bifrost-transport-ws`.
- Exposes local JSON-RPC over a Unix socket.
- Designed for service/process-manager operation.

Run:

```bash
cargo run -p bifrostd -- --config ./dev/data/daemon-alice.json
```
