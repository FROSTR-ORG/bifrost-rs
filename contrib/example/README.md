# node_ws_multi_peer_example

Reference package for a multi-peer node + websocket transport setup.

## What it does
- Builds a 2-of-2 FROST key set at runtime.
- Constructs a `BifrostNode` with `WebSocketTransport`.
- Demonstrates transport config (`WsTransportConfig`) and node initialization.
- Optionally performs real `connect`/`close` against a relay.

## Run
- Dry run (offline-safe):
  - `cargo run --manifest-path contrib/example/Cargo.toml`
- Network connect demo:
  - `RELAY_URL=wss://relay.damus.io RUN_NETWORK=1 cargo run --manifest-path contrib/example/Cargo.toml`
