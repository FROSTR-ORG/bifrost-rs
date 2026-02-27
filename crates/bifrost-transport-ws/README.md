# bifrost-transport-ws

WebSocket transport implementation for Bifrost Rust.

## Includes
- Nostr-native relay framing (`REQ`/`EVENT`/`CLOSE`) with signed events and RPC correlation.
- NIP-44-v2-compatible encrypted event content for peer RPC payloads.
- Connection state machine (`ConnectionState`).
- Configurable reconnect/backoff + RPC kind (`WsTransportConfig`).
- Nostr identity config (`WsNostrConfig`) for sender key material and peer author filters.
- Relay health tracking and health-ranked failover.
- Concurrent cast threshold stabilization with deterministic quorum-unreachable detection.

## Status
- Core WS hardening items implemented.
- Forced network-fault integration coverage remains as follow-up hardening work.

## Verify
- `cargo test -p bifrost-transport-ws --offline`
- Includes NIP-44 reference-vector assertions for conversation key and payload encrypt/decrypt.
- Fixture corpus lives at `crates/bifrost-transport-ws/tests/nip44_vectors.json`.
- Includes deterministic multi-length/unicode matrix tests and mutation/wrong-key negative cases.
