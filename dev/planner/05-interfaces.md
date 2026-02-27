# Interface Tracking

This document tracks public API surface changes and compatibility decisions.

Compatibility labels:
- `exact`: mirrors TS externally.
- `compatible`: semantically equivalent with Rust-idiomatic shape.
- `intentional_deviation`: deliberate behavior/API difference with rationale.

## `bifrost-core`

### Current API
- Group/session helpers: `get_group_id`, `create_session_package`, `verify_session_package`.
- Signing helpers: `create_partial_sig_package`, `verify_partial_sig_package`, `combine_signatures`, `create_partial_sig_packages_batch`, `combine_signatures_batch`.
- Nonce pool: `NoncePool` with generation/storage/consumption.
- ECDH helpers: `create_ecdh_package`, `combine_ecdh_packages`.

### Target API
- Maintain stable core helpers.
- Add explicit batch-sign API with nonce safety invariants.
- Add clear typed errors for all reject paths used by node/transport.
- Add nonce claim/finalize lifecycle APIs as specified in `09-batch-sign-nonce-model.md`.

### Compatibility Notes
- Current single-hash signing enforcement is temporary and intentional for nonce safety.
- TS deterministic nonce derivation model differs internally; Rust uses stored FROST signing nonces.
- Batch-sign rollout follows the model in `09-batch-sign-nonce-model.md` with Option-B-safe core batch APIs implemented; Option-A single-session multi-hash remains deferred.

## `bifrost-codec`

### Current API
- `rpc` envelope encoding/decoding.
- `wire` type conversions between core and transport data.

### Target API
- Strict schema-compatible payload validation.
- Parser helpers mirroring TS parse entrypoints for node handler readability.

### Compatibility Notes
- Compatible behavior target; wire format must remain externally stable.

## `bifrost-transport`

### Current API
- Trait-based transport with `request`, `cast`, `send_response`, `next_incoming`.

### Target API
- Preserve trait shape while defining stronger behavior contracts:
- timeout semantics
- threshold semantics
- cancellation/shutdown semantics.

### Compatibility Notes
- Rust trait abstraction is intentional deviation from TS class internals.

## `bifrost-transport-ws`

### Current API
- Connect/request/cast/response flow with `ConnectionState` visibility, `WsTransportConfig` retry/backoff controls (`rpc_kind` included), Nostr identity config (`WsNostrConfig`), and relay-health inspection (`active_relay`, `relay_health_snapshot`).
- Runtime framing is Nostr-native (`REQ` subscribe + signed `EVENT` publish + `CLOSE`) with request correlation against decoded RPC envelopes.
- Event payload content is encrypted in transport with NIP-44-v2-compatible processing (secp256k1 ECDH shared X, HKDF extract/expand key schedule, NIP-44 padding, ChaCha20 stream cipher, HMAC-SHA256 AAD over nonce+ciphertext, versioned base64url payload) with sender tag binding.

### Target API
- Multi-relay support, reconnect with backoff, failover strategy, robust pending-request cleanup.

### Compatibility Notes
- External behavior should match TS operationally, but internal scheduling/state machine may differ.
- Reconnect/backoff state transitions, multi-relay health-ranked failover, and concurrent cast/request threshold stabilization are implemented.
- Payload encryption now follows NIP-44-v2-compatible structure in transport; remaining hardening is broader interop vector-depth and operational robustness.

## `bifrost-node`

### Current API
- Lifecycle: `connect`, `close`.
- Operations: `echo`, `ping`, `onboard`, `sign`, `ecdh`.
- Incoming processing: `handle_next_incoming`, `process_next_incoming`, `handle_incoming`.
- Batch APIs: `sign_batch(&[[u8;32]])`, `sign_queue(&[[u8;32]])`, `ecdh_batch(&[[u8;33]])`.
- Security controls in options: replay/staleness (`request_ttl_secs`, `request_cache_limit`) and payload caps (`max_request_id_len`, `max_sender_len`, `max_echo_len`, `max_sign_content_len`).
- ECDH cache controls in options: `ecdh_cache_ttl_secs`, `ecdh_cache_max_entries`.
- Event stream API: `subscribe_events()` with lifecycle/message/bounced/info/error emission points.
- Peer nonce telemetry API: `peer_nonce_health(peer_pubkey)` exposing per-peer incoming/outgoing/spent nonce counts and sign/send readiness flags.

### Target API
- Add optional batch queue APIs for sign/ECDH.
- Add event stream/emitter parity hooks.
- Add middleware/security-policy extension points.

### Compatibility Notes
- Maintain operation semantics; add strict validation for sender binding, payload limits, replay protection.
- Current batch-sign implementation uses Option B fallback from `09-batch-sign-nonce-model.md`.

## `bifrost-rpc`

### Current API
- Local JSON request/response envelopes:
- `RpcRequestEnvelope { id, request }`
- `RpcResponseEnvelope { id, response }`
- Request set: `Health`, `Status`, `Events`, `Echo`, `Ping`, `Onboard`, `Sign`, `Ecdh`, `Shutdown`.
- Client helpers: `send_request_to`, `send_request`.
- `Status` response includes nonce telemetry for operator UX:
- global pool thresholds (`nonce_pool_size`, `nonce_pool_min_threshold`, `nonce_pool_critical_threshold`)
- per-peer nonce fields (`member_idx`, incoming/outgoing/spent counts, `nonce_can_sign`, `nonce_should_send`).

### Target API
- Stabilize schema/versioning (`rpc_version`) and error taxonomy.
- Add optional authenticated local channels.

### Compatibility Notes
- Intentional Rust-first API; this is new surface and not a TS class parity requirement.

## `bifrostd`

### Current API
- Binary daemon exposing local unix-socket RPC and wrapping `bifrost-node` + `bifrost-transport-ws`.
- Config-driven startup (`--config` path to JSON).

### Target API
- Add structured logging, supervised lifecycle hooks, and stronger shutdown semantics.
- Add event streaming endpoint suitable for rich TUI panels.

### Compatibility Notes
- Intentional deviation: TS demo ran node logic in-process; Rust split introduces headless daemon boundary.

## `bifrost-cli` / `bifrost-tui`

### Current API
- `bifrost-cli`: command-oriented RPC client for scripts/agents.
- `bifrost-tui`: interactive `ratatui`/`crossterm` dashboard over the same RPC methods (status/events/output/input panes), with peer selector resolution (`index` / alias / pubkey-prefix) and tail-follow rendering for status/events/output.

### Target API
- `bifrost-cli`: stable machine output for automation and batch workflows.
- `bifrost-tui`: richer dashboard panes + live event stream and key workflow shortcuts.

### Compatibility Notes
- Compatible with TS demo operational intent, but routed through daemon RPC instead of direct node ownership.

## `bifrost-relay-dev`

### Current API
- Local Nostr relay binary with `REQ` / `EVENT` / `CLOSE`, cache replay + `EOSE`, filter matching, and BIP-340 event validation.

### Target API
- Add richer test hooks (fault injection, deterministic clocks/cache, relay stats endpoint).

### Compatibility Notes
- Compatible port of the TS demo relay behavior with Rust internals.

## `bifrost-devnet`

### Current API
- Binary utility command: `keygen`.
- Generates `group.json`, `share-*.json`, and `daemon-*.json` for local daemon clusters.

### Target API
- Add orchestration subcommands (`start`, `stop`, `smoke`) or keep shell-script orchestration as stable companion.

### Compatibility Notes
- Intentional addition for Rust workflow ergonomics; TS demo used separate scripts for keygen/orchestration.

## Change Management Rule

For every public API change:
1. Update this document with `current`/`target` delta.
2. Update affected rows in `02-parity-matrix.md`.
3. Add acceptance evidence in `06-test-strategy.md`.
