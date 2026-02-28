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
- Nonce pool: `NoncePool` with generation/storage/consumption including atomic multi-claim (`take_outgoing_signing_nonces_many`).
- ECDH helpers: `create_ecdh_package`, `combine_ecdh_packages`.
- Utility helpers: `validate` module (`decode_hex32/33`, `decode_sig64`, fixed-size validators) and `sighash` module (`message_sighash`, `bind_sighash`).

### Target API
- Maintain stable core helpers.
- Add explicit batch-sign API with nonce safety invariants.
- Add clear typed errors for all reject paths used by node/transport.
- Add nonce claim/finalize lifecycle APIs as specified in `09-batch-sign-nonce-model.md`.

### Compatibility Notes
- TS deterministic nonce derivation model differs internally; Rust uses stored FROST signing nonces.
- Batch signing now follows Option-A-only single-session multi-hash flow with indexed nonce/signature binding.

## `bifrost-codec`

### Current API
- `rpc` envelope encoding/decoding.
- `wire` type conversions between core and transport data.
- `package` helper APIs for group/share package JSON encode/decode.

### Target API
- Strict schema-compatible payload validation.
- Parser helpers mirroring TS parse entrypoints for node handler readability.

### Compatibility Notes
- Compatible behavior target; wire format must remain externally stable.

## `frostr-utils`

### Current API
- Keyset lifecycle helpers: `create_keyset`, `verify_keyset`, `rotate_keyset_dealer`, `recover_key`.
- Group/share verification helpers: `verify_group_config`, `verify_share`.
- Onboarding package helpers for minimal bootstrap payload:
- bech32m encode/decode with `bfonboard` prefix
- binary serialize/deserialize for `share + peer_pk + relays`
- Stateless protocol helpers:
- signing: `validate_sign_session`, `sign_create_partial`, `sign_verify_partial`, `sign_finalize`
- ECDH: `ecdh_create_from_share`, `ecdh_finalize`

### Target API
- Keep utility scope focused on integration and tooling (not runtime orchestration).
- Preserve minimal onboarding package shape for phone-home bootstrap parity with TS.

### Compatibility Notes
- Intentional Rust-first utility surface; this is additive and does not change runtime protocol semantics.
- `bifrost-node` now builds sign/ECDH cryptographic operations on top of these stateless helpers while keeping nonce pool, transport, and peer-policy orchestration stateful in node runtime.

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
- Granular per-peer policy controls: `block_all` plus method-level `request/respond` permissions (`echo`, `ping`, `onboard`, `sign`, `ecdh`), runtime mutation (`get/set/list`), inbound respond-policy enforcement, and ping-scoped remote policy profile cache.
- ECDH cache controls in options: `ecdh_cache_ttl_secs`, `ecdh_cache_max_entries`.
- Event stream API: `subscribe_events()` with lifecycle/message/bounced/info/error emission points.
- Peer nonce telemetry API: `peer_nonce_health(peer_pubkey)` exposing per-peer incoming/outgoing/spent nonce counts and sign/send readiness flags.
- Facade APIs: `NodeClient`, `Signer`, `NoncePoolView`.
- Middleware hook surface: `NodeMiddleware::{before_request,after_request}`.

### Target API
- Add optional batch queue APIs for sign/ECDH.
- Add event stream/emitter parity hooks.
- Add middleware/security-policy extension points.

### Compatibility Notes
- Maintain operation semantics with strict validation for sender binding, payload limits, replay protection.
- `sign_batch` now executes Option-A-only single-session indexed multi-hash orchestration.
- sign/ECDH cryptographic operations are delegated through `frostr-utils::protocol` stateless APIs; node retains runtime state/policy responsibilities.

## `bifrost-rpc`

### Current API
- Local JSON request/response envelopes:
- `RpcRequestEnvelope { id, request }`
- `RpcResponseEnvelope { id, response }`
- Request set: `Health`, `Status`, `Events`, `Echo`, `Ping`, `Onboard`, `Sign`, `Ecdh`, `Shutdown`.
- Request set additionally includes peer-policy admin: `GetPeerPolicies`, `GetPeerPolicy`, `SetPeerPolicy`, `RefreshPeerPolicy`.
- Client helpers: `send_request_to`, `send_request`, `DaemonClient`.
- `Status` response includes nonce telemetry for operator UX:
- global pool thresholds (`nonce_pool_size`, `nonce_pool_min_threshold`, `nonce_pool_critical_threshold`)
- per-peer nonce fields (`member_idx`, incoming/outgoing/spent counts, `nonce_can_sign`, `nonce_should_send`).
- per-peer policy fields (`block_all`, method-level `request/respond`).

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
- `bifrost-tui`: interactive `ratatui`/`crossterm` dashboard over the same RPC methods (status/events/output/input panes), with peer selector resolution (`index` / alias / pubkey-prefix), session target selection (`use <peer>`), text-first sign hashing (`sign <text...>`), alias-first `ecdh <peer>`, echo shorthand (`echo <message...>` via active target), and tail-follow rendering for status/events/output.

### Target API
- `bifrost-cli`: stable machine output for automation and batch workflows.
- `bifrost-tui`: richer dashboard panes + live event stream and key workflow shortcuts.

### Compatibility Notes
- Compatible with TS demo operational intent, but routed through daemon RPC instead of direct node ownership.

## `bifrost-devtools`

### Current API
- Consolidated development tools binary with subcommands:
- `relay`: local Nostr relay (`REQ` / `EVENT` / `CLOSE`, cache replay + `EOSE`, filter matching, BIP-340 event validation)
- `keygen`: local key/config generator (`group.json`, `share-*.json`, `daemon-*.json`) using `frostr-utils` keyset helpers

### Target API
- Add richer test hooks (fault injection, deterministic clocks/cache, relay stats endpoint).
- Keep shell-script orchestration (`scripts/devnet*.sh`) as stable companion around subcommands.

### Compatibility Notes
- Compatible relay/keygen behavior with intentional Rust ergonomics improvement via unified devtools binary.

## Change Management Rule

For every public API change:
1. Update this document with `current`/`target` delta.
2. Update affected rows in `02-parity-matrix.md`.
3. Add acceptance evidence in `06-test-strategy.md`.
