# Interface Tracking

This document tracks public API surface changes and compatibility decisions.

Compatibility labels:
- `exact`: mirrors TS externally.
- `compatible`: semantically equivalent with Rust-idiomatic shape.
- `intentional_deviation`: deliberate behavior/API difference with rationale.

## `bifrost-core`

### Current API
- Group/session helpers: `get_group_id`, `create_session_package`, `verify_session_package`.
- Signing helpers: `create_partial_sig_package`, `verify_partial_sig_package`, `combine_signatures`.
- Nonce pool: `NoncePool` with generation/storage/consumption.
- ECDH helpers: `create_ecdh_package`, `combine_ecdh_packages`.

### Target API
- Maintain stable core helpers.
- Add explicit batch-sign API with nonce safety invariants.
- Add clear typed errors for all reject paths used by node/transport.

### Compatibility Notes
- Current single-hash signing enforcement is temporary and intentional for nonce safety.
- TS deterministic nonce derivation model differs internally; Rust uses stored FROST signing nonces.

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
- Basic single-relay connect/request/cast/response flow.

### Target API
- Multi-relay support, reconnect with backoff, failover strategy, robust pending-request cleanup.

### Compatibility Notes
- External behavior should match TS operationally, but internal scheduling/state machine may differ.

## `bifrost-node`

### Current API
- Lifecycle: `connect`, `close`.
- Operations: `echo`, `ping`, `onboard`, `sign`, `ecdh`.
- Incoming processing: `handle_next_incoming`, `process_next_incoming`, `handle_incoming`.

### Target API
- Add optional batch queue APIs for sign/ECDH.
- Add event stream/emitter parity hooks.
- Add middleware/security-policy extension points.

### Compatibility Notes
- Maintain operation semantics; add strict validation for sender binding, payload limits, replay protection.

## Change Management Rule

For every public API change:
1. Update this document with `current`/`target` delta.
2. Update affected rows in `02-parity-matrix.md`.
3. Add acceptance evidence in `06-test-strategy.md`.
