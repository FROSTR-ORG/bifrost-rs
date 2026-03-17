# Architecture

## Crate Responsibilities

## `bifrost-core`

- Core threshold signing/session/nonce/ECDH domain types.
- Deterministic group/session identity and integrity validation.
- Nonce lifecycle safety controls.

## `bifrost-codec`

- Wire structs and strict payload validation.
- Bridge envelope and payload encoding/decoding.
- Parsing helpers for group/share/session/onboarding data.

## `frostr-utils`

- Keyset lifecycle utilities: create, verify, rotate, recover.
- Onboarding package encode/decode helpers.

## `bifrost-signer`

- Signing-device state machine.
- Cryptographic operations: partial signing, aggregation finalization, ECDH combine.
- NIP-44 envelope decryption/encryption for peer events.
- Peer policy enforcement, replay/TTL checks, nonce pool integration.
- Outbound event construction with strict single-recipient `p` tags.

## `bifrost-router`

- Runtime-agnostic router core (`BridgeCore`) for command/event queueing.
- Inbound recipient routing enforcement (`exactly one p`, local-recipient only).
- Inbound event deduplication and overflow handling.
- Outbound event draining and signer completion/failure propagation.
- Persistence-hint emission (`none`/`batch`/`immediate`) for host runtimes.

## `bifrost-bridge-tokio`

- Tokio runtime boundary between router and transport adapter.
- Subscription/publish loop orchestration via router-exported filters/events.
- Pass-through transport adapter (no duplicate routing policy logic outside router/signer).
- Command dispatch (`sign`, `ecdh`, `ping`, `onboard`) and completion routing.

## Shell boundary

- `bifrost-rs` exports `bifrost_app::host` as the reusable host/listen/control layer.
- Runnable shell binaries now live in `repos/igloo-shell`.
- `igloo-shell` owns operator CLI/TUI/invite orchestration on top of the shared host layer.
- `bifrost-devtools` owns developer relay/keygen/e2e orchestration.
- `execute_command(...)` is the typed host executor; `run_command(...)` is the thin stdout wrapper for shell binaries.

## Hosted Runtime Contract

`bifrost-rs` is the signer authority for hosted clients such as browser extensions.

Canonical host-facing APIs:
- `runtime_status()`: aggregated runtime/readiness/metadata/pending-op read model.
- `drain_runtime_events()`: incremental runtime-status notifications for command/config/policy/inbound/state changes.
- `prepare_sign()`: operation-prep path for threshold signing.
- `prepare_ecdh()`: operation-prep path for collaborative ECDH.
- `wipe_state()`: canonical runtime reset and signer-state wipe path.

Host applications should not infer readiness from snapshot internals, nonce inventory, or transport-side heuristics. Snapshots exist for persistence and debugging, not as the main host-state contract. `runtime_status()` is the normal aggregated host read model; `readiness()` is the narrower capability view.

## Key Data Flow: Sign

1. Caller invokes a shell client such as `igloo-shell sign <message_hex32>`.
2. Bridge starts adapter session and subscribes to peer authors plus local recipient `#p`.
3. Signer creates a sign request, encrypts envelope, and emits events.
4. Peers process encrypted requests and return encrypted partials.
5. Signer enforces locked responder semantics: all selected locked peers must return valid responses.
6. Signer verifies/aggregates signatures and returns final result.

## Key Data Flow: ECDH

1. Caller invokes a shell client such as `igloo-shell ecdh <pubkey_hex32>`.
2. Signer creates local ECDH package and requests peer shares.
3. Signer enforces locked responder semantics for the selected peer set.
4. Signer validates responses and combines final shared secret.
5. Result is returned directly to caller.

## Security-Critical Boundaries

- Sender/member binding checks.
- Replay and TTL enforcement.
- Nonce one-time usage controls.
- Strict payload bounds at codec boundary.
- Encrypted bridge payloads carried as opaque relay content.
- Recipient routing enforced by strict single-`p` tag checks before payload processing.
- Hosted clients consume signer-owned readiness and peer capability, not client-derived approximations.
