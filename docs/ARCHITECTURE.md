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

## Runtime binaries

- `bifrost`: command-line entrypoint that loads config/state and executes operations.
- `bifrost-tui`: status/policy dashboard on top of bridge runtime.
- `bifrost-devtools`: local relay and key/config generation tooling.

## Key Data Flow: Sign

1. Caller invokes `bifrost ... sign <message_hex32>`.
2. Bridge starts adapter session and subscribes to peer authors plus local recipient `#p`.
3. Signer creates a sign request, encrypts envelope, and emits events.
4. Peers process encrypted requests and return encrypted partials.
5. Signer enforces locked responder semantics: all selected locked peers must return valid responses.
6. Signer verifies/aggregates signatures and returns final result.

## Key Data Flow: ECDH

1. Caller invokes `bifrost ... ecdh <pubkey_hex33>`.
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
