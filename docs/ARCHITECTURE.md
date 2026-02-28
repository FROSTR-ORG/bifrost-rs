# Architecture

## Crate Responsibilities

## `bifrost-core`

- Types: group/session/signature/nonce/ecdh domain models.
- Group/session integrity: deterministic group/session IDs and verification.
- Signing: FROST-compatible partial-sign creation, share verification, aggregation.
- Nonce pool: generation, storage, consumption of signing nonce state.
- ECDH package create/combine helpers.

## `bifrost-codec`

- RPC envelope encoding/decoding.
- Wire structs for transport payloads.
- Hex bridge conversions between wire and core types.

## `frostr-utils`

- Shared integration/tooling helpers for keyset lifecycle and onboarding packaging.
- Keyset operations: create/verify/rotate/recover.
- Onboarding package operations: minimal bootstrap package build + bech32m/binary encode/decode.

## `bifrost-transport`

- Generic transport traits:
- connect/close
- request/cast
- send_response
- next_incoming
- Error and message wrapper types.

## `bifrost-node`

- High-level API:
- `connect`, `close`, `echo`, `ping`, `onboard`, `sign`, `ecdh`
- Inbound processing:
- `handle_next_incoming`, `process_next_incoming`, `handle_incoming`
- Session validation and peer-selection orchestration.
- Nonce management integration with core nonce pool.

## `bifrost-transport-ws`

- Tokio/tungstenite based backend.
- Request correlation via pending map.
- Current limitations:
- no production-grade reconnect/failover state machine yet.

## Key Data Flow: Sign

1. Node selects signing peers and collects member nonces.
2. Node creates session package and sends sign request to peers.
3. Each signer generates partial signature for the session.
4. Node verifies signature shares and aggregates final signature.
5. Nonces are consumed exactly once.

## Key Data Flow: ECDH

1. Node selects peers and creates local ECDH package.
2. Node requests peer ECDH packages.
3. Node combines key shares into final shared secret.

## Security-Critical Boundaries

- Session integrity checks (`gid`, `sid`).
- Sender/member binding checks (still being hardened).
- Nonce one-time usage and lifecycle controls.
- Strict wire payload validation (in progress).
