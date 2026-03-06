# Plan B: Multi-Device Router with Strict Single `p`-Tag Addressing (Hard Cut)

Reference: `design/plans/plan-a-pubkey32-normalization-hard-cut-2026-03-05.md`

## Summary
Upgrade `bifrost-router` and `bifrost-bridge-tokio` to support multiple local signing devices behind a single relay connection, with strict recipient addressing via exactly one Nostr `p` tag per event.

## Decisions (Locked)
- Inbound event eligibility requires exactly one `p` tag.
- Event is routable only if that `p` tag matches one locally registered signer `pubkey32`.
- Events with zero or multiple `p` tags are rejected/ignored (hard cut, no compatibility path).
- Outbound events emitted by signer must include exactly one `p` tag matching the intended recipient.
- Payload stays fully encrypted; no additional cleartext routing fields are introduced.

## Key Implementation Changes

### 1) Multi-device router model (`bifrost-router`)
- Replace single-device core state with multi-device registry:
  - `HashMap<local_device_pubkey32, DeviceRuntime>`
- `DeviceRuntime` holds per-device signer/core state, queues, dedupe window, completions, failures.
- Add lifecycle APIs:
  - `register_device(device_pubkey32, signer, config)`
  - `unregister_device(device_pubkey32)`
  - status/policy/snapshot per device.
- Commands become explicitly targeted:
  - `Sign { device_pubkey32, ... }`
  - `Ecdh { device_pubkey32, ... }`
  - `Ping { device_pubkey32, ... }`
  - `Onboard { device_pubkey32, ... }`

### 2) Inbound/outbound routing behavior
- Inbound path:
  - parse event `p` tags
  - require exactly one recipient `p`
  - lookup local device by recipient key
  - enqueue/process only on matched device runtime.
- Outbound path:
  - maintain `(device_pubkey32, request_id)` association
  - emit events with request metadata tied to originating device runtime.
- Dedupe isolation:
  - event dedupe keyed per device (or `(device_pubkey32, event_id)`).

### 3) Signer event IO and subscription rules
- `bifrost-signer`:
  - include recipient `p` tag in outbound event creation
  - reject inbound events where recipient `p` does not equal local signer pubkey
  - keep request correlation inside encrypted envelope.
- `subscription_filters`:
  - include `kinds` + `authors` + `#p` constraints
  - router/bridge aggregate filters across registered local devices.

### 4) `bifrost-bridge-tokio` integration
- Single relay client remains.
- Internally host multi-device router and dispatch inbound events by `p` recipient.
- Extend typed API for device-aware operations:
  - `sign(device_pubkey32, ...)`, `ecdh(device_pubkey32, ...)`, `ping(...)`, `onboard(...)`
  - device-scoped status/policies/snapshot.
- Waiters keyed by `(device_pubkey32, request_id)` to avoid cross-device collision.

### 5) Codec/schema boundaries
- Keep `BridgeEnvelope` shape unchanged.
- Add/centralize strict Nostr tag parsing/validation helpers (single recipient `p` policy).
- Update docs to define recipient addressing contract and rejection behavior.

## Test Plan

### Unit
- Router:
  - register/unregister device behavior
  - command routing to correct device
  - inbound `p` routing acceptance/rejection:
    - one valid local `p` -> accepted
    - zero `p` -> rejected
    - multiple `p` -> rejected
    - non-local `p` -> ignored/rejected.
- Signer:
  - outbound includes exactly one `p` tag
  - inbound recipient mismatch rejected.

### Integration
- Tokio bridge with 2+ local devices:
  - one relay connection
  - event for device A never reaches device B
  - simultaneous rounds across devices complete independently.
- Waiter collision test:
  - same `request_id` on different devices does not collide.

### End-to-end
- Multi-tenant signing-service scenario:
  - several local signers active
  - peer-targeted encrypted events are delivered only to intended local signer.

## Acceptance Criteria
- Router supports dynamic multi-device lifecycle and device-targeted operations.
- Strict single-`p` tag policy enforced at inbound boundary.
- No legacy author-only fallback routing exists.
- Bridge and signer preserve encrypted payload model with minimal metadata.
- Full workspace tests pass with new routing semantics.

