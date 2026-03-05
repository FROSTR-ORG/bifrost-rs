# API Reference (Rust)

Current `bifrost-rs` API surface.

## `bifrost-core`

Primary types (`crates/bifrost-core/src/types.rs`):
- `GroupPackage`, `SharePackage`, `SignSessionTemplate`, `SignSessionPackage`
- `PartialSigPackage`, `EcdhPackage`, `PingPayload`, `OnboardRequest`, `OnboardResponse`
- Nonce commitment and policy profile types.

Primary functions:
- Group/session creation and validation.
- Partial-sign creation and verification.
- Signature aggregation.
- ECDH package create/combine.

## `bifrost-codec`

Bridge envelope (`crates/bifrost-codec/src/bridge.rs`):
- `BridgeEnvelope { request_id, sent_at, payload }`
- `BridgePayload` request/response variants for `ping`, `sign`, `ecdh`, `onboard`, and `error`.
- `encode_bridge_envelope`, `decode_bridge_envelope`.

Wire payloads (`crates/bifrost-codec/src/wire.rs`):
- Group/share/session/partial-signature/ECDH/ping/onboard payload structs.
- `TryFrom` conversions with strict bounds and shape checks.

## `bifrost-signer`

Primary runtime type (`crates/bifrost-signer/src/lib.rs`):
- `SigningDevice`

Primary operations:
- Inbound: `process_event(&Event)`
- Outbound command starts: `initiate_sign`, `initiate_ecdh`, `initiate_ping`, `initiate_onboard`
- Completion drain: `take_completions`
- Failure drain: `take_failures`
- State and policy: `status`, `policies`, `set_peer_policy`, `expire_stale`
- Subscription export: `subscription_filters`

State/config:
- `DeviceState`
- `DeviceConfig`
- `PendingOperation`, `CompletedOperation`

## `bifrost-bridge-tokio`

Runtime trait and orchestration (`crates/bifrost-bridge-tokio/src/lib.rs`):
- `RelayAdapter`: connect/disconnect/subscribe/publish/next_event.
- `Bridge`: starts runtime loop, accepts commands, returns results.

Bridge command surface:
- `sign`, `ecdh`, `ping`, `onboard`
- `status`, `policies`, `set_policy`, `snapshot_state`, `shutdown`
- explicit round-failure propagation for locked-peer timeout/invalid response conditions

## Runtime binaries

- `bifrost`: CLI (`sign`, `ecdh`, `ping`, `onboard`, `listen`, `status`, `policies`, `set-policy`)
- `bifrost-tui`: terminal dashboard.
- `bifrost-devtools`: `keygen`, `relay`, and `e2e-node` runtime e2e command.
