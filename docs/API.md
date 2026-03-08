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
- `OnboardRequestWire` now carries an optional invite `challenge`.
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
- Recipient helpers: local recipient identity + strict single-`p` routing checks

State/config:
- `DeviceState`
- `DeviceConfig`
- `PendingOperation`, `CompletedOperation`
- `PendingInviteRecord` for inviter-side challenge tracking
- `PersistenceHint` (batch/immediate/none persistence signal)

## `bifrost-router`

Runtime-agnostic router core (`crates/bifrost-router/src/lib.rs`):
- `BridgeCore`: queueing, dedupe, and signer-effect dispatch.
- strict recipient routing gate for inbound events (`exactly one p`, local recipient only).
- `BridgeConfig`: bounded queue/dedupe limits and overflow policy control.
- `BridgeCommand`: `sign`, `ecdh`, `ping`, `onboard` command surface.
- `onboard` commands may include an optional invite challenge.
- `OutboundEvent`: encrypted relay event plus optional request-id correlation.

## `bifrost-bridge-tokio`

Runtime trait and orchestration (`crates/bifrost-bridge-tokio/src/lib.rs`):
- `RelayAdapter`: connect/disconnect/subscribe/publish/next_event.
- `Bridge`: tokio runtime loop that drives `bifrost-router::BridgeCore`.

Bridge command surface:
- `sign`, `ecdh`, `ping`, `onboard`
- `status`, `policies`, `set_policy`, `snapshot_state`, `take_persistence_hint`, `shutdown`
- explicit round-failure propagation for locked-peer timeout/invalid response conditions

## Runtime binaries

- `bifrost`: CLI (`sign`, `ecdh`, `ping`, `onboard`, `invite`, `listen`, `status`, `policies`, `set-policy`)
- `bifrost` global flags: `--verbose`, `--debug`, plus `RUST_LOG` override support
- `bifrost-tui`: terminal dashboard.
- `bifrost-devtools`: `keygen`, `invite`, `relay`, `e2e-node`, and `e2e-full` runtime e2e commands.
- `bifrost-devtools` global flags: `--verbose`, `--debug`, plus `RUST_LOG` override support
