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
- `OnboardRequestWire` carries `version` plus bootstrap nonces; requester identity is inferred from the signed sender pubkey.
- `TryFrom` conversions with strict bounds and shape checks.

## `bifrost-signer`

Primary runtime type (`crates/bifrost-signer/src/lib.rs`):
- `SigningDevice`

Primary operations:
- Inbound: `process_event(&Event)`
- Outbound command starts: `initiate_sign`, `initiate_ecdh`, `initiate_ping`, `initiate_onboard`
- Completion drain: `take_completions`
- Failure drain: `take_failures`
- State and policy: `status`, `runtime_status`, `set_manual_peer_policy_override`, `clear_peer_policy_override`, `expire_stale`
- Subscription export: `subscription_filters`
- Recipient helpers: local recipient identity + strict single-`p` routing checks

State/config:
- `DeviceState`
- `DeviceConfig`
- `PendingOperation`, `CompletedOperation`
- `PersistenceHint` (batch/immediate/none persistence signal)

## `bifrost-router`

Runtime-agnostic router core (`crates/bifrost-router/src/lib.rs`):
- `BridgeCore`: queueing, dedupe, and signer-effect dispatch.
- strict recipient routing gate for inbound events (`exactly one p`, local recipient only).
- `BridgeConfig`: bounded queue/dedupe limits and overflow policy control.
- `BridgeCommand`: `sign`, `ecdh`, `ping`, `onboard` command surface.
- `OutboundEvent`: encrypted relay event plus optional request-id correlation.

## `bifrost-bridge-tokio`

Runtime trait and orchestration (`crates/bifrost-bridge-tokio/src/lib.rs`):
- `RelayAdapter`: connect/disconnect/subscribe/publish/next_event.
- `Bridge`: tokio runtime loop that drives `bifrost-router::BridgeCore`.

Bridge command surface:
- `sign`, `ecdh`, `ping`, `onboard`
- `status`, `runtime_status`, `set_manual_peer_policy_override`, `clear_peer_policy_override`, `snapshot_state`, `take_persistence_hint`, `shutdown`
- explicit round-failure propagation for locked-peer timeout/invalid response conditions

## `bifrost-bridge-wasm`

Browser/runtime bridge surface (`crates/bifrost-bridge-wasm/src/lib.rs`):
- runtime lifecycle: `init_runtime`, `restore_runtime`, `tick`
- ingress/egress: `handle_command`, `handle_inbound_event`, `drain_outbound_events`
- completions/failures: `drain_completions`, `drain_failures`
- runtime state: `snapshot_state`, `status`, `runtime_status`, `drain_runtime_events`, `wipe_state`
- config control: `read_config`, `update_config`
- signer-owned readiness and metadata: `readiness`, `peer_status`, `runtime_metadata`
- package and backup helpers: `encode_bfshare_package`, `decode_bfshare_package`, `encode_bfonboard_package`, `decode_bfonboard_package`, `encode_bfprofile_package`, `decode_bfprofile_package`

Bridge maintenance commands:
- `refresh_peer { peer_pubkey32_hex }`
- `refresh_all_peers`

Hosted clients should treat `runtime_status` as the canonical read model and `readiness` as the operation-capability view.
`drain_runtime_events` is incremental only; clients must recover current truth from `runtime_status` after resume or host restart. The current event kinds are status-oriented notifications such as `initialized`, `command_queued`, `inbound_accepted`, `config_updated`, `policy_updated`, `state_wiped`, and `status_changed`.
Snapshot exports remain useful for persistence and diagnostics, but not as the normal readiness API.

The bridge API returns JSON strings for structured payloads; `_json` suffixes are not used in method names.

## Shell surfaces

Runnable shell binaries now live in `repos/igloo-shell`:
- `igloo-shell`: operator CLI for managed profiles, `bfprofile` / `bfshare` / `bfonboard`, backup recovery/publish, and runtime control
- `igloo-shell-tui`: terminal dashboard
- `bifrost-devtools`: developer relay, keygen, and shell e2e orchestration

`bifrost-rs` exports the reusable host and runtime APIs behind those binaries; it does not own runnable shell binaries directly.

## `bifrost_app::host`

Reusable host/listen/control layer (`crates/bifrost-app/src/host.rs`):
- `execute_command(...)` returns typed host results for shell clients.
- `run_command(...)` is the thin stdout-printing wrapper used by CLI binaries.
- Unix control-socket commands now cover:
  - status and runtime status
  - `read_config` / `update_config`
  - `peer_status`, `readiness`, `runtime_status`, `runtime_metadata`
  - `wipe_state`
  - interactive operations like `sign`, `ecdh`, `ping`, and `onboard`
