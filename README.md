# Bifrost RS

Rust implementation of the FROSTR signer, router, bridge, codec, and utility stack.

## What This Repository Owns

`bifrost-rs` provides:
- FROST threshold signing over secp256k1.
- Collaborative threshold ECDH flows.
- Nostr-native encrypted peer messaging and bridge envelope handling.
- Hosted runtime layers for native and browser environments.
- Package, onboarding, recovery, and backup utilities used by consuming hosts.

It does not own host-specific operator UX. Shell, browser, and desktop workflows belong in consuming projects.

## Project Status

- Beta.
- Current signer/router/bridge architecture only.
- No legacy compatibility layer is maintained in this repository.

## Workspace Layout

- `crates/bifrost-core`: cryptographic/session primitives, policy types, and nonce safety.
- `crates/bifrost-codec`: strict wire, package, and bridge-envelope validation.
- `crates/bifrost-signer`: signing-device runtime, policy enforcement, readiness, and state.
- `crates/bifrost-router`: runtime-agnostic queueing, dedupe, and command/event routing.
- `crates/bifrost-bridge-tokio`: Tokio runtime bridge and relay adapter boundary.
- `crates/bifrost-bridge-wasm`: browser-facing WASM bridge runtime.
- `crates/bifrost-app`: reusable host/runtime glue for consuming hosts.
- `crates/frostr-utils`: keyset lifecycle, package, onboarding, and encrypted-backup helpers.
- `crates/bifrost-devtools`: developer relay, key generation, and local runtime orchestration tools.

## Architecture Summary

### Core crates

- `bifrost-core` owns the cryptographic domain types and deterministic validation rules.
- `bifrost-codec` owns strict payload parsing and serialization boundaries.
- `bifrost-signer` owns signer state, operation logic, readiness, replay controls, and policy enforcement.
- `bifrost-router` owns bridge-core queueing, request lifecycle, dedupe, and outbound event routing.

### Bridge and host crates

- `bifrost-bridge-tokio` connects router/signer logic to async native transports.
- `bifrost-bridge-wasm` exposes the same runtime model to browser hosts.
- `bifrost-app::host` is the reusable host boundary for config bootstrap, runtime startup, control sockets, and typed command execution.

### Hosted runtime contract

Hosted clients should treat `bifrost-rs` as the signer authority.

- `runtime_status()` is the canonical aggregated read model.
- `readiness()` is the narrower capability view.
- `drain_runtime_events()` is incremental and lossy-safe; clients must recover truth from `runtime_status()`.
- `prepare_sign()` and `prepare_ecdh()` are the normal operation-prep APIs.
- `wipe_state()` is the canonical signer-side reset path.

Clients should not reconstruct readiness from snapshots, nonce pools, or transport heuristics.

## API Surface

### `bifrost-core`

Primary types:
- `GroupPackage`, `SharePackage`
- `SignSessionTemplate`, `SignSessionPackage`
- `PartialSigPackage`, `EcdhPackage`
- `PingPayload`, `OnboardRequest`, `OnboardResponse`

Primary responsibilities:
- group/session creation and validation
- partial-sign creation and verification
- signature aggregation
- ECDH package create/combine

### `bifrost-codec`

Owns:
- bridge envelopes and payload variants
- strict wire structs and `TryFrom` conversions
- parsing helpers for group/share/session/onboarding material

### `bifrost-signer`

Primary runtime type:
- `SigningDevice`

Primary operations:
- `process_event(&Event)`
- `initiate_sign`, `initiate_ecdh`, `initiate_ping`, `initiate_onboard`
- `take_completions`, `take_failures`
- `status`, `runtime_status`, `peer_status`, `readiness`
- policy mutation and config patch application

### `bifrost-router`

Primary runtime type:
- `BridgeCore`

Owns:
- bounded command/inbound/outbound queues
- dedupe and overflow handling
- request lifecycle and failure propagation
- strict recipient routing before payload processing

### `bifrost-bridge-tokio`

Primary types:
- `RelayAdapter`
- `Bridge`

Bridge command surface includes:
- `sign`, `ecdh`, `ping`, `onboard`
- `status`, `runtime_status`, `runtime_metadata`, `readiness`, `peer_status`
- `read_config`, `update_config`
- `wipe_state`, `shutdown`

### `bifrost-bridge-wasm`

Primary browser-facing exports include:
- runtime lifecycle: `init_runtime`, `restore_runtime`, `tick`
- ingress/egress: `handle_command`, `handle_inbound_event`, `drain_outbound_events`
- read models: `status`, `runtime_status`, `readiness`, `runtime_metadata`, `peer_status`
- state helpers: `snapshot_state`, `wipe_state`, `drain_runtime_events`
- package helpers: `encode_*` / `decode_*` for `bfshare`, `bfonboard`, and `bfprofile`

### `bifrost_app::host`

Reusable host layer for consuming runtimes:
- `execute_command(...)` returns typed host results
- `run_command(...)` is the thin stdout wrapper
- daemon/control surfaces cover status, config, policy, readiness, runtime metadata, diagnostics, and interactive operations

## Runtime Configuration

The runtime config consumed by `bifrost_app::host` includes:
- `group_path`
- `share_path`
- `state_path`
- `relays`
- `peers`
- `manual_policy_overrides`
- `options`

Important option fields include:
- timeouts for sign / ecdh / ping / onboard
- request TTL and future-skew limits
- replay/cache capacities
- state save interval
- event kind
- peer selection strategy
- router queue, backoff, and overflow settings

Validation rules:
- relay lists must be non-empty
- peer ids are 32-byte x-only secp256k1 hex
- member indexes and pubkeys must match the configured group/share packages
- event kind must match across participating peers

## Operations and Troubleshooting

### Verification baseline

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --offline --no-deps -- -D warnings
cargo check --workspace --offline
cargo test --workspace --offline
```

### Runtime state and observability

- device state snapshots live at each configured `state_path`
- run markers live at `<state_path>.run.json`
- consuming hosts should collect structured runtime logs around `bifrost_app::host`
- `RUST_LOG=...` remains the explicit crate-level override

`state-health` reports:
- run marker metadata and phase
- current state hash health
- clean/dirty restart status and dirty reason

Dirty restart reason codes currently include:
- `missing_marker`
- `invalid_marker`
- `unsupported_marker_version`
- `marker_running`
- `missing_state_hash`
- `state_hash_unavailable`
- `state_hash_mismatch`

### Common failures

`cargo` not found:
```bash
cargo --version
```

Config file not found:
- confirm the config path exists
- regenerate local artifacts if needed with `bifrost-devtools`

Relay connection failures:
- confirm the relay is running
- confirm relay URLs in config are correct
- confirm no local firewall or port conflict is blocking access

`ping` / `sign` / `ecdh` timeouts:
- confirm peer listeners are active
- confirm all peers use the same `event_kind`
- confirm configured peer ids match group members

State corruption errors:
- stop the process
- back up and remove the corrupted `state_path`
- rerun; signer state will be reinitialized

If blocked, collect:
- command run
- exact stderr
- structured runtime logs
- relay logs
- active config JSON with secrets redacted

## `frostr-utils`

`frostr-utils` is the shared utility crate for keyset lifecycle, package formats, and transport-agnostic integration workflows.

### Keyset helpers

Primary helpers:
- `create_keyset(CreateKeysetConfig)`
- `verify_keyset(&KeysetBundle)`
- `verify_group_config(&GroupPackage)`
- `verify_share(&SharePackage, &GroupPackage)`
- `rotate_keyset_dealer(&GroupPackage, RotateKeysetRequest)`
- `recover_key(&RecoverKeyInput)`

Rotation model:
- threshold shares reconstruct the current signing key
- the same signing key is re-split into a fresh share set
- the group public key is preserved
- threshold and member count may change

If the group public key changes, that is a new keyset, not rotation.

### Package and backup ownership

`frostr-utils` is the canonical Rust owner of:
- `bfshare`
- `bfonboard`
- `bfprofile`
- encrypted profile backup `kind: 10000`

It owns:
- payload types
- encode/decode
- password-based encryption/decryption
- backup content encryption/decryption
- backup event build/parse

It does not own:
- relay publish/query
- latest-event selection
- host storage
- host lifecycle or UI state

`bfprofile` and encrypted backups store structured `groupPackage` data losslessly, preserving full compressed member pubkeys.

### Browser/WASM package API

`bifrost-bridge-wasm` is the canonical browser-facing export surface for Rust-owned package and backup semantics. Browser hosts should consume the generated WASM module rather than maintaining parallel JavaScript codecs.

Key exports include:
- package version/prefix helpers
- `encode_bfshare_package`, `decode_bfshare_package`
- `encode_bfonboard_package`, `decode_bfonboard_package`
- `encode_bfprofile_package`, `decode_bfprofile_package`
- encrypted profile backup helpers and event builders/parsers

### Utility security notes

- treat share material as highly sensitive secret data
- treat onboarding packages as sensitive because they contain a secret share
- limit relay lists to trusted bootstrap relays
- keep strict prefix and bounds validation on all decoded package material

## Documentation And Process

Root docs are the full repo manual:
- [README.md](./README.md)
- [TESTING.md](./TESTING.md)
- [CONTRIBUTING.md](./CONTRIBUTING.md)
- [RELEASE.md](./RELEASE.md)
- [SECURITY.md](./SECURITY.md)
- [CHANGELOG.md](./CHANGELOG.md)

General FROSTR protocol, cryptography, glossary, and system-wide architecture are documented at the workspace level, not duplicated in this repo.

## License

MIT.
