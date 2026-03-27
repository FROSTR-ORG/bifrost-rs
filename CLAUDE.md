# CLAUDE.md

This file gives working guidance for agent-driven changes inside `repos/bifrost-rs`.

## Project Role

`bifrost-rs` is the signer/runtime core for FROSTR. It owns:

- signer state and operation logic
- routing and bridge runtimes
- host orchestration in `bifrost_app::host`
- onboarding/invite encoding utilities
- WASM and Tokio bridge surfaces

It does not own any host-specific operator UI or CLI surface. `bifrost-devtools` in this repo owns developer relay, key generation, and runtime orchestration flows.

## Build And Test Commands

```bash
# Workspace checks
cargo check --workspace --offline
cargo clippy --workspace --all-targets --offline --no-deps
cargo fmt --all -- --check

# Focused tests
cargo test -p bifrost-signer --offline
cargo test -p bifrost-router --offline
cargo test -p bifrost-bridge-wasm --offline
cargo test -p bifrost-bridge-tokio --offline
cargo test -p bifrost-app --offline

# Full targeted verification used most often after interface changes
cargo test -p bifrost-signer -p bifrost-router -p bifrost-bridge-wasm -p bifrost-bridge-tokio -p bifrost-app --offline

# Format
cargo fmt
```

## Current Architecture

### Core crates

- `bifrost-core`: cryptographic types and policy primitives.
- `bifrost-codec`: wire encoding/decoding and parser helpers.
- `bifrost-signer`: signer runtime, readiness, peer status, pending operations, config patching.
- `bifrost-router`: high-level runtime command router over the signer.
- `frostr-utils`: onboarding, invite, and stateless helper utilities.

### Host and bridge crates

- `bifrost-app`: reusable host layer. `bifrost_app::host` owns config bootstrap, bridge startup, control socket serving, and typed command execution.
- `bifrost-bridge-wasm`: browser-facing bridge for external host integrations.
- `bifrost-bridge-tokio`: Tokio runtime bridge and Unix control socket support.

## Ownership Rules

- Keep `bifrost-rs` library-first.
- Do not add new host-specific operator workflows here.
- Keep host logic typed. Presentation and stdout formatting belong in consuming hosts, not in reusable host code.
- `runtime_status()` is the canonical hosted read model.
- `drain_runtime_events()` is incremental and lossy-safe; clients must recover truth from `runtime_status()`.
- `prepare_sign()` and `prepare_ecdh()` are the operation-prep APIs. Hosted clients should not infer readiness from snapshots.
- `wipe_state()` is the canonical signer reset path.

## Editing Priorities

When making architectural changes here, keep these cleanup constraints in mind:

- signer-owned readiness must stay truthful
- peer/readiness computation should exist in one place
- control socket and bridge surfaces should not drift apart without an explicit decision
- transport-specific policy translation should stay centralized

## Related Docs

- `README.md`
- `docs/ARCHITECTURE.md`
- `docs/API.md`
- `docs/SECURITY-MODEL.md`
