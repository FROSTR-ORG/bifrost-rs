# Bifrost RS

Rust implementation of the FROSTR threshold-signing stack.

## What This Is

`bifrost-rs` provides:
- FROST threshold signing over secp256k1.
- Collaborative ECDH flows.
- Nostr-native encrypted peer messaging (NIP-44-compatible envelope handling).
- Hard-cut runtime split between:
  - `bifrost-signer` for cryptographic/stateful signing-device logic.
  - `bifrost-router` for runtime-agnostic routing/queueing between signer and transport.
  - `bifrost-bridge-tokio` / `bifrost-bridge-wasm` for platform-specific bridge runtimes.
- `bifrost_app::host` for reusable host/listen/control behavior consumed by shell clients such as `igloo-shell`.
- `bifrost_app::host::execute_command(...)` is the typed host executor; `run_command(...)` is the thin stdout wrapper used by shell binaries.

## Project Status

- Alpha.
- Hard-cut architecture; no legacy compatibility layer is maintained.
- Runtime documentation reflects the current signer/router/bridge architecture only.

## Workspace Layout

- `crates/bifrost-core`: cryptographic/session primitives and nonce safety.
- `crates/frostr-utils`: keyset/onboarding helpers.
- `crates/bifrost-codec`: strict wire/envelope validation.
- `crates/bifrost-signer`: signing-device runtime and policy/state management.
- `crates/bifrost-router`: runtime-agnostic routing core (queueing, dedupe, command processing).
- `crates/bifrost-bridge-tokio`: async tokio bridge runtime and Nostr adapter boundary.
- `crates/bifrost-bridge-wasm`: wasm bridge runtime boundary.
- `crates/bifrost-app`: shared host/runtime glue exported for external shell clients.
- `docs/`: product and operations documentation.

## Shell Ownership

Shell/operator workflows are no longer owned by `bifrost-rs`.

- Use `repos/igloo-shell` for operator CLI, `bfshare` / `bfonboard` / `bfprofile` workflows, and managed-profile UX.
- Use `bifrost-devtools` in this repo for developer relay, keygen, and shell runtime e2e flows.
- Use `bifrost-rs` directly for library, signer, router, bridge, and WASM work.

## Observability

- Hosted shell clients should initialize JSON logging around `bifrost_app::host`.
- `RUST_LOG=...` remains available when you need explicit crate-level filter overrides.

## Verification Matrix

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --offline --no-deps -- -D warnings
cargo check --workspace --offline
cargo test --workspace --offline
```

## Documentation Map

Start here:
- [docs/INDEX.md](./docs/INDEX.md)
- [docs/GUIDE.md](./docs/GUIDE.md)
- [../../docs/ARCHITECTURE.md](../../docs/ARCHITECTURE.md)
- [../../docs/PROTOCOL.md](../../docs/PROTOCOL.md)

Core manuals:
- [docs/API.md](./docs/API.md)
- [docs/PROTOCOL.md](./docs/PROTOCOL.md)
- [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md)
- [docs/CRYPTOGRAPHY.md](./docs/CRYPTOGRAPHY.md)
- [docs/SECURITY-MODEL.md](./docs/SECURITY-MODEL.md)
- [docs/CONFIGURATION.md](./docs/CONFIGURATION.md)
- [docs/OPERATIONS.md](./docs/OPERATIONS.md)
- [docs/TROUBLESHOOTING.md](./docs/TROUBLESHOOTING.md)
- [docs/GLOSSARY.md](./docs/GLOSSARY.md)

Governance/process:
- [CONTRIBUTING.md](./CONTRIBUTING.md)
- [TESTING.md](./TESTING.md)
- [RELEASE.md](./RELEASE.md)
- [SECURITY.md](./SECURITY.md)
- [CHANGELOG.md](./CHANGELOG.md)
- [../../docs/adrs/INDEX.md](../../docs/adrs/INDEX.md)
- [../../docs/policies/documentation-guidance.md](../../docs/policies/documentation-guidance.md)

## Hosted Runtime Model

Hosted clients such as `igloo-chrome` should treat `bifrost-rs` as the signer authority.

- `runtime_status()` is the canonical aggregated read model.
- `drain_runtime_events()` is the incremental runtime-status notification path.
- `prepare_sign()` and `prepare_ecdh()` are the normal operation-prep APIs.
- `wipe_state()` is the canonical signer-side reset path.

Clients should not reconstruct signer readiness from snapshots, nonce pools, or transport heuristics.

## License

MIT.
