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
- `bifrost` CLI for command execution.
- `bifrost-tui` for operator status views.
- `bifrost-devtools` for local relay + key/config generation.

## Project Status

- Alpha.
- Hard-cut migration in progress.
- Runtime documentation reflects the current signer/router/bridge architecture only.

## Workspace Layout

- `crates/bifrost-core`: cryptographic/session primitives and nonce safety.
- `crates/frostr-utils`: keyset/onboarding helpers.
- `crates/bifrost-codec`: strict wire/envelope validation.
- `crates/bifrost-signer`: signing-device runtime and policy/state management.
- `crates/bifrost-router`: runtime-agnostic routing core (queueing, dedupe, command processing).
- `crates/bifrost-bridge-tokio`: async tokio bridge runtime and Nostr adapter boundary.
- `crates/bifrost-bridge-wasm`: wasm bridge runtime boundary.
- `crates/bifrost-app`: production CLI package (`bifrost`) plus shared runtime glue.
- `crates/bifrost-dev`: developer tooling package (`bifrost-tui`, `bifrost-devtools`).
- `docs/`: product and operations documentation.

## Quickstart

1. Generate local key/config artifacts:

```bash
cargo run -p bifrost-dev --bin bifrost-devtools -- keygen --out-dir ./data --threshold 2 --count 3 --relay ws://127.0.0.1:8194
```

2. Start a local relay:

```bash
cargo run -p bifrost-dev --bin bifrost-devtools -- relay 8194
```

3. Start signer listeners (separate terminals):

```bash
cargo run -p bifrost-app --bin bifrost -- --config ./data/bifrost-alice.json listen
cargo run -p bifrost-app --bin bifrost -- --config ./data/bifrost-bob.json listen
cargo run -p bifrost-app --bin bifrost -- --config ./data/bifrost-carol.json listen
```

4. Run commands from one node:

```bash
cargo run -p bifrost-app --bin bifrost -- --config ./data/bifrost-alice.json status
cargo run -p bifrost-app --bin bifrost -- --config ./data/bifrost-alice.json ping <peer_pubkey_hex>
cargo run -p bifrost-app --bin bifrost -- --config ./data/bifrost-alice.json sign <32-byte-hex>
cargo run -p bifrost-app --bin bifrost -- --config ./data/bifrost-alice.json ecdh <32-byte-hex>
```

5. Run runtime e2e:

```bash
cargo run -p bifrost-dev --bin bifrost-devtools --offline -- e2e-node --out-dir ./data --relay ws://127.0.0.1:8194
```

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

## License

MIT.
