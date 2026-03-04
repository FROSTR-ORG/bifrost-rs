# Guide

This guide gets you from a clean checkout to a working local `bifrost-rs` setup.

## Prerequisites

- Rust toolchain installed (`cargo`, `rustfmt`, `clippy`).

## 1. Build Baseline

```bash
cargo check --workspace
cargo test --workspace
```

## 2. Generate Local Artifacts

```bash
cargo run -p bifrost-dev --bin bifrost-devtools -- keygen --out-dir ./data --threshold 2 --count 3 --relay ws://127.0.0.1:8194
```

Generated files include:
- `./data/group.json`
- `./data/share-<name>.json`
- `./data/bifrost-<name>.json`

## 3. Start Relay

```bash
cargo run -p bifrost-dev --bin bifrost-devtools -- relay 8194
```

## 4. Start Listener Nodes

Run each in its own terminal:

```bash
cargo run -p bifrost-app --bin bifrost -- --config ./data/bifrost-alice.json listen
cargo run -p bifrost-app --bin bifrost -- --config ./data/bifrost-bob.json listen
cargo run -p bifrost-app --bin bifrost -- --config ./data/bifrost-carol.json listen
```

## 5. Run Operations

From an operator terminal:

```bash
cargo run -p bifrost-app --bin bifrost -- --config ./data/bifrost-alice.json status
cargo run -p bifrost-app --bin bifrost -- --config ./data/bifrost-alice.json policies
cargo run -p bifrost-app --bin bifrost -- --config ./data/bifrost-alice.json ping <peer_pubkey_hex>
cargo run -p bifrost-app --bin bifrost -- --config ./data/bifrost-alice.json onboard <peer_pubkey_hex>
cargo run -p bifrost-app --bin bifrost -- --config ./data/bifrost-alice.json sign <32-byte-hex>
cargo run -p bifrost-app --bin bifrost -- --config ./data/bifrost-alice.json ecdh <33-byte-hex>
```

## 6. Optional TUI

```bash
cargo run -p bifrost-dev --bin bifrost-tui -- --config ./data/bifrost-alice.json
```

## 7. Cross-Platform Runtime E2E

```bash
cargo run -p bifrost-dev --bin bifrost-devtools --offline -- e2e-node --out-dir ./data --relay ws://127.0.0.1:8194
```

## Next Reading

- `docs/OPERATIONS.md`
- `docs/CONFIGURATION.md`
- `docs/TROUBLESHOOTING.md`
