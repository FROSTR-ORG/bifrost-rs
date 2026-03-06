# Operations Runbook

Routine operation commands for `bifrost-rs`.

## Build and Test Gates

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --offline --no-deps -- -D warnings
cargo check --workspace --offline
cargo test --workspace --offline
```

## Generate Runtime Material

```bash
cargo run -p bifrost-dev --bin bifrost-devtools -- keygen --out-dir ./data --threshold 2 --count 3 --relay ws://127.0.0.1:8194
```

## Start Relay

```bash
cargo run -p bifrost-dev --bin bifrost-devtools -- relay 8194
```

## Start Signer Listeners

```bash
cargo run -p bifrost-app --bin bifrost -- --config ./data/bifrost-alice.json listen
cargo run -p bifrost-app --bin bifrost -- --config ./data/bifrost-bob.json listen
cargo run -p bifrost-app --bin bifrost -- --config ./data/bifrost-carol.json listen
```

## Operator Commands

```bash
cargo run -p bifrost-app --bin bifrost -- --config ./data/bifrost-alice.json status
cargo run -p bifrost-app --bin bifrost -- --config ./data/bifrost-alice.json policies
cargo run -p bifrost-app --bin bifrost -- --config ./data/bifrost-alice.json set-policy <peer> '<policy-json>'
cargo run -p bifrost-app --bin bifrost -- --config ./data/bifrost-alice.json ping <peer>
cargo run -p bifrost-app --bin bifrost -- --config ./data/bifrost-alice.json onboard <peer>
cargo run -p bifrost-app --bin bifrost -- --config ./data/bifrost-alice.json sign <32-byte-hex>
cargo run -p bifrost-app --bin bifrost -- --config ./data/bifrost-alice.json ecdh <32-byte-hex>
```

## Logs and State

- Relay logs: stdout/stderr of `bifrost-devtools relay`.
- Device state snapshots: `state_path` from each signer config.

## Runtime E2E

Preferred cross-platform path:

```bash
cargo run -p bifrost-dev --bin bifrost-devtools --offline -- e2e-node --out-dir ./data --relay ws://127.0.0.1:8194
cargo run -p bifrost-dev --bin bifrost-devtools --offline -- e2e-full --threshold 11 --count 15
```

POSIX wrappers:

```bash
scripts/devnet.sh smoke
scripts/test-node-e2e.sh
scripts/test-tui-e2e.sh
```
