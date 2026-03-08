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
cargo run -p bifrost-dev --bin bifrost-devtools -- --verbose keygen --out-dir ./data --threshold 2 --count 3 --relay ws://127.0.0.1:8194
```

## Start Relay

```bash
cargo run -p bifrost-dev --bin bifrost-devtools -- --verbose relay 8194
```

## Start Signer Listeners

```bash
cargo run -p bifrost-app --bin bifrost -- --verbose --config ./data/bifrost-alice.json listen
cargo run -p bifrost-app --bin bifrost -- --verbose --config ./data/bifrost-bob.json listen
cargo run -p bifrost-app --bin bifrost -- --verbose --config ./data/bifrost-carol.json listen
```

## Operator Commands

```bash
cargo run -p bifrost-app --bin bifrost -- --verbose --config ./data/bifrost-alice.json status
cargo run -p bifrost-app --bin bifrost -- --verbose --config ./data/bifrost-alice.json policies
cargo run -p bifrost-app --bin bifrost -- --verbose --config ./data/bifrost-alice.json state-health
cargo run -p bifrost-app --bin bifrost -- --verbose --config ./data/bifrost-alice.json set-policy <peer> '<policy-json>'
cargo run -p bifrost-app --bin bifrost -- --verbose --config ./data/bifrost-alice.json ping <peer>
cargo run -p bifrost-app --bin bifrost -- --verbose --config ./data/bifrost-alice.json invite create
cargo run -p bifrost-app --bin bifrost -- --verbose --config ./data/bifrost-alice.json invite show-pending
cargo run -p bifrost-app --bin bifrost -- --verbose --config ./data/bifrost-alice.json onboard <peer> --challenge-hex32 <challenge_hex32>
cargo run -p bifrost-app --bin bifrost -- --verbose --config ./data/bifrost-alice.json sign <32-byte-hex>
cargo run -p bifrost-app --bin bifrost -- --verbose --config ./data/bifrost-alice.json ecdh <32-byte-hex>
cargo run -p bifrost-dev --bin bifrost-devtools -- --verbose invite assemble --token '<invite-token-json>' --share <share.json> --password-env INVITE_PASSWORD
cargo run -p bifrost-dev --bin bifrost-devtools -- --verbose invite accept <bfonboard1...> --password-env INVITE_PASSWORD
```

Invite/onboarding rules:
- `invite create` creates only the token and persists inviter-side challenge state.
- `invite assemble` is the step that combines `token + share + password` into the encrypted `bfonboard1...` package.
- The onboarding package is not a persistent profile artifact; the recipient consumes it to complete `onboard` and then relies on signer/runtime state and snapshots.

## Logs and State

- Relay logs: stdout/stderr of `bifrost-devtools relay`.
- Device state snapshots: `state_path` from each signer config.
- Run marker snapshots: `<state_path>.run.json`.
- Structured runtime logs: `bifrost --verbose` or `bifrost --debug`.
- Structured devtools logs: `bifrost-devtools --verbose` or `bifrost-devtools --debug`.
- `RUST_LOG=...` overrides default crate filters when explicit tuning is needed.

`state-health` reports:
- Marker metadata (`run_id`, `phase`, version, timestamps).
- Current state ciphertext hash and marker hash health.
- `clean` boolean and `dirty_reason` when restart will discard volatile state.

Dirty restart reason codes and event IDs:
- `missing_marker` (`BAPP-RUN-001`)
- `invalid_marker` (`BAPP-RUN-002`)
- `unsupported_marker_version` (`BAPP-RUN-003`)
- `marker_running` (`BAPP-RUN-004`)
- `missing_state_hash` (`BAPP-RUN-005`)
- `state_hash_unavailable` (`BAPP-RUN-006`)
- `state_hash_mismatch` (`BAPP-RUN-007`)

`bifrost-app` emits structured warnings with `reason_code`, `event_id`, and `occurrence` for each dirty restart reason.

## Runtime E2E

Preferred cross-platform path:

```bash
cargo run -p bifrost-dev --bin bifrost-devtools --offline -- --verbose e2e-node --out-dir ./data --relay ws://127.0.0.1:8194
cargo run -p bifrost-dev --bin bifrost-devtools --offline -- --verbose e2e-full --threshold 11 --count 15
```

POSIX wrappers:

```bash
scripts/devnet.sh smoke
scripts/test-node-e2e.sh
scripts/test-tui-e2e.sh
```

`e2e-node` relay preflight behavior:
- If relay port is occupied by `bifrost-devtools relay`, stale processes are terminated and restarted.
- If occupied by a non-devtools process, the run fails fast with owner details.
