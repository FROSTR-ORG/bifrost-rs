# Operations Runbook

Runtime internals and persistence behavior for `bifrost-rs`.

Shell/operator runbooks now live in `repos/igloo-shell/docs/`.

## Build and Test Gates

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --offline --no-deps -- -D warnings
cargo check --workspace --offline
cargo test --workspace --offline
```

## Shell-Owned Runbooks

Use these manuals for runnable commands and local operator workflows:
- `../../igloo-shell/docs/GUIDE.md`
- `../../igloo-shell/docs/CONFIGURATION.md`
- `../../igloo-shell/docs/OPERATIONS.md`

Package/onboarding rules:
- `bfonboard` is the only onboarding package artifact.
- `bfprofile` is the full encrypted local device profile package.
- `bfshare` is the compact encrypted recovery package.
- Encrypted profile backups are published as `kind: 10000` and recovered by host layers using relays plus the share-derived author key.

## Logs and State

- Device state snapshots: `state_path` from each signer config.
- Run marker snapshots: `<state_path>.run.json`.
- Structured shell/runtime logs are documented in `../../igloo-shell/docs/OPERATIONS.md`.
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

Preferred operator/runtime e2e is documented in `../../igloo-shell/docs/OPERATIONS.md`.
Use these current entrypoints:

```bash
../igloo-shell/scripts/devnet.sh smoke
../igloo-shell/scripts/test-node-e2e.sh
../igloo-shell/scripts/test-tui-e2e.sh
../igloo-shell/scripts/ws_soak.sh --iterations 25 --out dev/audit/work/evidence/ws-soak-<date>.txt
```

`e2e-node` relay preflight behavior is owned by `igloo-shell`.
