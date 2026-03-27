# Operations Runbook

Runtime internals and persistence behavior for `bifrost-rs`.

## Build and Test Gates

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --offline --no-deps -- -D warnings
cargo check --workspace --offline
cargo test --workspace --offline
```

## Package and Backup Rules

- `bfonboard` is the only onboarding package artifact.
- `bfprofile` is the full encrypted local device profile package.
- `bfshare` is the compact encrypted recovery package.
- Encrypted profile backups are published as `kind: 10000` and recovered by host layers using relays plus the share-derived author key.

## Logs and State

- Device state snapshots: `state_path` from each signer config.
- Run marker snapshots: `<state_path>.run.json`.
- Structured runtime logs should be collected by the consuming host according to its own operational surface.
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

Use these current workspace-owned entrypoints:

```bash
cargo test --workspace --offline
```

Host-specific runtime E2E and soak workflows are intentionally owned by the consuming host repositories rather than this manual.
