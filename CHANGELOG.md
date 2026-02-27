# CHANGELOG

All notable changes to `bifrost-rs` should be documented in this file.

## [0.1.0] - 2026-02-27

### Added

- Rust workspace migration foundation across core, codec, transport, node, and runtime crates.
- Runtime targets:
  - `bifrostd` daemon
  - `bifrost-cli`
  - `bifrost-tui`
  - `bifrost-relay-dev`
  - `bifrost-devnet`
- Devnet/e2e automation scripts:
  - `scripts/devnet.sh`
  - `scripts/devnet-tmux.sh`
  - `scripts/test-node-e2e.sh`
  - `scripts/test-tui-e2e.sh`
- Planner/runbook-based migration tracking under `planner/`.

### Security

- Sender/member binding checks in node inbound handlers.
- Replay and stale-envelope protections.
- Payload bounds and strict codec validation.
- Nonce safety guardrails and batch-sign validation checks.

### Notes

- See `docs/release-checklist-v0.1.0.md` for release gate evidence.

