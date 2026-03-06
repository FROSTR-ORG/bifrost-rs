# CHANGELOG

All notable changes to `bifrost-rs` should be documented in this file.

## [Unreleased]

## [0.3.0] - 2026-03-06

### Changed

- Added `RouterPort` boundary in `bifrost-router` and refactored `bifrost-bridge-tokio` to consume router through the trait boundary.
- Added explicit router request lifecycle phases (`created`, `awaiting_responses`, `completed`, `failed`, `expired`) and runtime request-phase query support.
- Added structured lifecycle logging for accepted/rejected/failed operations in bridge runtime paths.
- Hardened runtime clean-shutdown detection to avoid false dirty-restart volatility drops.
- Updated stress harness and soak runner to current architecture (`bifrost-bridge-tokio` tests + `e2e-full` runtime stress).

### Added

- Architecture hardening implementation plan: `design/plans/plan-c-architecture-hardening-2026-03-06.md`.
- Stress evidence artifact: `dev/audit/work/evidence/ws-soak-2026-03-06.txt`.

### Fixed

- `ws_soak` stale crate/test references after hard-cut crate renames.
- Intermittent runtime stress failures (`nonce unavailable`) caused by over-strict restart-cleanliness checks.

### Documentation

- Remediated runtime/testing terminology drift across root docs and `docs/` to align on signer/router/platform-bridge architecture.

## [0.2.0] - 2026-03-04

### Changed

- Hard-cut runtime naming now reflects current crate boundaries:
  - `bifrost-router` (runtime-agnostic routing core)
  - `bifrost-bridge-tokio` / `bifrost-bridge-wasm` (platform bridge runtimes)
- Documentation updated to use signer/router/bridge terminology consistently.

- Hard-cut runtime architecture now centered on:
  - `bifrost-signer` (stateful cryptographic engine)
  - `bifrost-bridge` (runtime orchestration and relay boundary)
  - `bifrost-app` (`bifrost` CLI runtime)
  - `bifrost-dev` (`bifrost-devtools`, `bifrost-tui`)
- Removed reliance on legacy daemon/RPC runtime components from active release paths.
- `scripts/test-node-e2e.sh` now delegates to `bifrost-devtools e2e-node` for a cross-platform primary node e2e flow.

### Added

- `bifrost-devtools e2e-node` command for runtime end-to-end orchestration.
- Bridge/signer hardening:
  - bounded bridge command ingress
  - explicit config validation (fail-fast)
  - request-id future-skew rejection
  - strict group-package invariants
  - bounded state-file decode protections
- Additional runtime tests:
  - `crates/bifrost-app/tests/state_store_limits.rs`
  - relay tag-filter regression coverage in `bifrost-devtools`

## [0.1.0] - 2026-02-27

### Added

- Rust workspace migration foundation across core, codec, transport, node, and runtime crates.
- Runtime targets:
  - `bifrostd` daemon
  - `bifrost-cli`
  - `bifrost-tui`
  - `bifrost-devtools` (`relay` + `keygen` subcommands)
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

- See `dev/audit/checklist-v0.1.0.md` and `dev/audit/internal-audit-2026-02-27.md` for release gate evidence.
