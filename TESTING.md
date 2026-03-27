# Testing Guide

This file defines the baseline test gates for `bifrost-rs`.

## Fast Local Baseline

```bash
dev/scripts/toolchain_preflight.sh --require-cargo
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --offline --no-deps -- -D warnings
cargo check --workspace --offline
cargo test --workspace --offline
```

## Runtime E2E

Observability controls:
- hosted JSON logs around `bifrost_app::host`
- `RUST_LOG=...` remains the low-level override when explicit crate filtering is needed

Host-owned runtime E2E, soak, and operator workflows are intentionally outside this repository.

## Coverage Report

```bash
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --locked
cargo llvm-cov --workspace --lcov --output-path target/coverage/lcov.info --summary-only
cargo llvm-cov report --summary-only | tee target/coverage/coverage-summary.txt
bash scripts/evaluate-coverage-targets.sh target/coverage/coverage-summary.txt
```

## Test Coverage Surface

Current test classes in repo:

- Unit tests: crate-level `#[test]` coverage in `crates/*/src` for:
  - `bifrost-core`
  - `bifrost-codec`
  - `bifrost-signer`
  - `bifrost-router`
  - `bifrost-bridge-tokio`
  - `frostr-utils`
- Integration tests (`tests/` targets):
  - `crates/bifrost-bridge-tokio/tests/bridge_flow.rs`
  - `crates/bifrost-bridge-tokio/tests/bridge_queues.rs`
  - `crates/bifrost-bridge-tokio/tests/bridge_dedupe_and_failures.rs`
  - `crates/bifrost-bridge-tokio/tests/bridge_admin_and_phases.rs`
  - `crates/bifrost-bridge-tokio/tests/bridge_recovery.rs`
  - `crates/bifrost-app/tests/config_options.rs`
  - `crates/bifrost-app/tests/daemon_lifecycle.rs`
  - `crates/bifrost-app/tests/onboarding_runtime.rs`
  - `crates/bifrost-app/tests/state_store_limits.rs`
- `crates/bifrost-app/tests/run_marker_v2.rs`
- `crates/bifrost-signer/tests/runtime_roundtrip.rs`
- End-to-end/runtime host tests: owned by consuming host projects

Coverage status:

- `cargo llvm-cov --workspace --lcov --output-path target/coverage/lcov.info --summary-only` collects overall workspace coverage and uploads summary artifacts.
- `cargo llvm-cov report --summary-only` is the quickest local summary for crate-by-crate review after targeted test changes.
- Soft targets are defined in `scripts/coverage-targets.env` and evaluated by `scripts/evaluate-coverage-targets.sh`.
- Current soft targets:
  - regions: `80.00%`
  - lines: `82.00%`
- CI does not fail on missed coverage targets in this phase; it publishes the target evaluation artifact for review.

## Testing Requirements By Change Type

- Crypto/core changes: add deterministic correctness + reject-path tests.
- Codec changes: add strict malformed/bounds tests.
- Signer/router/bridge runtime changes: add request lifecycle, failure-mapping, and timeout-path tests.
- App changes (`bifrost-app` host/runtime): add host/control integration checks.

## CI Expectation

Before merge, provide test evidence in PR description:

- command run
- pass/fail result
- any known limitation in sandboxed environments
