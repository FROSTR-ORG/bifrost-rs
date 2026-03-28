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

- unit tests in `crates/*/src` for:
  - `bifrost-core`
  - `bifrost-codec`
  - `bifrost-signer`
  - `bifrost-router`
  - `bifrost-bridge-tokio`
  - `frostr-utils`
- integration tests for:
  - `bifrost-bridge-tokio`
  - `bifrost-app`
  - `bifrost-signer`

Coverage status:
- `cargo llvm-cov --workspace --lcov --output-path target/coverage/lcov.info --summary-only` collects workspace coverage
- `cargo llvm-cov report --summary-only` is the quick local summary
- soft targets are evaluated via `scripts/evaluate-coverage-targets.sh`

Current soft targets:
- regions: `80.00%`
- lines: `82.00%`

CI does not fail on missed coverage targets in this phase; it publishes target evaluation artifacts for review.

## Testing Requirements By Change Type

- crypto/core changes: add deterministic correctness and reject-path tests
- codec changes: add strict malformed/bounds tests
- signer/router/bridge runtime changes: add request lifecycle, failure mapping, and timeout-path tests
- app changes (`bifrost-app`): add host/control integration checks
- `frostr-utils` changes: add encode/decode, package round-trip, recovery, and reject-path coverage

## Focused Verification

Common targeted commands:

```bash
cargo test -p bifrost-core --offline
cargo test -p bifrost-codec --offline
cargo test -p bifrost-signer --offline
cargo test -p bifrost-router --offline
cargo test -p bifrost-bridge-tokio --offline
cargo test -p bifrost-bridge-wasm --offline
cargo test -p bifrost-app --offline
cargo test -p frostr-utils --offline
```

For host/runtime interface changes, use:

```bash
cargo test -p bifrost-app --offline
cargo test -p bifrost-bridge-tokio --offline
cargo test -p bifrost-bridge-wasm --offline
```

For package/backup/schema changes, use:

```bash
cargo test -p frostr-utils --offline
cargo test -p bifrost-bridge-wasm --offline
```

## Troubleshooting Test Failures

Common failure classes:

- toolchain/setup:
  - confirm `cargo --version`
  - rerun `dev/scripts/toolchain_preflight.sh --require-cargo`
- config/runtime fixture failures:
  - verify local runtime artifacts exist and paths are valid
  - regenerate temporary artifacts with `bifrost-devtools` if needed
- relay-related test failures:
  - confirm local relay ports are free
  - rerun with explicit logs enabled via `RUST_LOG=...`
- timeout and async lifecycle failures:
  - inspect structured runtime logs first
  - confirm peer ids and event kinds match the fixture topology
- state corruption/load failures:
  - remove the affected local `state_path` and rerun the test

## CI Expectation

Before merge, provide test evidence in the PR description:
- command run
- pass/fail result
- any known limitation in sandboxed environments
