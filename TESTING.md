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

```bash
dev/scripts/toolchain_preflight.sh --require-cargo
cargo run -p bifrost-dev --bin bifrost-devtools --offline -- e2e-node
cargo run -p bifrost-dev --bin bifrost-devtools --offline -- e2e-full --threshold 11 --count 15
scripts/devnet.sh smoke
scripts/test-node-e2e.sh
scripts/test-tui-e2e.sh
```

`bifrost-devtools e2e-node` is the cross-platform primary path. The shell scripts remain as POSIX wrappers and TUI-specific checks.

## WS Soak / Fault Regression

```bash
dev/scripts/ws_soak.sh --iterations 25 --out dev/audit/work/evidence/ws-soak-$(date +%F).txt
```

## Coverage Report

```bash
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --locked
cargo llvm-cov --workspace --lcov --output-path target/coverage/lcov.info --summary-only
```

## Test Coverage Surface

Current test classes in repo:

- Unit tests: crate-level `#[test]` coverage in `crates/*/src` for:
  - `bifrost-core`
  - `bifrost-codec`
  - `bifrost-signer`
  - `bifrost-bridge`
  - `frostr-utils`
- Integration tests (`tests/` targets):
  - `crates/bifrost-bridge/tests/bridge_flow.rs`
  - `crates/bifrost-bridge/tests/bridge_queues.rs`
  - `crates/bifrost-bridge/tests/bridge_dedupe_and_failures.rs`
  - `crates/bifrost-app/tests/config_options.rs`
  - `crates/bifrost-app/tests/state_store_limits.rs`
- End-to-end/runtime tests:
  - `cargo run -p bifrost-dev --bin bifrost-devtools --offline -- e2e-node`
  - `scripts/test-node-e2e.sh`
  - `scripts/test-tui-e2e.sh`
  - `scripts/devnet.sh smoke`

Coverage status:

- `cargo llvm-cov --workspace --lcov --output-path target/coverage/lcov.info --summary-only` collects overall workspace coverage and uploads summary artifacts.
- There is no repository-defined minimum coverage threshold in CI; coverage quality is captured by artifact review.

## Testing Requirements By Change Type

- Crypto/core changes: add deterministic correctness + reject-path tests.
- Codec changes: add strict malformed/bounds tests.
- Signer/bridge runtime changes: add request lifecycle, failure-mapping, and timeout-path tests.
- App changes (`bifrost-app` / `bifrost-dev` bins/runtime): add CLI/TUI/devtools integration checks.

## CI Expectation

Before merge, provide test evidence in PR description:

- command run
- pass/fail result
- any known limitation in sandboxed environments
