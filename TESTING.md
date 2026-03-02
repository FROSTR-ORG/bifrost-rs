# Testing Guide

This file defines the baseline test gates for `bifrost-rs`.

## Fast Local Baseline

```bash
dev/scripts/toolchain_preflight.sh --require-cargo
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --offline --no-deps
cargo test -p bifrost-core -p bifrost-codec -p bifrost-node --offline
cargo test -p bifrost-transport-ws --offline
cargo check -p bifrost-devtools -p bifrostd -p bifrost-cli -p bifrost-tui --offline
```

## Runtime E2E

```bash
dev/scripts/toolchain_preflight.sh --require-cargo
scripts/devnet.sh smoke
scripts/test-node-e2e.sh
scripts/test-tui-e2e.sh
```

## WS Soak / Fault Regression

```bash
dev/scripts/ws_soak.sh --iterations 25 --out dev/audit/work/evidence/ws-soak-$(date +%F).txt
```

## Planner Verification Gate

```bash
dev/scripts/planner_runbook.sh verify
```

## Coverage Report

```bash
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --locked
cargo llvm-cov --workspace --lcov --output-path target/coverage/lcov.info --summary-only
```

## Test Coverage Surface

Current test classes in repo:

- Unit tests: extensive crate-level `#[test]` coverage in `crates/*/src`.
  - `cargo test -p bifrost-core -p bifrost-codec -p bifrost-node` (core suite)
  - `cargo test -p bifrost-transport-ws` (transport suite)
- Integration tests (Rust `tests/` targets):
  - `crates/bifrost-node/tests/happy_paths.rs`
  - `crates/bifrost-node/tests/adversarial.rs`
  - `crates/bifrost-node/tests/fault_injection.rs`
  - `crates/bifrost-codec/tests/fixture_matrix.rs`
  - `crates/bifrost-cli/tests/e2e_cli.rs`
  - CI runs these explicitly via the `test-integration` task:
    - `cargo test -p bifrost-node --test happy_paths`
    - `cargo test -p bifrost-node --test adversarial`
    - `cargo test -p bifrost-node --test fault_injection`
- End-to-end/runtime tests:
  - `scripts/test-node-e2e.sh`
  - `scripts/test-tui-e2e.sh`
  - `scripts/devnet.sh smoke`
  - CI runs these in `runtime-e2e`.

Coverage status:

- `cargo llvm-cov --workspace --lcov --output-path target/coverage/lcov.info --summary-only` collects overall workspace coverage and uploads summary artifacts.
- There is no repository-defined minimum coverage threshold in CI; coverage quality is captured by artifact review.

## Testing Requirements By Change Type

- Crypto/core changes: add deterministic correctness + reject-path tests.
- Codec changes: add strict malformed/bounds tests.
- Node changes: add authorization/replay/payload-limit tests.
- Runtime changes: add daemon/cli/tui integration checks.

## CI Expectation

Before merge, provide test evidence in PR description:

- command run
- pass/fail result
- any known limitation in sandboxed environments
