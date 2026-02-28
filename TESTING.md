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
