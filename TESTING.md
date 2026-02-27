# Testing Guide

This file defines the baseline test gates for `bifrost-rs`.

## Fast Local Baseline

```bash
cargo test -p bifrost-core -p bifrost-codec -p bifrost-node --offline
cargo test -p bifrost-transport-ws --offline
cargo check -p bifrost-relay-dev -p bifrostd -p bifrost-cli -p bifrost-tui --offline
```

## Runtime E2E

```bash
scripts/devnet.sh smoke
scripts/test-node-e2e.sh
scripts/test-tui-e2e.sh
```

## Planner Verification Gate

```bash
dev/scripts/planner_runbook.sh verify
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

