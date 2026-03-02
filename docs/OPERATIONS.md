# Operations Runbook

This runbook covers routine operation of local/runtime environments for `bifrost-rs`.

## Core Commands

### Devnet lifecycle

```bash
scripts/devnet.sh gen
scripts/devnet.sh start
scripts/devnet.sh status
scripts/devnet.sh stop
scripts/devnet.sh smoke
```

### Cluster lifecycle

```bash
CLUSTER_COUNT=5 THRESHOLD=3 scripts/devnet-cluster.sh gen
CLUSTER_COUNT=5 THRESHOLD=3 scripts/devnet-cluster.sh start
CLUSTER_COUNT=5 THRESHOLD=3 scripts/devnet-cluster.sh status
CLUSTER_COUNT=5 THRESHOLD=3 scripts/devnet-cluster.sh stop
CLUSTER_COUNT=5 THRESHOLD=3 scripts/devnet-cluster.sh smoke
```

### tmux demo lifecycle

```bash
scripts/devnet-tmux.sh start
scripts/devnet-tmux.sh status
scripts/devnet-tmux.sh stop
```

## Health Checks

### Toolchain preflight

```bash
toolchain_preflight.sh --require-cargo --require-cargo-audit
```

### Build and quality gates

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --offline --no-deps
cargo check --workspace --offline
```

### Test gates

```bash
cargo test -p bifrost-core -p bifrost-codec -p bifrost-node -p bifrost-transport-ws --offline
cargo test -p bifrost-devtools -p bifrost-rpc --offline
scripts/test-node-e2e.sh
scripts/test-tui-e2e.sh
```

## Daemon Operations

### Start a single daemon manually

```bash
cargo run -p bifrostd -- --config <path-to-daemon-config-json>
```

### Query daemon via CLI

```bash
cargo run -p bifrost-cli -- --socket /tmp/bifrostd-alice.sock health
cargo run -p bifrost-cli -- --socket /tmp/bifrostd-alice.sock negotiate bifrost-cli 1
cargo run -p bifrost-cli -- --socket /tmp/bifrostd-alice.sock status
cargo run -p bifrost-cli -- --socket /tmp/bifrostd-alice.sock events 50
```

### Expected baseline state

- `health` returns daemon liveness.
- `negotiate` succeeds with supported version range.
- `status` returns node readiness and peer nonce/pool views.
- `events` includes startup lifecycle events (`ready`, `info:*`).

## Audit Execution

Run full release/audit matrix:

```bash
audit_run.sh
```

Scaffold only (no execution):

```bash
audit_run.sh --scaffold-only
```

Optional planning checks (if runbook tooling is available):

```bash
planner_runbook.sh summary
planner_runbook.sh verify
```

## Logs and Artifacts

Runtime logs:
- `<runtime-logs-dir>/relay.log`
- `<runtime-logs-dir>/bifrostd-<name>.log`

Audit artifacts:
- `<audit-artifact-dir>/*.md`
- `<audit-artifact-dir>/evidence/*`

## Security and Operational Controls

- Use explicit RPC auth token in daemon config unless local development explicitly sets `auth.insecure_no_auth=true`.
- Keep socket paths permission-restricted to daemon owner.
- Keep relay lists controlled; do not trust relay metadata or availability.
- Treat devnet key material as disposable test material.
