# Guide

This guide gets you from a clean checkout to a working local `bifrost-rs` devnet, with CLI and TUI validation.

## Prerequisites

- Rust toolchain installed and working (`cargo`, `rustfmt`, `clippy`).
- `cargo-audit` installed for security gate execution.
- `tmux` optional (only needed for `scripts/devnet-tmux.sh`).

Preflight:

```bash
./dev/scripts/toolchain_preflight.sh --require-cargo --require-cargo-audit
```

## 1. Build Baseline

```bash
cargo check -p bifrost-devtools -p bifrostd -p bifrost-cli -p bifrost-tui --offline
cargo test -p bifrost-core -p bifrost-codec -p bifrost-node --offline
```

## 2. Generate Devnet Credentials and Config

```bash
scripts/devnet.sh gen
```

This creates group/share/config artifacts under `dev/data`.

## 3. Start Local Runtime

```bash
scripts/devnet.sh start
scripts/devnet.sh status
```

Expected processes:
- `bifrost-devtools`
- `bifrostd` for `alice`, `bob`, `carol`

Logs:
- `dev/data/logs/relay.log`
- `dev/data/logs/bifrostd-alice.log`
- `dev/data/logs/bifrostd-bob.log`
- `dev/data/logs/bifrostd-carol.log`

## 4. Verify RPC Health With CLI

Use Alice socket as baseline:

```bash
cargo run -p bifrost-cli -- --socket /tmp/bifrostd-alice.sock health
cargo run -p bifrost-cli -- --socket /tmp/bifrostd-alice.sock negotiate bifrost-cli 1
cargo run -p bifrost-cli -- --socket /tmp/bifrostd-alice.sock status
cargo run -p bifrost-cli -- --socket /tmp/bifrostd-alice.sock events 20
```

Run operational methods:

```bash
cargo run -p bifrost-cli -- --socket /tmp/bifrostd-alice.sock ping <peer_pubkey_hex>
cargo run -p bifrost-cli -- --socket /tmp/bifrostd-alice.sock echo <peer_pubkey_hex> hello
cargo run -p bifrost-cli -- --socket /tmp/bifrostd-alice.sock onboard <peer_pubkey_hex>
cargo run -p bifrost-cli -- --socket /tmp/bifrostd-alice.sock sign <32-byte-hex>
cargo run -p bifrost-cli -- --socket /tmp/bifrostd-alice.sock ecdh <33-byte-hex>
```

## 5. Use TUI

```bash
cargo run -p bifrost-tui -- --socket /tmp/bifrostd-alice.sock
```

Inside TUI, run:
- `help`
- `status`
- `events 20`
- `use bob`
- `ping bob`
- `echo hi`
- `sign hello`
- `sign hex:<32-byte-hex>`
- `ecdh bob`
- `policy list`
- `policy get bob`

Peer selectors accept:
- alias (`alice`, `bob`, `carol`)
- index
- pubkey prefix

## 6. Run Full Runtime Smoke and E2E

```bash
scripts/devnet.sh smoke
scripts/test-node-e2e.sh
scripts/test-tui-e2e.sh
```

Optional cluster smoke:

```bash
CLUSTER_COUNT=5 THRESHOLD=3 scripts/devnet-cluster.sh smoke
```

## 7. Stop Runtime

```bash
scripts/devnet.sh stop
```

If using tmux demo:

```bash
scripts/devnet-tmux.sh stop
```

## 8. Release/Audit Gate Execution

```bash
dev/scripts/audit_run.sh
```

Artifacts are written under `dev/audit/work/evidence`.

## Next Reading

- `OPERATIONS.md` for day-2 runbook details.
- `CONFIGURATION.md` for daemon/auth/transport options.
- `TROUBLESHOOTING.md` for common failures.
- `frostr-utils/INDEX.md` for keyset and onboarding integration utilities.
