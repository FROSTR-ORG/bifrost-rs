# Guide

Quick path to run `bifrost-rs` end-to-end locally.

## 1) Verify Build/Test Baseline

```bash
cargo check -p bifrost-devnet -p bifrost-relay-dev -p bifrostd -p bifrost-cli -p bifrost-tui --offline
cargo test -p bifrost-core -p bifrost-codec -p bifrost-node --offline
```

## 2) Generate Devnet Artifacts

```bash
scripts/devnet.sh gen
```

Generated files are written under `dev/data`.

## 3) Start Runtime Stack

```bash
scripts/devnet.sh start
scripts/devnet.sh status
```

## 4) Use CLI

```bash
cargo run -p bifrost-cli -- --socket /tmp/bifrostd-alice.sock status
cargo run -p bifrost-cli -- --socket /tmp/bifrostd-alice.sock ping <peer_pubkey_hex>
```

## 5) Use TUI

```bash
cargo run -p bifrost-tui -- --socket /tmp/bifrostd-alice.sock
```

## 6) Run E2E Scripts

```bash
scripts/devnet.sh smoke
scripts/test-node-e2e.sh
scripts/test-tui-e2e.sh
```

## 7) Stop

```bash
scripts/devnet.sh stop
```

