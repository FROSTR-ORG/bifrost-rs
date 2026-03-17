# Guide

This guide covers the `bifrost-rs` runtime/library layer.

Runnable shell workflows now live in `repos/igloo-shell/docs/`.

## Prerequisites

- Rust toolchain installed (`cargo`, `rustfmt`, `clippy`)

## 1. Build Baseline

```bash
cargo check --workspace
cargo test --workspace
```

## 2. Read the Runtime Surface

Start with:
- `API.md` for the exported runtime and bridge APIs
- `ARCHITECTURE.md` for crate boundaries
- `PROTOCOL.md` for wire and validation boundaries

## 3. Current Host Model

`bifrost-rs` no longer owns runnable shell binaries.

- `bifrost_app::host` is the reusable host/listen/control layer consumed by `igloo-shell`
- hosted clients such as `igloo-chrome` use signer-owned APIs like `runtime_status()`, `prepare_sign()`, `prepare_ecdh()`, `drain_runtime_events()`, and `wipe_state()`
- Operator CLI/TUI flows belong to `repos/igloo-shell`
- Developer relay, keygen, and runtime shell e2e belong to `bifrost-devtools`

## 4. Local Verification

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --offline --no-deps -- -D warnings
cargo check --workspace --offline
cargo test --workspace --offline
```

## 5. When You Need Shell Workflows

Use the `igloo-shell` manuals:
- `../../igloo-shell/docs/INDEX.md`
- `../../igloo-shell/docs/GUIDE.md`
- `../../igloo-shell/docs/CONFIGURATION.md`
- `../../igloo-shell/docs/OPERATIONS.md`

## Next Reading

- `docs/API.md`
- `docs/ARCHITECTURE.md`
- `docs/CONFIGURATION.md`
- `docs/TROUBLESHOOTING.md`
