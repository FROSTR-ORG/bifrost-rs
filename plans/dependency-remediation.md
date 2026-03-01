# Dependency Audit Remediation

## Current Status (2026-02-28)

- `chacha20poly1305` removed from workspace dependencies and lockfile.
- `crossterm` unified to `0.29` in `bifrost-tui` and lockfile.
- `async-trait` removed from traits and implementations; explicit-future signatures are in place across transport traits and all transport mock/test impls.
- Lockfile no longer contains `async-trait` or `chacha20poly1305`.

Outstanding items are documentation-only:
- `frost-secp256k1-tr-unofficial` risk remains (tracked in `design/v1/libraries.md` and already documented as unresolvable without protocol migration).
- dual `thiserror` versions remain transitive (`1.x` from frost chain, `2.x` direct); accepted/risk-tracked only.

Evidence runbook used for this pass:
```bash
cargo fmt --all -- --check
cargo check --workspace --offline
cargo clippy --workspace --all-targets --offline --no-deps
cargo test -p bifrost-core -p bifrost-codec -p bifrost-node -p bifrost-transport-ws --offline
cargo test -p bifrost-devtools -p bifrost-rpc -p bifrostd -p frostr-utils --offline
```

## Context

The design extraction at `design/v1/libraries.md` identified four actionable dependency issues. This plan remediates the three that can be resolved directly and documents the one that cannot.

## Findings Summary

| # | Finding | Action | Risk |
|---|---------|--------|------|
| 1 | `chacha20poly1305` unused workspace dep | Remove | None |
| 2 | `crossterm` dual versions (0.28 + 0.29) | Bump to 0.29 | Low |
| 3 | `async-trait` removable (edition 2024) | Remove, use native syntax | Low |
| 4 | `thiserror` dual versions (1.x + 2.x) | Not actionable | -- |
| 5 | `frost-secp256k1-tr-unofficial` HIGH RISK | Document only | -- |

Finding 4 (`thiserror` 1.x) is pulled transitively by `ratatui -> ratatui-termwiz -> termwiz 0.23.3`. Cannot be eliminated without dropping ratatui or waiting for termwiz to update. No action.

Finding 5 (`frost-secp256k1-tr-unofficial`) is the core crypto dependency. Cannot be replaced without a protocol migration. Already documented in `libraries.md` as HIGH RISK. No code action.

---

## Step 1: Remove unused `chacha20poly1305`

**Files to modify:**
- `Cargo.toml` (root) -- delete line 38: `chacha20poly1305 = "0.10"`

That's it. No crate references it.

---

## Step 2: Bump `crossterm` from 0.28 to 0.29

**Files to modify:**
- `crates/bifrost-tui/Cargo.toml` line 16 -- change `crossterm = "0.28"` to `crossterm = "0.29"`

The TUI uses only stable crossterm APIs (`event::{self, Event, KeyCode, KeyEventKind}`, `terminal::{disable_raw_mode, enable_raw_mode}`, `execute!`, `terminal`). These are unchanged between 0.28 and 0.29. This aligns with the version ratatui 0.30 pulls transitively via ratatui-crossterm, eliminating the duplicate.

---

## Step 3: Remove `async-trait`, use native async fn in traits

**13 sites across 6 files.**

### 3a. Trait definitions -- `crates/bifrost-transport/src/traits.rs`
- Remove `use async_trait::async_trait;` (line 1)
- Remove `#[async_trait]` from `Sleeper` trait (line 10)
- Remove `#[async_trait]` from `Transport` trait (line 15)

### 3b. WebSocket impl -- `crates/bifrost-transport-ws/src/ws_transport.rs`
- Remove `use async_trait::async_trait;` (line 6)
- Remove `#[async_trait]` from `impl Transport for WebSocketTransport` (line 831)

### 3c. Node tests -- `crates/bifrost-node/src/node.rs` (test module)
- Remove `use async_trait::async_trait;` (line 1555)
- Remove `#[async_trait]` from `impl Transport for TestTransport` (line 1625)

### 3d. Integration tests -- `crates/bifrost-node/tests/happy_paths.rs`
- Remove `use async_trait::async_trait;` (line 4)
- Remove `#[async_trait]` from `impl Transport for MockTransport` (line 42)

### 3e. Integration tests -- `crates/bifrost-node/tests/fault_injection.rs`
- Remove `use async_trait::async_trait;` (line 5)
- Remove `#[async_trait]` from `impl Transport for ChaosTransport` (line 106)

### 3f. Integration tests -- `crates/bifrost-node/tests/adversarial.rs`
- Remove `use async_trait::async_trait;` (line 4)
- Remove `#[async_trait]` from `impl Transport for MockTransport` (line 42)

### 3g. Cargo.toml cleanup (4 files)
- `Cargo.toml` (root) -- delete `async-trait = "0.1"` (line 25)
- `crates/bifrost-transport/Cargo.toml` -- delete `async-trait.workspace = true` (line 9)
- `crates/bifrost-transport-ws/Cargo.toml` -- delete `async-trait.workspace = true` (line 10)
- `crates/bifrost-node/Cargo.toml` -- delete `async-trait.workspace = true` (line 10)

---

## Step 4: Update `design/v1/libraries.md`

Update the audit artifact to reflect the completed remediation:
- Remove `chacha20poly1305` row, remove from "Unused Workspace Dependencies" finding
- Update `crossterm` row to show 0.29 only, remove from "Future Considerations" dual-version note
- Remove `async-trait` row, remove from "Future Considerations"
- Update "Summary of Findings" section to reflect resolved items

---

## Verification

```bash
# Check the workspace compiles
cargo check --workspace --offline

# Run all tests
cargo test -p bifrost-core -p bifrost-codec -p bifrost-node -p bifrost-transport-ws --offline
cargo test -p bifrost-devtools -p bifrost-rpc -p bifrostd -p frostr-utils --offline

# Lint
cargo clippy --workspace --all-targets --offline --no-deps

# Format
cargo fmt --all -- --check

# Verify crossterm deduplication (should show only 0.29, not 0.28)
grep -A1 'name = "crossterm"' Cargo.lock

# Verify chacha20poly1305 removed from lockfile after next resolution
grep 'chacha20poly1305' Cargo.lock

# Verify async-trait removed from lockfile after next resolution
grep 'async-trait' Cargo.lock
```
