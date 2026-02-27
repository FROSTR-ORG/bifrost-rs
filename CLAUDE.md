# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

bifrost-rs is a Rust workspace migrating `bifrost-ts` (TypeScript) to Rust. It implements a FROST threshold signing protocol coordinator for Nostr, using `frost-secp256k1-tr-unofficial` for the underlying cryptography. The migration tracks parity with the TS implementation through structured planning artifacts in `planner/`.

## Build & Test Commands

```bash
# Check all crates
cargo check --workspace

# Run all tests (offline, no network)
cargo test -p bifrost-core -p bifrost-codec -p bifrost-node -p bifrost-transport-ws --offline

# Run a single crate's tests
cargo test -p bifrost-core --offline

# Run a specific test file (integration tests)
cargo test -p bifrost-node --test happy_paths --offline
cargo test -p bifrost-node --test adversarial --offline

# Run a single test by name
cargo test -p bifrost-core -- test_name_here

# Format
cargo fmt

# Focused check (quick iteration)
cargo check -p bifrost-core -p bifrost-node --offline
```

## Workspace Architecture

Five crates with a strict dependency hierarchy (lower crates never depend on higher ones):

```
bifrost-node          (orchestration: lifecycle, sign/ecdh flows, batching, event stream)
  ├── bifrost-codec   (RPC envelope encode/decode, wire type conversion, parser helpers)
  ├── bifrost-core    (FROST signing, nonce pool, ECDH, session/group primitives)
  └── bifrost-transport (Transport/Clock/Sleeper traits, message types)

bifrost-transport-ws  (WebSocket Transport impl: reconnect, backoff, relay failover)
  └── bifrost-transport
```

**bifrost-core** — Pure cryptographic operations. Key types: `GroupPackage`, `SharePackage`, `SignSessionPackage`, `NoncePool`. The FROST library is aliased as `frost_secp256k1_tr_unofficial as frost` throughout. Nonce safety is critical: `NoncePool::take_outgoing_signing_nonces` enforces single-use with spent tracking.

**bifrost-codec** — Serialization layer. `rpc` module handles JSON-RPC envelope encode/decode. `wire` module converts between core types and transport-friendly wire types. `parse` module provides typed parser entrypoints (`parse_session`, `parse_ecdh`, `parse_psig`, etc.).

**bifrost-transport** — Trait definitions only. `Transport` trait defines `connect`, `close`, `request`, `cast` (multi-peer threshold gather), `send_response`, `next_incoming`. `Clock` trait abstracts time for testability.

**bifrost-transport-ws** — WebSocket implementation with multi-relay support, health-ranked failover, exponential backoff reconnection, and pending-request cleanup.

**bifrost-node** — `BifrostNode<T: Transport, C: Clock>` is the main orchestrator. It owns the nonce pool, replay cache, ECDH cache, and event emitter. Operations: `echo`, `ping`, `onboard`, `sign`, `sign_batch`, `sign_queue`, `ecdh`, `ecdh_batch`. Node integration tests use mock transport/clock implementations.

## Key Technical Constraints

- **Nonce safety is the top priority.** FROST signing nonces are single-use. The NoncePool tracks spent codes and rejects reuse. Never bypass this.
- **Single-hash enforcement** in `create_partial_sig_package` is intentional — multi-hash batch signing within one session (Option A) is deferred; batch signing uses per-session multiplexing (Option B) via `create_partial_sig_packages_batch`.
- **Rust edition 2024** — the workspace uses `edition = "2024"`.
- **Wire format stability** — codec wire types must remain externally compatible with bifrost-ts.

## Migration Workflow

The `planner/` directory is the source-of-truth for migration state. Use the automation CLI:

```bash
scripts/planner_runbook.sh next          # pick next backlog item
scripts/planner_runbook.sh set-status <TASK_ID> in_progress
scripts/planner_runbook.sh verify        # run verification checks
scripts/planner_runbook.sh set-status <TASK_ID> done
```

After implementing changes, update: `planner/02-parity-matrix.md` (rows touched), `planner/06-test-strategy.md` (test evidence), `planner/05-interfaces.md` (if public API changed), and `planner/07-risks-and-decisions.md` (if new risks/decisions).

## Context Resume

When resuming work on this project, read in order:
1. `docs/current-status.md`
2. `planner/04-backlog.md`
3. `planner/03-milestones.md`
