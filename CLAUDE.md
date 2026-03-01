# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

bifrost-rs is a Rust workspace implementing a FROST threshold signing protocol coordinator for Nostr, using `frost-secp256k1-tr-unofficial` for the underlying cryptography. It was migrated from `bifrost-ts` (TypeScript) with full behavior parity (53/53 items complete). The FROST library is aliased as `frost_secp256k1_tr_unofficial as frost` throughout.

## Build & Test Commands

```bash
# Check all crates
cargo check --workspace --offline

# Lint
cargo clippy --workspace --all-targets --offline --no-deps

# Format check
cargo fmt --all -- --check

# Run all unit/integration tests (offline, no network)
cargo test -p bifrost-core -p bifrost-codec -p bifrost-node -p bifrost-transport-ws --offline
cargo test -p bifrost-devtools -p bifrost-rpc -p bifrostd -p frostr-utils --offline

# Run a single crate's tests
cargo test -p bifrost-core --offline

# Run a specific test file (integration tests)
cargo test -p bifrost-node --test happy_paths --offline
cargo test -p bifrost-node --test adversarial --offline
cargo test -p bifrost-node --test fault_injection --offline
cargo test -p bifrost-codec --test fixture_matrix --offline
cargo test -p bifrost-cli --test e2e_cli --offline

# Run a single test by name
cargo test -p bifrost-core -- test_name_here

# Format
cargo fmt

# Focused check (quick iteration)
cargo check -p bifrost-core -p bifrost-node --offline

# Local devnet (relay + 3 daemons)
scripts/devnet.sh gen      # generate test keys/configs
scripts/devnet.sh start    # start relay + alice/bob/carol daemons
scripts/devnet.sh smoke    # health/status/events smoke test
scripts/devnet.sh stop     # stop everything

# Runtime E2E tests (require running devnet)
scripts/test-node-e2e.sh
scripts/test-tui-e2e.sh
```

## Workspace Architecture

Eleven crates in a strict dependency hierarchy (lower crates never depend on higher ones):

### Protocol Layer

```
bifrost-node          (orchestration: lifecycle, sign/ecdh flows, batching, event stream)
  ├── bifrost-codec   (RPC envelope encode/decode, wire type conversion, parser helpers)
  ├── bifrost-core    (FROST signing, nonce pool, ECDH, session/group primitives)
  ├── bifrost-transport (Transport/Clock/Sleeper traits, message types)
  └── frostr-utils    (keyset lifecycle, onboarding packages, stateless sign/ECDH helpers)

bifrost-transport-ws  (WebSocket Transport impl: reconnect, backoff, relay failover)
  └── bifrost-transport
```

**bifrost-core** — Pure cryptographic operations. Key types: `GroupPackage`, `SharePackage`, `SignSessionPackage`, `NoncePool`. Nonce safety is critical: `NoncePool::take_outgoing_signing_nonces` enforces single-use with spent tracking.

**bifrost-codec** — Serialization layer. `rpc` module handles JSON-RPC envelope encode/decode. `wire` module converts between core types and transport-friendly wire types. `parse` module provides typed parser entrypoints (`parse_session`, `parse_ecdh`, `parse_psig`, etc.).

**bifrost-transport** — Trait definitions only. `Transport` trait defines `connect`, `close`, `request`, `cast` (multi-peer threshold gather), `send_response`, `next_incoming`. `Clock` trait abstracts time for testability.

**bifrost-transport-ws** — WebSocket implementation with multi-relay support, health-ranked failover, exponential backoff reconnection, and pending-request cleanup.

**bifrost-node** — `BifrostNode<T: Transport, C: Clock>` is the main orchestrator. It owns the nonce pool, replay cache, ECDH cache, and event emitter. Operations: `echo`, `ping`, `onboard`, `sign`, `sign_batch`, `sign_queue`, `ecdh`, `ecdh_batch`. Node integration tests use mock transport/clock implementations.

**frostr-utils** — Shared utility crate for keyset lifecycle (create/verify/rotate/recover), onboarding package helpers (bech32m encode/decode, binary serialization), and stateless protocol helpers consumed by `bifrost-node` (`sign_create_partial`/`sign_verify_partial`/`sign_finalize`, `ecdh_create_from_share`/`ecdh_finalize`).

### Runtime Layer

```
bifrostd              (headless daemon: unix-socket JSON-RPC, wraps node + transport-ws)
  ├── bifrost-rpc     (shared RPC schema/envelope types, DaemonClient helper)
  ├── bifrost-node
  └── bifrost-transport-ws

bifrost-cli           (scriptable CLI client over bifrostd RPC)
  └── bifrost-rpc

bifrost-tui           (ratatui interactive operator dashboard over bifrostd RPC)
  └── bifrost-rpc

bifrost-devtools      (keygen + local Nostr relay for dev/test)
```

**bifrostd** — Headless daemon exposing local JSON-RPC over a Unix socket. Fail-closed auth defaults, bounded RPC line framing (64 KiB), enforced socket permission mode (0600). Config: `--config ./dev/data/daemon-alice.json`.

**bifrost-rpc** — Newline-delimited JSON over Unix sockets. Envelope types (`RpcRequestEnvelope`/`RpcResponseEnvelope`), method definitions, and `DaemonClient` helper shared by CLI and TUI.

**bifrost-tui** — `ratatui`/`crossterm` dashboard with scripted execution mode (`--script`), peer selectors (index/alias/pubkey-prefix), and per-peer policy controls.

**bifrost-devtools** — `keygen` (generate group/share/daemon configs) and `relay` (local Nostr relay with BIP-340 verify).

## Key Technical Constraints

- **Nonce safety is the top priority.** FROST signing nonces are single-use. The NoncePool tracks spent codes and rejects reuse. Never bypass this.
- **Single-hash enforcement** in `create_partial_sig_package` is intentional — batch signing uses Option-A single-session multi-hash orchestration via `create_partial_sig_packages_batch`.
- **Rust edition 2024** — the workspace uses `edition = "2024"`.
- **Wire format stability** — codec wire types must remain externally compatible with bifrost-ts.
- **Sender/member binding** — inbound handlers enforce that the sender is a valid group member for the session.
- **Replay protection** — node enforces request-ID replay/idempotency with stale-envelope rejection.

## Planner

This project uses a `.planner/` system for tracking agent-driven work.

- Read `.planner/context.md` for project identity and constraints.
- Read `.planner/handoff.md` for current state and session context.
- Check `.planner/backlog.md` for pending work items.
- Plans in `.planner/plans/` are active work proposals; completed plans live in `.planner/done/`.
- Use `.planner/templates/` for standard artifact structures.
- Append to `.planner/work.log` when starting or completing work.
- To execute the plans queue, follow `.planner/runbook.md`.
