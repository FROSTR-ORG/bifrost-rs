# Current Status

Date baseline: 2026-02-27

## Implemented

- Workspace split into crates under `crates/`.
- Core:
- group/session determinism and validation.
- sign flow with FROST integration for current single-message path.
- core batch-sign helpers implemented with nonce/session count guards (`create_partial_sig_packages_batch`, `combine_signatures_batch`).
- nonce pool integration with FROST signing nonce state.
- one-time outgoing nonce claim guardrail with reuse-rejection test.
- ecdh package generation/combination.
- Codec:
- rpc envelope encode/decode.
- wire conversion between core and transport types.
- strict envelope/wire payload shape and bounds rejection with codec tests.
- explicit parser helper parity module (`parse_session`, `parse_ecdh`, `parse_psig`, `parse_onboard_*`, `parse_ping`, group/share package parsers).
- Node:
- lifecycle and operational APIs (`echo`, `ping`, `onboard`, `sign`, `ecdh`).
- inbound message handling.
- sign-session validation guards and negative-path tests.
- sender/member binding enforcement in inbound handlers.
- replay/idempotency protections for request IDs with stale-envelope rejection.
- payload limit enforcement controls on inbound envelopes/payloads.
- `sign_batch` API added with safe per-message session multiplexing fallback.
- Queue batchers implemented: `sign_queue` and `ecdh_batch`.
- ECDH TTL/LRU cache implemented in node options/runtime behavior.
- Node event stream/emitter parity implemented (`subscribe_events` with lifecycle/message/info/error/bounced events).
- Planner:
- complete migration planning artifact set under `dev/planner/`.
- Transport WS:
- connection state model, reconnect/backoff retry configuration, and relay health/failover ordering implemented in `bifrost-transport-ws`.
- Runtime:
- `bifrost-rpc` schema/client helpers for local daemon RPC.
- `bifrost-relay-dev` crate ports the TS dev relay behavior (`REQ`/`EVENT`/`CLOSE`, cache/subscriptions/filtering, BIP-340 event verification).
- `bifrost-devnet` crate generates local group/share/daemon configs for multi-node setups.
- `bifrostd` daemon target with unix-socket JSON-RPC and background node inbound/event loops.
- `bifrost-cli` and `bifrost-tui` targets connect to `bifrostd` RPC (`bifrost-tui` now uses a pane-based `ratatui`/`crossterm` MVP).
- `bifrost-tui` supports scripted execution mode (`--script`) for deterministic automation/e2e runs.
- `bifrost-tui` peer operations accept selector forms (`index`, aliases `alice|bob|carol`, pubkey-prefix) and status panel now reports per-peer nonce pool health with `theirs/ours` progress bars derived from daemon nonce-pool thresholds.
- `bifrost-tui` status/events/output panes use tail-follow rendering so latest activity stays visible.
- `scripts/devnet.sh` orchestrates `gen/start/status/stop/smoke` across relay + three daemons.
- `scripts/devnet-tmux.sh` launches a 4-pane tmux demo layout (relay log + alice/bob/carol TUIs).

## Verified Test Baseline

- `cargo test -p bifrost-core -p bifrost-codec -p bifrost-node -p bifrost-transport-ws --offline` passes.
- `cargo check -p bifrost-relay-dev -p bifrostd -p bifrost-cli -p bifrost-tui --offline` passes.
- `cargo test -p bifrost-relay-dev -p bifrost-rpc --offline` passes.
- `scripts/devnet.sh smoke` passes (relay + `bifrostd-{alice,bob,carol}` + CLI `health/status/events`).
- `cargo test -p bifrost-node --test happy_paths --offline` includes explicit per-method RPC e2e coverage (`echo`, `ping`, `onboard`, `sign`, `ecdh`).
- `cargo test -p bifrost-cli --test e2e_cli --offline` validates CLI command-to-RPC mapping across all RPC methods (requires local Unix socket bind permission in execution environment).
- `scripts/test-tui-e2e.sh` runs devnet-backed TUI e2e against real daemons and exercises all protocol RPC methods (`ping`, `echo`, `ecdh`, `sign`, `onboard`) via scripted TUI commands.
- Node integration tests pass:
- `cargo test -p bifrost-node --test happy_paths --offline`
- `cargo test -p bifrost-node --test adversarial --offline`

## Open Gaps

- Transport WS forced-fault integration coverage for reconnect/failover remains open.
- Runtime hardening gaps remain for `bifrostd` stack: rpc authn/authz, compatibility/version negotiation, and full multi-node devnet orchestration scripts.
- Node-level Option-A single-session multi-hash orchestration (Option-B path is implemented).
- TS class parity gaps:
- stricter security policy parity:
- deeper schema utility parity with TS helpers.

## Repository State Notes

- Git history was reset to remove polluted initial commit.
- Root `.gitignore` now excludes build artifacts and common local outputs.
- `target/` files are ignored.
