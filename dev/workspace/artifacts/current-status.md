# Current Status

Date baseline: 2026-02-27

## Implemented

- Workspace split into crates under `crates/`.
- Core:
- group/session determinism and validation.
- stricter sign-session invariants: canonical member ordering, duplicate-member rejection, group membership/threshold enforcement.
- sign flow with FROST integration for single-message and single-session multi-hash batch path.
- core batch-sign helpers with indexed hash-entry binding (`create_partial_sig_package`, `create_partial_sig_packages_batch`, `combine_signatures`, `combine_signatures_batch`).
- nonce pool integration with FROST signing nonce state.
- deterministic FIFO incoming nonce consumption semantics.
- one-time outgoing nonce claim guardrail with reuse-rejection test and atomic multi-claim (`take_outgoing_signing_nonces_many`).
- ecdh package generation/combination.
- utility parity modules: `validate` and `sighash`.
- Codec:
- rpc envelope encode/decode.
- wire conversion between core and transport types.
- strict envelope/wire payload shape and bounds rejection with codec tests.
- explicit parser helper parity module (`parse_session`, `parse_ecdh`, `parse_psig`, `parse_onboard_*`, `parse_ping`, group/share package parsers).
- package helper module (`encode/decode_group_package_json`, `encode/decode_share_package_json`).
- Node:
- lifecycle and operational APIs (`echo`, `ping`, `onboard`, `sign`, `ecdh`).
- inbound message handling.
- sign-session validation guards and negative-path tests.
- sender/member binding enforcement in inbound handlers.
- replay/idempotency protections for request IDs with stale-envelope rejection.
- payload limit enforcement controls on inbound envelopes/payloads.
- `sign_batch` now uses Option-A single-session multi-hash orchestration with indexed nonce/signature binding.
- Queue batchers implemented: `sign_queue` and `ecdh_batch`.
- ECDH TTL/LRU cache implemented in node options/runtime behavior.
- Node event stream/emitter parity implemented (`subscribe_events` with lifecycle/message/info/error/bounced events).
- facade parity surface added: `NodeClient`, `Signer`, `NoncePoolView`, `NodeMiddleware` hooks.
- stateless sign/ECDH protocol layer extracted in `frostr-utils::protocol` and consumed by `bifrost-node` (`sign_create_partial`/`sign_verify_partial`/`sign_finalize`, `ecdh_create_from_share`/`ecdh_finalize`).
- Planner:
- complete migration planning artifact set under `dev/planner/`.
- Transport WS:
- connection state model, reconnect/backoff retry configuration, and relay health/failover ordering implemented in `bifrost-transport-ws`.
- Runtime:
- `bifrost-rpc` schema/client helpers for local daemon RPC.
- `bifrost-devtools` crate consolidates relay + keygen tooling (`relay` ports TS dev relay behavior with BIP-340 verify; `keygen` generates local group/share/daemon configs).
- `bifrostd` daemon target with unix-socket JSON-RPC and background node inbound/event loops.
- `bifrostd` control-plane hardening: fail-closed auth defaults, explicit dev-only insecure bypass flag, bounded RPC line framing (`64 KiB`), and enforced socket permission mode (`0600`).
- `bifrost-cli` and `bifrost-tui` targets connect to `bifrostd` RPC (`bifrost-tui` now uses a pane-based `ratatui`/`crossterm` MVP).
- `bifrost-tui` supports scripted execution mode (`--script`) for deterministic automation/e2e runs.
- `bifrost-tui` includes a high-contrast colorful operator theme with semantic output styling and active-target HUD (`use <peer>`).
- `bifrost-tui` peer operations accept selector forms (`index`, aliases `alice|bob|carol`, pubkey-prefix) and status panel now reports per-peer nonce pool health with `theirs/ours` progress bars derived from daemon nonce-pool thresholds.
- `bifrost-tui` testing ergonomics support text-first signing (`sign <text...>` hashed via SHA-256), explicit digest modes (`sign hex:<hex32>` / `sign 0x<hex32>`), alias-first `ecdh <peer>`, and echo shorthand (`echo <message...>` routed to active target).
- Peer policy parity shipped with hard-break config/RPC schema: granular per-peer `request/respond` method policy + `block_all`, daemon/runtime policy mutation APIs, ping-scoped policy profile sync, explicit policy-denied peer error payloads, and randomized eligible peer selection for sign/ECDH (including sign nonce-availability gate).
- `bifrost-tui` status/events/output panes use tail-follow rendering so latest activity stays visible.
- `scripts/devnet.sh` orchestrates `gen/start/status/stop/smoke` across relay + three daemons.
- `scripts/devnet-tmux.sh` launches a 4-pane tmux demo layout (relay log + alice/bob/carol TUIs).

## Verified Test Baseline

- `cargo test -p bifrost-core -p bifrost-codec -p bifrost-node -p bifrost-transport-ws --offline` passes.
- `cargo check -p bifrost-devtools -p bifrostd -p bifrost-cli -p bifrost-tui --offline` passes.
- `cargo test -p bifrostd --offline` passes (auth policy and oversized-line guard tests).
- `cargo test -p bifrost-devtools -p bifrost-rpc --offline` passes.
- `scripts/devnet.sh smoke` passes (relay + `bifrostd-{alice,bob,carol}` + CLI `health/status/events`).
- `cargo test -p bifrost-node --test happy_paths --offline` includes explicit per-method RPC e2e coverage (`echo`, `ping`, `onboard`, `sign`, `ecdh`).
- `cargo test -p bifrost-cli --test e2e_cli --offline` validates CLI command-to-RPC mapping across all RPC methods (requires local Unix socket bind permission in execution environment).
- `cargo test -p bifrost-codec --test fixture_matrix --offline` validates fixture-driven RPC/session/onboard edge-case corpus (`crates/bifrost-codec/tests/fixtures/rpc_parse_matrix.json`).
- `cargo test -p bifrost-node --test fault_injection --offline` validates multi-node fault scenarios (partial quorum timeout, delayed peers, churn recovery, delayed ECDH success).
- `scripts/test-tui-e2e.sh` runs devnet-backed TUI e2e against real daemons and exercises all protocol RPC methods (`ping`, `echo`, `ecdh`, `sign`, `onboard`) via scripted TUI commands.
- Node integration tests pass:
- `cargo test -p bifrost-node --test happy_paths --offline`
- `cargo test -p bifrost-node --test adversarial --offline`
- `cargo test -p frostr-utils --offline` includes stateless protocol roundtrip coverage for sign and ECDH helpers.

## Open Gaps

- No open parity rows in `dev/planner/02-parity-matrix.md` (27/27 done).
- Remaining work is non-parity hardening:
  - recurring long-duration WS forced-fault soak runs with archived evidence (`dev/scripts/ws_soak.sh`).
  - maintain CI coverage artifact trend (`coverage` job in `.github/workflows/ci.yml` using `cargo llvm-cov`).
  - accepted transitive advisory monitoring (`RUSTSEC-2023-0089`), owner `security/runtime`, next review `2026-03-31`.

## Repository State Notes

- Git history was reset to remove polluted initial commit.
- Root `.gitignore` now excludes build artifacts and common local outputs.
- `target/` files are ignored.
