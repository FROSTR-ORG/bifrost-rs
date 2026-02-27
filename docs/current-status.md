# Current Status

Date baseline: 2026-02-27

## Implemented

- Workspace split into crates under `crates/`.
- Core:
- group/session determinism and validation.
- sign flow with FROST integration for current single-message path.
- nonce pool integration with FROST signing nonce state.
- ecdh package generation/combination.
- Codec:
- rpc envelope encode/decode.
- wire conversion between core and transport types.
- Node:
- lifecycle and operational APIs (`echo`, `ping`, `onboard`, `sign`, `ecdh`).
- inbound message handling.
- sign-session validation guards and negative-path tests.
- Planner:
- complete migration planning artifact set under `planner/`.

## Verified Test Baseline

- `cargo test -p bifrost-core -p bifrost-node --offline` passes.
- Workspace-wide offline check is limited by uncached WS dependencies.

## Open Gaps

- Transport WS production hardening: reconnect/failover/health.
- Batch signing parity with safe nonce lifecycle.
- TS class parity gaps:
- batchers
- cache
- emitter/event model
- stricter security policy parity:
- sender/member binding hardening
- replay/idempotency protections
- payload limits and schema strictness.

## Repository State Notes

- Git history was reset to remove polluted initial commit.
- Root `.gitignore` now excludes build artifacts and common local outputs.
- `target/` files are ignored.
