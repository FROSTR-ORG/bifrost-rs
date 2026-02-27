# Internal Audit Report (2026-02-27)

## Summary

- Audit status: `conditional_pass`
- Blocking item for full security gate: `cargo-audit` unavailable in current environment.
- Core/runtime/devnet checks passed when executed serially.

## Evidence

1. `cargo check --workspace --offline`  
Result: pass

2. `cargo test -p bifrost-core -p bifrost-codec -p bifrost-node -p bifrost-transport-ws --offline`  
Result: pass

3. `cargo test -p bifrost-relay-dev -p bifrost-rpc --offline`  
Result: pass

4. `scripts/test-node-e2e.sh`  
Result: pass

5. `scripts/test-tui-e2e.sh`  
Result: pass

6. `dev/scripts/planner_runbook.sh summary`  
Result: pass

## Findings

1. `cargo-audit` tool gap  
- Command `cargo audit -V` failed with: `no such command: audit`.  
- Impact: supply-chain vulnerability scan gate not satisfied yet.

2. Devnet e2e script concurrency caveat  
- Running `scripts/test-node-e2e.sh` and `scripts/test-tui-e2e.sh` in parallel can produce false failures due to shared `dev/data` artifacts.  
- Resolution: run these scripts sequentially during audit/release.

## Recommended Follow-Ups

1. Install `cargo-audit` in CI/release environment and add report attachment to audit artifacts.
2. Keep devnet e2e execution serialized in runbooks/checklists.
