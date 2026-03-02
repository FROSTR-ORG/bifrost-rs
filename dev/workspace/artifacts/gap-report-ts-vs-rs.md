# Gap Report: `bifrost-ts` vs `bifrost-rs`

Date: 2026-02-27
Scope baseline:
- TS source and demo: `FROSTR-ORG/bifrost`
- RS parity source: `dev/planner/02-parity-matrix.md`

## Executive Summary

Parity closure work is complete for mapped migration scope. The previous open rows (sign orchestration, nonce model evidence, class facades, schema/types utility helpers, validate/sighash/package helpers) are now implemented and evidence-linked in planner artifacts.

Residual differences are intentional architecture choices (daemon runtime split, Rust-native utility/facade shape), not unresolved parity defects.

## Coverage Snapshot

From `dev/planner/02-parity-matrix.md`:
- total mapped rows: `27`
- `done`: `27`
- `in_progress`: `0`
- `todo`: `0`

## Closed Items In This Pass

1. Option-A-only sign orchestration
- `sign_batch` now executes single-session multi-hash flow with indexed nonce/signature binding.

2. Nonce parity evidence
- Added atomic multi-claim path (`take_outgoing_signing_nonces_many`) and indexed malformed-session rejects.

3. Class parity facades
- Added `NodeClient`, `Signer`, `NoncePoolView` and middleware hook surface.

4. Utility parity
- Added `bifrost-core::validate` and `bifrost-core::sighash` modules with tests.

5. Package/schema/types parity
- Added `bifrost-codec::package` helpers and updated indexed sign-session wire/type surfaces.

## Verification Evidence (Current)

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --offline --no-deps`
- `cargo check --workspace --offline`
- `cargo test -p bifrost-core -p bifrost-codec -p bifrost-node --offline`
- `scripts/test-node-e2e.sh`
- `scripts/test-tui-e2e.sh`
- `dev/scripts/planner_runbook.sh verify`
- `cargo audit` (warning-only accepted risk `RUSTSEC-2023-0089`)

## Remaining Risks (Non-Parity)

- Accepted transitive advisory warning (`atomic-polyfill`) via Frost dependency chain remains tracked as release-cycle accepted risk until upstream updates.
- WS transport long-duration forced-fault reliability depth remains an operability hardening area.

## Evidence References

- Parity matrix: `dev/planner/02-parity-matrix.md`
- Interfaces: `dev/planner/05-interfaces.md`
- Tests/gates: `dev/planner/06-test-strategy.md`
- Audit checklist/report: `dev/audit/checklist-v0.1.0.md`, `dev/audit/internal-audit-2026-02-27.md`
