# bifrost-rs Audit Checklist (v0.1.0)

Date: 2026-02-27

## Build + Test Gates

- [x] `dev/scripts/toolchain_preflight.sh --require-cargo --require-cargo-audit`
- [x] `cargo fmt --all -- --check`
- [x] `cargo clippy --workspace --all-targets --offline --no-deps`
- [x] `cargo check --workspace --offline`
- [x] `cargo test -p bifrost-core -p bifrost-codec -p bifrost-node -p bifrost-transport-ws --offline`
- [x] `cargo test -p bifrost-devtools -p bifrost-rpc --offline`
- [x] `scripts/test-node-e2e.sh` (run sequentially; hardened cold-start handling)
- [x] `scripts/test-tui-e2e.sh` (run sequentially; hardened cold-start handling)

## Planning + Governance Gates

- [x] Planner backlog parses cleanly and status counts are consistent.
- [x] `dev/scripts/planner_runbook.sh summary`
- [x] `dev/scripts/planner_runbook.sh verify`
- [x] Root governance docs present (`CONTRIBUTING.md`, `TESTING.md`, `RELEASES.md`, `SECURITY.md`, `CHANGELOG.md`)

## Security + Supply Chain Gates

- [x] `cargo audit` executed
- [x] `cargo audit` vulnerability-free result
- [x] Advisory warning triage complete
  - Current accepted-risk: `RUSTSEC-2023-0089` (`atomic-polyfill`, transitive via Frost dependency chain)
  - Owner: `security/runtime`; next review date: `2026-03-31`
- [x] Security model doc aligned with runtime boundaries (`docs/SECURITY-MODEL.md`)

## Signoff

- [ ] Engineering signoff
- [ ] Security signoff
- [ ] Release signoff
