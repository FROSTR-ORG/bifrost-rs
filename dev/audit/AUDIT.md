# Package Audit Guide

This document defines how to run a release-quality, category-based audit for `bifrost-rs`.

## Scope

- Architecture
- Completeness
- Separation/contracts/boundaries
- Security
- Technical debt
- Code smell
- Readability
- Documentation
- Testing quality
- Reliability/operability
- Release/supply-chain readiness

## Audit Inputs

- Governance docs: `CONTRIBUTING.md`, `TESTING.md`, `RELEASE.md`, `SECURITY.md`.
- Current runtime status snapshot: `dev/artifacts/current-status.md`.
- Prior audit artifacts: `dev/audit/`.
- Execution model: `dev/audit/RUNBOOK.md`.

## Run Layout

Use a single working folder for each execution:

`dev/audit/work/`

Required files:

- `00-index.md`
- `01-architecture.md`
- `02-completeness.md`
- `03-separation-boundaries.md`
- `04-security.md`
- `05-technical-debt.md`
- `06-code-smell.md`
- `07-readability.md`
- `08-documentation.md`
- `09-testing-quality.md`
- `10-reliability-operability.md`
- `11-release-supply-chain.md`
- `99-summary.md`

## Command Matrix

Run from repo root:

```bash
dev/scripts/toolchain_preflight.sh --require-cargo --require-cargo-audit
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --offline --no-deps -- -D warnings
cargo check --workspace --offline
cargo test --workspace --offline
cargo run -p bifrost-dev --bin bifrost-devtools --offline -- e2e-node --out-dir dev/data --relay ws://127.0.0.1:8194
scripts/devnet.sh smoke
scripts/test-node-e2e.sh
scripts/test-tui-e2e.sh
cargo audit | tee dev/audit/work/evidence/cargo-audit.log
```

## Execution Rules

- Run devnet e2e scripts sequentially; they share `dev/data` state.
- Record command, date, result, and notable findings.
- If a command fails, capture the blocker and do not mark audit green.
- Use category status values: `pass`, `conditional_pass`, `fail`.
- Use finding severities: `critical`, `high`, `medium`, `low`, `info`.

## Outputs

- Run index + category markdowns + run summary under `dev/audit/work/`
- Checklist update: `dev/audit/checklist-v0.1.0.md`
- Audit baseline report: `dev/audit/internal-audit-YYYY-MM-DD.md`
- Any release-impacting blocker must be reflected in `RELEASE.md` and audit artifacts.

## Recommended Scaffolding

Use `dev/audit/templates/` to scaffold new run files and agent coordination artifacts.
