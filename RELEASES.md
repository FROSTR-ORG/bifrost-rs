# Release Process

This document defines the release workflow for `bifrost-rs`.

## Versioning

Use semantic versioning:

- `MAJOR`: breaking API/protocol behavior
- `MINOR`: backward-compatible features
- `PATCH`: backward-compatible fixes

## Pre-Release Checklist

0. Execution environment prerequisites are present:
   - `dev/scripts/toolchain_preflight.sh --require-cargo --require-cargo-audit`
1. Planner status is consistent:
   - `dev/scripts/planner_runbook.sh summary`
2. Verification gate passes:
   - `dev/scripts/planner_runbook.sh verify`
3. Runtime smoke/e2e passes:
   - `scripts/devnet.sh smoke`
   - `scripts/test-node-e2e.sh`
   - `scripts/test-tui-e2e.sh`
4. WS forced-fault soak evidence captured:
   - `dev/scripts/ws_soak.sh --iterations 25 --out dev/audit/work/evidence/ws-soak-<date>.txt`
5. Docs are updated:
   - `README.md`
   - `dev/artifacts/current-status.md`
   - `dev/audit/checklist-v0.1.0.md` (or next checklist)
   - `dev/audit/AUDIT.md` and `dev/audit/templates/* + dev/audit/work/*`
6. `CHANGELOG.md` updated for the version.

## Release Artifacts

- Tag: `vX.Y.Z`
- Changelog entry in `CHANGELOG.md`
- Any migration notes in `dev/artifacts/migration-guide-ts-to-rs.md`
- Security scan artifact from CI (`cargo-audit-report`)

## Security Gate

Confirm:

- no known critical unresolved vulnerabilities
- recent security-impacting changes include tests
- security guidance in `SECURITY.md` and `docs/SECURITY-MODEL.md` is still accurate
- `cargo audit` report is attached for the release candidate
