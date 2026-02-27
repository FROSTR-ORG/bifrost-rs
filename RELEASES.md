# Release Process

This document defines the release workflow for `bifrost-rs`.

## Versioning

Use semantic versioning:

- `MAJOR`: breaking API/protocol behavior
- `MINOR`: backward-compatible features
- `PATCH`: backward-compatible fixes

## Pre-Release Checklist

1. Planner status is consistent:
   - `dev/scripts/planner_runbook.sh summary`
2. Verification gate passes:
   - `dev/scripts/planner_runbook.sh verify`
3. Runtime smoke/e2e passes:
   - `scripts/devnet.sh smoke`
   - `scripts/test-node-e2e.sh`
   - `scripts/test-tui-e2e.sh`
4. Docs are updated:
   - `README.md`
   - `dev/artifacts/current-status.md`
   - `dev/artifacts/release-checklist-v0.1.0.md` (or next checklist)
   - `dev/audit/AUDIT.md` and `dev/audit/templates/* + dev/audit/work/*`
5. `CHANGELOG.md` updated for the version.

## Release Artifacts

- Tag: `vX.Y.Z`
- Changelog entry in `CHANGELOG.md`
- Any migration notes in `dev/artifacts/migration-guide-ts-to-rs.md`

## Security Gate

Confirm:

- no known critical unresolved vulnerabilities
- recent security-impacting changes include tests
- security guidance in `SECURITY.md` and `docs/SECURITY-MODEL.md` is still accurate
