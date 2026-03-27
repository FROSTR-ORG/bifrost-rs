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
1. Verification gates pass:
   - `cargo fmt --all -- --check`
   - `cargo clippy --workspace --all-targets --offline --no-deps -- -D warnings`
   - `cargo check --workspace --offline`
   - `cargo test --workspace --offline`
2. Repository-owned verification gates and runtime integration tests pass.
3. Any required host-owned runtime smoke/e2e evidence for this release has been collected separately.
4. Docs are updated:
   - `README.md`
   - repo-local `docs/*` manuals that still exist (`API.md`, `ARCHITECTURE.md`, `CONFIGURATION.md`, `OPERATIONS.md`, `TROUBLESHOOTING.md`, `SECURITY-MODEL.md`, `docs/frostr-utils/*`) as applicable
   - `CONTRIBUTING.md`
   - `TESTING.md`
   - `SECURITY.md`
   - `RELEASE.md`
   - `dev/artifacts/current-status.md`
   - `dev/audit/checklist-vX.Y.Z.md` (for the release candidate)
   - `dev/audit/AUDIT.md`
5. `CHANGELOG.md` updated for the version.
6. Security scan captured:
   - `cargo audit | tee dev/audit/work/evidence/cargo-audit-<date>.log`

## Release Artifacts

- Tag: `vX.Y.Z`
- Changelog entry in `CHANGELOG.md`
- Any migration notes in `dev/artifacts/migration-guide-ts-to-rs.md`
- Security scan artifact from CI (`cargo-audit-report`)

## Security Gate

Confirm:

- no known critical unresolved vulnerabilities
- recent security-impacting changes include tests
- security guidance in `SECURITY.md` and `docs/SECURITY-MODEL.md` is still accurate for this repo
- `cargo audit` report is attached for the release candidate
