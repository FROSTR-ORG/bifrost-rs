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
   - `TESTING.md`
   - `CONTRIBUTING.md`
   - `SECURITY.md`
   - `RELEASE.md`
   - `dev/artifacts/current-status.md`
   - `dev/audit/checklist-vX.Y.Z.md` (for the release candidate)
   - `dev/audit/AUDIT.md`
5. `CHANGELOG.md` updated for the version.
6. Security scan captured:
   - `cargo audit | tee dev/audit/work/evidence/cargo-audit-<date>.log`

## Release Artifacts

- tag: `vX.Y.Z`
- changelog entry in `CHANGELOG.md`
- any migration notes in `dev/artifacts/migration-guide-ts-to-rs.md`
- security scan artifact from CI (`cargo-audit-report`)

## Security Gate

Confirm:

- no known critical unresolved vulnerabilities
- recent security-impacting changes include tests
- security guidance in `SECURITY.md` and the root architecture/process docs is still accurate for this repo
- `cargo audit` report is attached for the release candidate

## Repo-Specific Release Notes Checklist

Before tagging, confirm the root docs still reflect reality for:
- crate ownership and hosted runtime boundaries
- current package and backup ownership in `frostr-utils`
- runtime config semantics
- verification commands and targeted release checks
- operational expectations around logs, state, and run markers
