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
2. Runtime smoke/e2e passes:
   - `cargo run -p igloo-shell-cli --manifest-path ../igloo-shell/Cargo.toml --offline -- e2e-node --out-dir dev/data --relay ws://127.0.0.1:8194`
   - `cargo run -p igloo-shell-cli --manifest-path ../igloo-shell/Cargo.toml --offline -- e2e-full --threshold 11 --count 15`
   - `../igloo-shell/scripts/devnet.sh smoke`
   - `../igloo-shell/scripts/test-node-e2e.sh`
   - `../igloo-shell/scripts/test-tui-e2e.sh`
3. WS forced-fault soak evidence captured:
   - `../igloo-shell/dev/scripts/ws_soak.sh --iterations 25 --out dev/audit/work/evidence/ws-soak-<date>.txt`
4. Docs are updated:
   - `README.md`
   - `docs/*` (as applicable)
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
- security guidance in `SECURITY.md` and `docs/SECURITY-MODEL.md` is still accurate
- `cargo audit` report is attached for the release candidate
