# bifrost-rs v0.1.0 Release Checklist

Date: 2026-02-27
Owner: release lead
Scope: workspace crates + docs/examples + CI

## 1. Code + Parity Gates

- [x] Planner backlog complete (`20/20 done`).
  - Evidence: `./dev/scripts/planner_runbook.sh summary`
- [x] Milestones M1-M8 marked done in planner.
  - Evidence: `dev/planner/03-milestones.md`
- [x] Core/node/codec/ws parity artifacts updated.
  - Evidence: `dev/planner/02-parity-matrix.md`, `dev/planner/05-interfaces.md`

## 2. Test Gates

- [x] Workspace tests pass for core/codec/node/ws.
  - Evidence:
  - `cargo test -p bifrost-core -p bifrost-codec -p bifrost-node -p bifrost-transport-ws --offline`
- [x] Node integration happy-path suite passes.
  - Evidence:
  - `cargo test -p bifrost-node --test happy_paths --offline`
- [x] Node adversarial suite passes.
  - Evidence:
  - `cargo test -p bifrost-node --test adversarial --offline`
- [x] Workspace check passes.
  - Evidence:
  - `cargo check --workspace --offline`

## 3. Docs + Examples Gates

- [x] Root and crate READMEs updated for current parity.
  - Evidence:
  - `README.md`
  - `crates/*/README.md`
- [x] TS->Rust migration guide published.
  - Evidence: `dev/artifacts/migration-guide-ts-to-rs.md`
- [x] Node+WS example package added and compiles.
  - Evidence:
  - `contrib/example/`
  - `cargo check -p node_ws_multi_peer_example --offline`

## 4. CI Gates

- [x] CI matrix workflow added.
  - Evidence: `.github/workflows/ci.yml`
- [ ] CI run green on GitHub Actions for merge commit/tag.
  - Evidence: CI URL/artifacts
  - Note: pending remote execution.

## 5. Release Metadata Gates

- [ ] Add package metadata for all publishable crates:
  - `description`
  - `repository`
  - `homepage` (optional)
  - `documentation`
  - `keywords`
  - `categories`
  - `rust-version`
  - Evidence: `crates/*/Cargo.toml`
- [ ] Confirm crate publish policy (which crates are published).
  - Evidence: release notes decision record

## 6. Security + Reliability Gates

- [ ] Dependency/vuln audit pass (`cargo audit`).
  - Evidence: audit output attached
- [ ] WS forced-fault integration reliability suite.
  - Evidence: test artifacts/logs
- [ ] Nonce replenish race scenario test coverage.
  - Evidence: tests + notes in `dev/planner/06-test-strategy.md`

## 7. Release Packaging Gates

- [ ] Changelog/release notes for v0.1.0.
  - Evidence: `CHANGELOG.md` or release notes doc
- [ ] Tag/release process runbook executed.
  - Evidence: tag + release artifact links

## 8. Signoff

- [ ] Engineering signoff
- [ ] Security signoff
- [ ] Release manager signoff

---

## Execution Snapshot (this run)

Completed in this run:
- M5-001 (queue batchers)
- M6-001 (cross-crate happy-path integration)
- M6-002 (adversarial integration)
- M7-001 (README/doc updates)
- M7-002 (node+ws example)
- M8-001 (CI matrix)
- M8-002 (migration guide)

Commands executed successfully:
- `./dev/scripts/planner_runbook.sh verify`
- `cargo test -p bifrost-core -p bifrost-codec -p bifrost-node -p bifrost-transport-ws --offline`
- `cargo test -p bifrost-node --test happy_paths --offline`
- `cargo test -p bifrost-node --test adversarial --offline`
- `cargo check --workspace --offline`
