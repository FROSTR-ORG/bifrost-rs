# AGENTS.md

Guidance for AI/code agents working in this repository.

## Mission

Migrate `bifrost-ts` to Rust with behavior parity and stronger safety.

## First-Read Files

1. `README.md`
2. `CONTRIBUTING.md`
3. `SECURITY.md`
4. `TESTING.md`
5. `RELEASES.md`
6. `docs/INDEX.md`
7. `docs/GUIDE.md`
8. `dev/artifacts/current-status.md`
9. `dev/planner/README.md`
10. `dev/planner/04-backlog.md`

## Documentation Structure

- `docs/` is the product manual and knowledgebase for `bifrost-rs` users and integrators.
- Root governance docs (`CONTRIBUTING.md`, `TESTING.md`, `RELEASES.md`, `SECURITY.md`, `CHANGELOG.md`) define project policy and operational process.
- Agent-oriented planning source-of-truth: `dev/planner/`
- Agent-oriented execution/context artifacts: `dev/artifacts/`

## Workflow Requirements

1. Treat `dev/planner/` as source-of-truth for migration state.
2. Use `dev/scripts/planner_runbook.sh` to inspect and update execution status.
3. Before implementing:
- pick a backlog item from `dev/scripts/planner_runbook.sh next`
- set status to `in_progress` (`dev/scripts/planner_runbook.sh set-status <TASK_ID> in_progress`)
4. After implementing:
- run `dev/scripts/planner_runbook.sh verify`
- update parity matrix rows
- update test evidence
- update milestones/risk/decision logs if changed
5. Only mark backlog item `done` with concrete evidence.
6. Keep root governance docs (`CONTRIBUTING.md`, `TESTING.md`, `RELEASES.md`, `SECURITY.md`, `CHANGELOG.md`) aligned with implementation reality.

## Technical Constraints

- Keep cryptographic correctness and nonce safety as top priority.
- Preserve protocol behavior unless deviation is explicitly documented.
- Prefer additions to tests over assumptions.
- Avoid changing public API without updating `dev/planner/05-interfaces.md`.

## Current High-Priority Work

- `M1-001`: safe batch-sign nonce model.
- `M2-001`: strict codec payload validation.
- `M3-001`: sender/member binding enforcement.

## Repository Notes

- Root `.gitignore` ignores build artifacts (`target/`) and common local outputs.
- Workspace was reset to remove a polluted initial commit; ensure future commits stay clean.
- `bifrost-transport-ws` remains partially implemented for production reliability features.
- Canonical technical docs live in `docs/` and must be updated alongside behavior changes.
