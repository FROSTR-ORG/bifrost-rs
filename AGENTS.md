# AGENTS.md

Guidance for AI/code agents working in this repository.

## Mission

Migrate `bifrost-ts` to Rust with behavior parity and stronger safety.

## First-Read Files

1. `README.md`
2. `docs/README.md`
3. `docs/current-status.md`
4. `planner/README.md`
5. `planner/04-backlog.md`

## Workflow Requirements

1. Treat `planner/` as source-of-truth for migration state.
2. Before implementing:
- pick a backlog item
- set status to `in_progress`
3. After implementing:
- update parity matrix rows
- update test evidence
- update milestones/risk/decision logs if changed
4. Only mark backlog item `done` with concrete evidence.

## Technical Constraints

- Keep cryptographic correctness and nonce safety as top priority.
- Preserve protocol behavior unless deviation is explicitly documented.
- Prefer additions to tests over assumptions.
- Avoid changing public API without updating `planner/05-interfaces.md`.

## Current High-Priority Work

- `M1-001`: safe batch-sign nonce model.
- `M2-001`: strict codec payload validation.
- `M3-001`: sender/member binding enforcement.

## Repository Notes

- Root `.gitignore` ignores build artifacts (`target/`) and common local outputs.
- Workspace was reset to remove a polluted initial commit; ensure future commits stay clean.
- `bifrost-transport-ws` remains partially implemented for production reliability features.
