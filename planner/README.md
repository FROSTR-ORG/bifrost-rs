# Bifrost Migration Planner

This folder is the single source of truth for the `bifrost-ts` to `bifrost-rs` migration.

## Status Legend

- `todo`: not started
- `in_progress`: actively being worked
- `blocked`: waiting on dependency/decision
- `done`: completed with linked evidence

## Ownership Model

- Crypto and protocol: `bifrost-core` owners
- Encoding and schema: `bifrost-codec` owners
- Runtime behavior: `bifrost-node` owners
- Transport reliability: `bifrost-transport` and `bifrost-transport-ws` owners
- QA and release: integration/test owners

## Workflow

1. Select work from `04-backlog.md`.
2. Set item status to `in_progress`.
3. Implement and validate changes in code/tests.
4. Update planner artifacts before merge:
- `02-parity-matrix.md` rows touched by the work.
- `03-milestones.md` progress markers.
- `06-test-strategy.md` with test evidence.
- `07-risks-and-decisions.md` for new risks/decisions.
5. Mark backlog item `done` only after evidence is linked.

## Artifact Index

1. [01-scope-and-goals.md](./01-scope-and-goals.md)
2. [02-parity-matrix.md](./02-parity-matrix.md)
3. [03-milestones.md](./03-milestones.md)
4. [04-backlog.md](./04-backlog.md)
5. [05-interfaces.md](./05-interfaces.md)
6. [06-test-strategy.md](./06-test-strategy.md)
7. [07-risks-and-decisions.md](./07-risks-and-decisions.md)
8. [08-status-template.md](./08-status-template.md)
