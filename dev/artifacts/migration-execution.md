# Migration Execution Playbook

This is the operational guide for executing the planner.

## Source Of Truth

- Backlog and sequencing: `dev/planner/04-backlog.md`
- Scope and acceptance: `dev/planner/01-scope-and-goals.md`
- Parity tracking: `dev/planner/02-parity-matrix.md`
- Interface decisions: `dev/planner/05-interfaces.md`
- Test gates: `dev/planner/06-test-strategy.md`

## Execution Loop

1. Pick the next task in `dev/planner/04-backlog.md`.
2. Move status to `in_progress`.
3. Implement code and tests for that task.
4. Update parity rows touched.
5. Update test evidence rows.
6. Update milestone progress.
7. Document any new risk or decision.
8. Mark task `done` with concrete evidence.

## Current First Execution Pass

- `M1-001` in progress: safe batch-sign nonce model.
- `M2-001` in progress: strict codec payload validation.
- `M3-001` in progress: sender/member binding enforcement.

Planned PR sequence:

1. `PR-01`: nonce model design + guardrails.
2. `PR-02`: codec validation hardening.
3. `PR-03`: node authorization hardening.
4. `PR-04`: safe batch-sign implementation.
5. `PR-05`: adversarial signature-share tests.

## Required Evidence Per PR

- Tests added/updated with passing results.
- Planner updates:
- backlog item status
- parity matrix rows
- test strategy evidence
- risk/decision deltas (if any).
