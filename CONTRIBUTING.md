# Contributing to bifrost-rs

Thanks for contributing. This project migrates `bifrost-ts` to Rust with strict parity and stronger safety.

## Prerequisites

- Rust toolchain (stable)
- `cargo` available
- Unix-like environment for runtime scripts

## Setup

```bash
git clone <repo-url>
cd bifrost-rs
cargo check --workspace --offline
```

## Workflow

1. Pick a task from `dev/planner/04-backlog.md`.
2. Set it to `in_progress` using:
   - `dev/scripts/planner_runbook.sh set-status <TASK_ID> in_progress`
3. Implement code + tests.
4. Run verification:
   - `dev/scripts/planner_runbook.sh verify`
5. Update planner evidence (`02`, `05`, `06`, `07` as needed).
6. Mark task `done` only with concrete evidence.

## Coding Rules

- Prioritize cryptographic correctness and nonce safety.
- Do not silently change protocol behavior.
- Add tests for every behavioral change, especially negative-path tests.
- Keep public API changes synchronized with `dev/planner/05-interfaces.md`.

## Pull Requests

- Keep PRs focused and reviewable.
- Include:
  - problem statement
  - changes made
  - test evidence (commands + result)
  - planner updates touched

## Documentation Requirements

If behavior changes:

1. Update root `README.md` if user-facing behavior changed.
2. Update technical docs in `docs/`.
3. Update planner artifacts with evidence.
