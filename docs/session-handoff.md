# Session Handoff

Use this file when moving machines or resetting agent context.

## Snapshot Checklist

1. Capture repo state:
- `git status --short --branch`
2. Record active backlog tasks:
- `planner/04-backlog.md` entries marked `in_progress`
3. Record unresolved risks:
- open rows in `planner/07-risks-and-decisions.md`
4. Record current validation baseline:
- latest successful `cargo check`/`cargo test` commands.
5. Record immediate next PR target and acceptance checks.

## Current Known Snapshot (2026-02-27)

- In progress tasks:
- `M1-001`, `M2-001`, `M3-001`
- Completed:
- planner artifacts created
- node/core sign-session hardening and tests
- Root git history reset to remove polluted initial commit.
- Root `.gitignore` hardened for build artifacts.

## Resume Procedure On New Machine

1. Clone/open repository.
2. Read in this order:
- `docs/README.md`
- `docs/current-status.md`
- `planner/README.md`
- `planner/04-backlog.md`
3. Run focused validation:
- `cargo check -p bifrost-core -p bifrost-node`
- `cargo test -p bifrost-core -p bifrost-node`
4. Start next planned PR from execution pass list.

## Non-Negotiables

- Do not proceed on memory alone; always reconcile with planner/doc files.
- Any change to behavior must update planner evidence.
- Keep parity matrix and interface doc synchronized with code.
