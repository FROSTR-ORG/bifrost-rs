# Planner Automation Runbook

Use `dev/scripts/planner_runbook.sh` to execute and track the planner consistently.

## Quick Start

From repo root:

```bash
dev/scripts/planner_runbook.sh summary
dev/scripts/planner_runbook.sh next
```

## Commands

- `summary`
  - Counts tasks by status and milestone.
- `next`
  - Shows current `in_progress` tasks and `todo` tasks with satisfied dependencies.
- `list`
  - Prints all task rows in backlog order.
- `set-status <TASK_ID> <todo|in_progress|blocked|done>`
  - Updates task status directly in `dev/planner/04-backlog.md`.
- `verify`
  - Runs baseline checks/tests used during execution.
- `milestone`
  - Prints milestone headers and status lines from `dev/planner/03-milestones.md`.

## End-to-End Operator Loop

1. `dev/scripts/planner_runbook.sh next`
2. Pick one ready task.
3. `dev/scripts/planner_runbook.sh set-status <TASK_ID> in_progress`
4. Implement code and tests.
5. `dev/scripts/planner_runbook.sh verify`
6. Update planner evidence docs (`02`, `05`, `06`, `07` as needed).
7. `dev/scripts/planner_runbook.sh set-status <TASK_ID> done`
8. Repeat.

## Notes

- Dependency resolution is strict for explicit task IDs (`Mx-xxx`) and comma-separated lists.
- Milestone-range dependency strings (example: `M1-M5`) are treated as not auto-resolvable by the script and should be handled manually.
