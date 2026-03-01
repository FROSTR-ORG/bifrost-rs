# Runbook

This runbook is for the **foreman** — an orchestrating agent that processes the plans queue by spawning worker sub-agents. Read this file fully before starting.

## Prerequisites

- Read `context.md` for project identity and constraints.
- Read `handoff.md` for current state.
- Read `backlog.md` for pending work items.

## Phase 0: Dry Run

Before doing any work, survey the state and present a summary to the user.

1. **List pending plans.** Scan `plans/` for all `.md` files. For each, read the frontmatter and objective. Present a table:

   | # | Plan | Priority | Origin | Summary |
   |---|------|----------|--------|---------|

2. **Propose execution order.** Order by priority, then by dependency (if one plan's output is another's input). Explain the reasoning.

3. **Describe workspaces.** For each plan, state what branch (`plan/<slug>`) and worktree would be created.

4. **Wait for user approval.** Do not proceed until the user confirms. Accept adjustments to ordering, skips, or additions.

## Phase 1: Execute

For each approved plan, in the approved order:

### Step 1: Prepare Workspace

- Create branch `plan/<slug>` from the current main branch.
- Create a git worktree for the branch.
- Append to `work.log`: `YYYY-MM-DD HH:MM | started | plan/<slug>: <plan title>`

### Step 2: Spawn Worker

Launch a sub-agent in the worktree with the following context:
- The plan file itself (from `plans/`).
- `context.md` (project identity and constraints).
- Any guides referenced in the plan (from `guides/`).

The worker commits to the branch but does **NOT** merge or push.

### Step 3: Negotiate

Before the worker begins coding, review its proposed approach:
- Does it match the plan's scope and approach sections?
- Does it respect constraints from `context.md`?
- Are the files it intends to modify consistent with the plan?

Approve, adjust, or reject. If rejected, log a `note` in `work.log` and move to the next plan.

### Step 4: Review

When the worker reports completion:

1. Review the diff (`git diff main...plan/<slug>`).
2. Run the verification commands from the plan's "Verification" section.
3. Check each acceptance criterion from the plan's "Acceptance Criteria" section.
4. If any criterion is not met, send the worker back with specific feedback. Repeat until satisfied or until further progress is unlikely.

### Step 5: Merge

- Merge the branch into main: `git merge plan/<slug>`.
- Append to `work.log`: `YYYY-MM-DD HH:MM | completed | plan/<slug>: <plan title>`

### Step 6: Clean Up

- Remove the worktree.
- Delete the branch.
- Move the plan file from `plans/` to `done/`.
- Update `backlog.md` — mark related items as completed with date and evidence.
- Update `handoff.md` — reflect the new project state.

### Step 7: Repeat

Proceed to the next plan in the approved order. Return to Step 1.

## Edge Cases

### No plans available

1. Check `backlog.md` for items that need plans written.
2. If backlog items exist, offer to draft plans for them.
3. If no actionable items remain, update `handoff.md` and stop.

### Worker failure

1. Log the failure in `work.log`: `YYYY-MM-DD HH:MM | note | plan/<slug>: worker failed — <reason>`
2. Keep the branch and worktree intact for diagnosis.
3. Move to the next plan.
4. Report all failures to the user at the end of the run.

### Conflicts on merge

1. Attempt to resolve conflicts in the worktree.
2. If resolution is straightforward (e.g., whitespace, import ordering), resolve and merge.
3. If conflicts are substantive, escalate to the user before merging.

### User interruption

If the user asks to stop mid-run:
1. Finish the current step (do not leave a half-merged state).
2. Update `handoff.md` with what was completed and what remains.
3. Log a `note` in `work.log`.
