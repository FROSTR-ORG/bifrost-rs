# Planner System

A reusable, lightweight planner for tracking agent-driven work: audits, reports, plans, and guides. Git-tracked, per-project, with a flat rolling work log and foreman runbook for automated plan execution.

## Quick Start

1. Copy this directory into your project as `.planner/`.
2. Fill in `context.md` with your project's identity.
3. Add the CLAUDE.md snippet (below) to your project's `CLAUDE.md`.
4. Start working — create audits, reports, plans, and guides as needed.

## Directory Structure

```
.planner/
├── README.md          # This file — system overview
├── runbook.md         # Foreman execution runbook
├── review.md          # Post-session retrospective prompt
├── context.md         # Project identity and constraints
├── backlog.md         # Tagged work item list
├── decisions.md       # Lightweight ADR log
├── handoff.md         # Agent-to-agent context transfer
├── notes.md           # Freeform scratchpad
├── risks.md           # Risk register
├── work.log           # Rolling flat journal of agent activity
├── templates/         # Body templates for standardized artifacts
│   ├── plan.md        # Plan body template
│   ├── audit.md       # Audit body template
│   └── report.md      # Report body template
├── audits/            # Audit work products
├── reports/           # Reports generated from audits
├── plans/             # Active/pending work plans
├── done/              # Completed plans (moved from plans/)
└── guides/            # Design guides — living reference docs
```

## Conventions

### File Naming

- **Dated artifacts** (audits, reports, plans): `YYYY-MM-DD-<slug>.md`
- **Living docs** (guides): `<slug>.md`

### Artifact Frontmatter

All audits, reports, plans, and guides carry minimal YAML frontmatter:

```yaml
---
title: Short Descriptive Title
type: plan           # audit | report | plan | guide
created: YYYY-MM-DD
origin: reports/YYYY-MM-DD-slug.md  # optional — what spawned this
---
```

### Work Log Format

Append-only, one line per event:

```
YYYY-MM-DD HH:MM | <status> | <description>
```

Statuses: `started`, `completed`, `note`

## Lifecycle

```
audit (audits/) → report (reports/) → plan (plans/) → done (done/)
                                         ↑
                        guide (guides/) --┘  (informs plans/audits)
```

Not every artifact follows the full chain. Agents may skip steps or create artifacts standalone. A plan can originate from a report, an audit finding, a backlog item, or nothing at all.

## Subfolder Purposes

- **audits/** — Agent audit work products. An audit examines something and produces findings.
- **reports/** — Generated from audits. Distills findings into actionable observations.
- **plans/** — Active/pending work plans. Can originate from a report, audit, or standalone.
- **done/** — Completed plans, physically moved from `plans/`.
- **guides/** — Design guides. Living reference docs that inform future audits and plans.
- **templates/** — Body templates for plans, audits, and reports. Used when creating new artifacts.

## Root-Level Documents

| File | Purpose |
|------|---------|
| `context.md` | Project identity — what it is, its architecture, constraints, conventions, and key paths. Filled in once when the planner is initialized, updated as the project evolves. |
| `backlog.md` | Tagged work item list with priorities and origins. Active items at top, completed below. |
| `decisions.md` | Lightweight ADR log. Records architectural and process decisions with context and consequences. |
| `handoff.md` | Agent-to-agent context transfer. Updated at the end of a session so the next agent can resume cleanly. |
| `notes.md` | Freeform scratchpad. Agents append dated sections during work. |
| `risks.md` | Risk register with impact, likelihood, status, and mitigation tracking. |
| `work.log` | Append-only flat journal. One line per start/complete/note event. |
| `runbook.md` | Foreman execution runbook. Orchestrating agent reads this to process the plans queue. |
| `review.md` | Post-session retrospective prompt. Run at end of a long session to extract insights. |

## Execution

To execute pending plans, an orchestrating agent (the "foreman") follows `runbook.md`. The runbook defines a dry-run approval gate, workspace preparation via worktrees, worker sub-agent spawning, review cycles, and merge/cleanup procedures.

To run a post-session review, follow `review.md`. This extracts project and planner insights while full session context is still available.

## CLAUDE.md Snippet

Add this to your project's `CLAUDE.md` after copying the planner into `.planner/`:

```markdown
## Planner

This project uses a `.planner/` system for tracking agent-driven work.

- Read `.planner/context.md` for project identity and constraints.
- Read `.planner/handoff.md` for current state and session context.
- Check `.planner/backlog.md` for pending work items.
- Plans in `.planner/plans/` are active work proposals; completed plans live in `.planner/done/`.
- Use `.planner/templates/` for standard artifact structures.
- Append to `.planner/work.log` when starting or completing work.
- To execute the plans queue, follow `.planner/runbook.md`.
```
