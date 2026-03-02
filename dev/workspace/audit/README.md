# Audit Artifacts

This folder stores audit guides, baseline evidence, canonical templates, and the current working audit set.

## Canonical Templates

- `templates/README.md`
- `templates/*.template.md` (authoritative audit file set and execution order)

## Working Set

- `work/`
  - `00-index.md` + one markdown per category + coordination files + `99-summary.md`

## Baseline Files

- `AUDIT.md`: audit execution standard and required run layout.
- `RUNBOOK.md`: uninterrupted multi-agent execution model and coordination protocol.
- `checklist-v0.1.0.md`: release-audit checklist and signoff rows.
- `internal-audit-2026-02-27.md`: baseline internal audit evidence snapshot.

## Templates

- `templates/`: run scaffolding and collaboration templates:
  - `00-index.template.md`
  - `01-architecture.template.md` through `11-release-supply-chain.template.md`
  - `99-summary.template.md`
  - `12-agent-assignments.template.md`
  - `13-shared-notes.template.md`
  - `14-findings-log.template.md`
  - `15-remediation-queue.template.md`
  - `agent-brief.template.md`

## Note

- Historical date-organized run folders were removed to keep one canonical template flow.
