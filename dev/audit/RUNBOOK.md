# Multi-Agent Audit Runbook

This runbook defines how to execute a full category audit in one uninterrupted pass,
with parallel agent delegation, synchronized findings collection, and remediation handoff.

## 1. Objective

Produce a complete audit execution under `dev/audit/work/` with:

- one file per category,
- a consolidated finding log,
- a master run summary,
- a remediation queue that can be turned into backlog tasks.

## 2. Roles

- `Audit Lead`:
  - owns sequencing, status board, and final go/no-go recommendation.
- `Category Agents`:
  - each owns one or more category files.
- `Evidence Agent`:
  - runs command matrix and stores evidence snippets/log refs.
- `Remediation Agent`:
  - normalizes findings into actionable remediation queue items.

## 3. Preflight (single-threaded)

1. Reset working folder:
   - `rm -rf dev/audit/work && mkdir -p dev/audit/work`
2. Copy canonical templates from `dev/audit/templates/`:
   - `00-index.md`
   - category files `01`..`11`
   - `12-agent-assignments.md`
   - `13-shared-notes.md`
   - `14-findings-log.md`
   - `15-remediation-queue.md`
   - `99-summary.md`
3. Confirm planner is cleanly parsed:
   - `dev/scripts/planner_runbook.sh summary`
4. Lock execution rules:
   - e2e scripts are serial only (`scripts/test-node-e2e.sh`, `scripts/test-tui-e2e.sh`).

## 4. Parallel Delegation Model

Use three waves to avoid write collisions:

### Wave A (parallel)

- Agent A1: `01-architecture.md`, `03-separation-boundaries.md`
- Agent A2: `02-completeness.md`, `05-technical-debt.md`
- Agent A3: `08-documentation.md`, `11-release-supply-chain.md`

### Wave B (parallel)

- Agent B1: `04-security.md`
- Agent B2: `06-code-smell.md`, `07-readability.md`
- Agent B3: `09-testing-quality.md`, `10-reliability-operability.md`

### Wave C (single-threaded)

- Audit Lead merges all findings into:
  - `14-findings-log.md`
  - `99-summary.md`
- Remediation Agent converts approved findings into:
  - `15-remediation-queue.md`

## 5. Agent Execution Contract

Each category agent must:

1. Use the category template sections exactly.
2. Add finding IDs with stable prefix:
   - `ARC-*`, `CMP-*`, `SEP-*`, `SEC-*`, `TD-*`, `SMELL-*`, `READ-*`, `DOC-*`, `TST-*`, `OPS-*`, `REL-*`
3. Record evidence paths and commands.
4. Set category status: `pass`, `conditional_pass`, or `fail`.
5. Append cross-category notes to `13-shared-notes.md`.

## 6. Synchronization Cadence

- Sync interval: every 20-30 minutes.
- At each sync, each agent posts:
  - current category status,
  - new findings,
  - blockers/questions,
  - dependency on another category.
- Audit Lead updates `12-agent-assignments.md` status table.

## 7. Findings Collection and Normalization

All accepted findings must be added to `14-findings-log.md` with:

- `id`
- `category`
- `severity`
- `status` (`open`/`accepted-risk`/`closed`)
- `location`
- `summary`
- `recommended_fix`
- `owner`
- `target_milestone`

Normalization rules:

- Deduplicate semantically identical findings.
- Keep highest severity if duplicates conflict.
- Reject findings without concrete evidence location.

## 8. Evidence Handling

Store command outcomes and references in:

- category files (Evidence Reviewed section), and
- `13-shared-notes.md` (run-level evidence snippets).

Minimum evidence commands:

```bash
dev/scripts/toolchain_preflight.sh --require-cargo --require-cargo-audit
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --offline --no-deps
cargo check --workspace --offline
cargo test -p bifrost-core -p bifrost-codec -p bifrost-node -p bifrost-transport-ws --offline
cargo test -p bifrost-devtools -p bifrost-rpc --offline
scripts/test-node-e2e.sh
scripts/test-tui-e2e.sh
dev/scripts/planner_runbook.sh summary
cargo audit
```

## 9. Uninterrupted Execution Rules

- No mid-run scope changes unless marked in `13-shared-notes.md` and approved by Audit Lead.
- If a blocking issue is found:
  - do not stop the whole run,
  - record blocker in category file and `14-findings-log.md`,
  - continue remaining categories.
- Only Audit Lead edits `99-summary.md`.

## 10. Remediation Handoff

After findings are finalized:

1. Fill `15-remediation-queue.md` with prioritized actions.
2. Convert queue items to planner backlog tasks (or update existing ones).
3. Link each remediation item to finding IDs.
4. Update release docs if a release gate is impacted.

## 11. Completion Checklist

- [ ] All category files present and complete.
- [ ] `14-findings-log.md` contains normalized open findings.
- [ ] `15-remediation-queue.md` contains actionable items.
- [ ] `99-summary.md` contains aggregate status and go/no-go decision.
- [ ] Planner evidence updated for any new remediation tasks.

## 12. Output Artifacts For Every Run

Required files in `dev/audit/work/`:

- `00-index.md`
- `01`..`11` category files
- `12-agent-assignments.md`
- `13-shared-notes.md`
- `14-findings-log.md`
- `15-remediation-queue.md`
- `99-summary.md`
