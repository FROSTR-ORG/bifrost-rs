# Architecture Quality Remediation Plan
Date: 2026-03-02  
Status: Draft

## Purpose
Remediate architecture quality issues identified in the docs/code audit: duplicated protocol constants, magic numbers, weak error observability, and boundary leakage between layers (`docs`/`README` findings were resolved earlier).

Execution policy: `We are in alpha. This is a hard cut. No tech debt allowed!`

## Problem Statement
- Multiple modules duplicate protocol and operational defaults (retry, backoff, versions, envelope semantics).
- Several production paths intentionally swallow errors without visibility.
- Layer boundaries are mostly good but some components (especially `bifrostd`) are tightly coupled to concrete runtime types and default wiring.
- Hard-coded literals reduce readability and increase drift risk.

## Success Criteria
- Shared constants module is used for protocol/version/timeouts/backoff limits across layers.
- All swallowed/ignored errors have explicit handling policy (`retry`, `propagate`, `downgrade`, `fatal`) and telemetry.
- Runtime boundary seam is decoupled sufficiently to support transport/node type swaps in daemon startup and tests.
- A small matrix links each architecture concern to mitigation and evidence.
- Unit/integration/e2e coverage added or updated to prevent regression.

## Workstreams

### 1) Centralize Protocol and Runtime Constants (P0)
Goal: eliminate duplicated semantics across crates and reduce behavior drift.

1. Create shared constants locations:
- `crates/bifrost-codec`: protocol constants (envelope/request versions, codec limits if applicable).
- `crates/bifrost-node`: runtime policy constants (request id/timeout defaults, replay cache limits, payload policy aliases).
- `crates/bifrost-transport-ws`: transport defaults (RPC kind IDs, retry/backoff defaults, socket/session constants).
- `crates/bifrostd`: daemon defaults should reference node/transport constants where possible.

2. Replace duplicated literals in:
- `crates/bifrostd/src/main.rs`
- `crates/bifrost-node/src/node.rs`
- `crates/bifrost-node/src/types.rs`
- `crates/bifrost-transport/src/*.rs`
- `crates/bifrost-transport-ws/src/ws_transport.rs`
- `crates/bifrost-devtools` examples/tests/fixtures if they encode production defaults

3. Add compile-time/static assertions or tests ensuring defaults resolve to shared sources.

Acceptance:
- No semantic duplicate for envelope version, request/retry/backoff defaults, and timeout caps across module boundaries.
- Grep for known literals (`20_000`, `250`, `3`, `rpc_kind` style hard-coded values) should be reduced to canonical symbols in production code.

### 2) Error Observability and Handling Policy (P0)
Goal: replace silent error swallowing with explicit policy and actionable telemetry.

1. Inventory all ignored errors in the audit scope:
- event send paths
- cleanup/shutdown paths
- incoming processing loops
- ws transport internal send/dispatch paths

2. For each ignored error site:
- choose policy:
  - `fatal` (return error, fail fast)
  - `retry` (with bounded counters)
  - `degrade` (continue + counter + log event)
  - `ignore` (only with explicit documentation + reason)
- add structured logging/metrics counter per error class.

3. Introduce a `error_context` helper or typed wrappers so failures are surfaced consistently by subsystem.

Acceptance:
- No production-path `let _ = ...` remains without a comment containing an explicit policy rationale.
- New/updated tests validate that expected errors are surfaced through logs or return paths.

### 3) Strengthen Layer Boundaries and Dependency Injection (P1)
Goal: reduce coupling and make boundaries testable/replaceable.

1. Introduce constructor boundary abstraction in `bifrostd`:
- avoid direct `BifrostNode<WebSocketTransport, SystemClock>` embedding in the main runtime path.
- pass factory/config interfaces for node/transport creation.

2. Clarify module contracts:
- document transport and node option coupling in `docs/ARCHITECTURE.md`.
- add typed config objects to replace ad hoc cross-module defaults.

3. Add integration tests for:
- alternate transport construction path (mock transport + in-memory clock),
- startup/shutdown with swapped options.

Acceptance:
- daemon startup accepts injected node/transport implementations in non-test mode.
- one boundary test demonstrates transport/node substitution without editing core business logic.

### 4) DRY and Maintainability Cleanup (P1)
Goal: remove repeated patterns and centralize behavior definitions.

1. Create dedicated config builders:
- `NodeConfig`
- `TransportConfig`
- `DaemonConfig`
that own defaults and validation.

2. Consolidate duplicated timeout/path limit validations into shared helper(s).

3. Add lint-level guardrails:
- optional `clippy`/unit checks against duplicate constants and repeated literal categories.

Acceptance:
- Defaulting logic exists in a single location per domain (node/transport/daemon).
- Cross-module docs point to canonical config sources.

### 5) Validation Matrix and Regression Coverage (P2)
Goal: keep architectural quality changes from regressing behavior.

1. Add/extend tests:
- unit tests for new constant modules and builders
- integration tests for error-policy behavior in request-processing loop and transport reconnect/retry
- docs test checklist updates (if you maintain checklist artifacts)

2. Create a small evidence bundle:
- before/after grep evidence for key constants
- before/after count of ignored errors with policy annotation
- one smoke run for node+daemon+ws transport with representative request mix

Acceptance:
- CI gates include at least one test proving retry/backoff config source-of-truth behavior.
- test coverage references updated for unit/integration/e2e categories.

## Milestones

1. Week 1: implement constants unification and error policy tagging (workstreams 1 and 2).
2. Week 2: boundary DI refactor and config builders (workstream 3).
3. Week 3: finish DRY cleanup plus regression tests/documentation updates (worksets 4 and 5).

## Risk & Dependencies
- Refactoring constants may touch protocol behavior if defaults were accidentally inferred from tests only.
- Error-policy changes can alter control flow in long-running daemons; rollout should include rollout/rollback notes and a grace window.
- Boundary refactor should avoid touching public RPC semantics in a way that affects CLI/TUI callers.

## Rollout Plan
- PR1: shared constants + constants-first defaults + minimal observability tags.
- PR2: error handling policy annotations + tests.
- PR3: boundary/DI adjustments + integration coverage.
- PR4: final audit, docs, and evidence package.

## Owners (proposed)
- Workstream 1: `core+transport`
- Workstream 2: `node+daemon`
- Workstream 3: `bifrostd architecture`
- Workstream 4-5: shared (`docs`, `qa`, `engineering`)

## Tracking
- Add backlog items in `dev/planner/04-backlog.md` for each major workstream.
- Attach evidence IDs from unit/integration/e2e test updates in execution notes.
