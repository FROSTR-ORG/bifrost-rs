# Architecture Quality Remediation Checklist

Date: 2026-03-02  
Owner: Engineering  
Status: Draft
Execution posture: Alpha hard cut. This is a hard cut. No tech debt allowed!
Deferral policy: No deferrals. Every listed item must be completed in this cycle; no partial or placeholder implementations.

Parent plan: [architecture-quality-remediation-2026-03-02](../../design/plans/architecture-quality-remediation-2026-03-02.md)

## Prerequisites
- [ ] Confirm current architecture audit findings remain current (`docs/` + `README.md` already patched).
- [ ] Ensure branch is clean for implementation work.
- [ ] Identify module owners for each workstream and notify them.

## Workstream A — Centralize Protocol and Runtime Constants (P0)

### A1. Create shared constants
- [ ] No deferrals: completion must include all constant modules and all references migrated in the same cycle.
- [ ] Add protocol constants module for envelope/request versioning and framing.
- [ ] Add transport constants module for reconnect, retry, and backoff defaults.
- [ ] Add node constants module for request/session/timeout defaults.

### A2. Replace duplicated literals in production code
- [ ] No deferrals: all listed files must be migrated now, with no temporary duplication.
- [ ] Replace duplicated timeout values in `crates/bifrost-node/src/node.rs` with shared constants.
- [ ] Replace duplicated timeout/retry/backoff values in `crates/bifrost-transport-ws/src/ws_transport.rs`.
- [ ] Replace duplicated defaults in `crates/bifrostd/src/main.rs`.
- [ ] Replace duplicated limits/constants in `crates/bifrost-codec` and `crates/bifrost-transport`.
- [ ] Replace duplicated defaults in tests/examples that assert runtime semantics.

### A3. Verify constant convergence
- [ ] No deferrals: validation coverage must be added in this checklist cycle.
- [ ] Add unit tests asserting all references use shared constants.
- [ ] Add compile-time style check that flags known hard-coded protocol defaults if used directly.
- [ ] Document canonical constant ownership in `docs/ARCHITECTURE.md`.

## Workstream B — Error Handling & Observability (P0)

### B1. Inventory and classify ignored failures
- [ ] No deferrals: all ignored-failure sites identified must be fully cataloged and classified now.
- [ ] Create list of every current `let _ = ...`/ignored `Result` in code-paths under:
  - `crates/bifrostd/src/main.rs`
  - `crates/bifrost-node/src/node.rs`
  - `crates/bifrost-transport-ws/src/ws_transport.rs`
  - `crates/bifrost-core` hotspots
- [ ] Classify each as `fatal`, `retry`, `degrade`, or `ignore`.

### B2. Update handling policy
- [ ] No deferrals: no intentionally swallowed error path may remain without explicit policy and observability.
- [ ] Replace hard ignore paths with structured diagnostics + metrics/counters where safe.
- [ ] Document expected behavior when channel/process/send failures occur.
- [ ] Add explicit comments for any remaining intentional ignores with rationale.

### B3. Guardrails
- [ ] No deferrals: each policy class must be covered with tests in this cycle.
- [ ] Add tests for at least one error-path per policy class.
- [ ] Add log/assertion for repeated failures in inbound request loop.
- [ ] Ensure daemon shutdown surfaces expected cleanup failures in debug/trace logs.

## Workstream C — Boundary Isolation & Dependency Injection (P1)

### C1. Define boundary contracts
- [ ] No deferrals: boundary contract interfaces must be introduced, not postponed.
- [ ] Introduce explicit runtime config/factory interfaces for transport and node creation.
- [ ] Remove concrete coupling in `bifrostd` startup path where practical.

### C2. Refactor startup wiring
- [ ] No deferrals: startup wiring changes must be implemented fully before completion.
- [ ] Update daemon initialization to inject node/transport via factory interfaces.
- [ ] Keep external CLI/TUI behavior unchanged.

### C3. Add replacement validation
- [ ] No deferrals: replacement coverage must be executed in this cycle.
- [ ] Add integration test for alternate transport/mock transport startup.
- [ ] Add test for configurable node construction with custom options.

## Workstream D — DRY Cleanups (P1)

### D1. Consolidate default builders
- [ ] No deferrals: all three builders must ship together with callsite migration.
- [ ] Add typed builders for:
  - Node options
  - Transport options
  - Daemon/server options
- [ ] Ensure all callsites use builder defaults instead of literal duplicates.

### D2. Reduce duplicated validation logic
- [ ] No deferrals: all duplicated validation groups listed are to be consolidated immediately.
- [ ] Extract shared validation helpers for:
  - replay/cache policy
  - payload size constraints
  - request id and envelope checks
- [ ] Replace duplicated checks with helper calls.

## Workstream E — Regression Coverage and Evidence (P2)

### E1. Add/adjust tests
- [ ] No deferrals: all test updates listed are required and in-scope now.
- [ ] Extend unit tests around shared constants and option builders.
- [ ] Extend integration tests for retry/backoff and error-policy behavior.
- [ ] Add/refresh e2e tests for daemon startup and reconnect semantics.

### E2. Evidence and sign-off
- [ ] No deferrals: evidence package must be produced as part of this hard cut closure.
- [ ] Capture before/after evidence:
  - constants defined in one place
  - ignored errors reduced and classified
  - boundary replacement test passing
- [ ] Link evidence IDs to backlog/task tracking.
- [ ] Produce final checklist completion note for release decision.

## Pre-merge Exit Criteria
- [ ] Hard cut policy met: no deferred refactors or placeholders are accepted.
- [ ] No protocol-critical literals duplicated across transport/node/daemon boundaries.
- [ ] All intentional ignores are documented with explicit rationale.
- [ ] Boundary replacement path covered by integration test.
- [ ] Test coverage includes unit + integration + e2e for remediation areas.
- [ ] Documentation updated to reflect the finalized architecture and error policy.

## Definition of Done
- [ ] All workstream sections (A–E) have no unclosed items.
- [ ] Every `[ ]` under sections A1 through E2 is completed; no deferral bullet remains unchecked.
- [ ] Parent plan link resolves and is accepted as active implementation authority.
- [ ] No placeholder or deferred follow-up issue is introduced for remaining unimplemented items.
- [ ] Alpha hard-cut policy and no-tech-debt mandate are fully satisfied.
