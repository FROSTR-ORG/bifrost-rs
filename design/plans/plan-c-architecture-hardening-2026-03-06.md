# Plan C: Architecture Hardening (Signer + Router + Bridges)

Date: 2026-03-06
Status: Proposed
Scope: `bifrost-signer`, `bifrost-router`, `bifrost-codec`, `bifrost-bridge-tokio`, `bifrost-bridge-wasm`, `bifrost-app`

## Goals

1. Enforce strict system boundaries between core/router/bridge/app.
2. Make request lifecycle behavior explicit, testable, and recoverable.
3. Reduce persistence risk while minimizing IO overhead.
4. Eliminate protocol-shape drift across layers.
5. Strengthen correctness guarantees under concurrent and adversarial ordering.

## Non-Goals

1. Backward-compatibility shims.
2. Legacy runtime support.
3. New product features unrelated to architectural hardening.

## Workstream 1: Formal `RouterPort` Boundary

### Changes

1. Introduce `RouterPort` trait as the only router-facing platform interface.
2. Move bridge-specific concerns behind adapter implementations (`tokio`, `wasm`).
3. Remove direct platform/runtime dependencies from router core.

### Acceptance Criteria

1. `bifrost-router` compiles without `tokio`/platform runtime imports.
2. `bifrost-bridge-tokio` and `bifrost-bridge-wasm` each implement `RouterPort`.
3. All router command/event flows pass through the trait boundary.

## Workstream 2: Explicit Request Lifecycle State Machine

### Changes

1. Add typed request states:
   - `Created`
   - `LockedPeersSelected`
   - `AwaitingResponses`
   - `Completed`
   - `Failed`
   - `Expired`
2. Encode legal transitions and terminal states in one module.
3. Route sign/ecdh/ping/onboard through shared lifecycle enforcement.

### Acceptance Criteria

1. Illegal transitions are unrepresentable or return deterministic errors.
2. Each request reaches exactly one terminal state.
3. Terminal state emission is idempotent (no duplicate completion/failure).

## Workstream 3: Hot vs Durable Persistence Lanes

### Changes

1. Persist config/policy updates immediately.
2. Batch health/metrics persistence.
3. Checkpoint request snapshots on lifecycle transitions (not every tick).
4. Preserve nonce pools + pending requests only on clean shutdown;
   drop unsafe pending/nonce state on dirty restart.

### Acceptance Criteria

1. Config/policy mutations are durable immediately after command success.
2. Dirty-restart detection enforces pending/nonce invalidation policy.
3. IO volume is reduced versus always-immediate persistence path.

## Workstream 4: Replay/Dedupe as Policy Objects

### Changes

1. Replace scattered replay/dedupe knobs with typed policy structs.
2. Centralize TTL, cache capacity, and overflow behavior evaluation.
3. Reuse the same policy model across sign/ecdh/inbound event processing.

### Acceptance Criteria

1. Replay and dedupe behavior is configured via one policy entrypoint.
2. No duplicated ad hoc queue/replay checks remain.
3. Policy edge cases are covered in focused unit tests.

## Workstream 5: Canonical Wire Schema Boundary

### Changes

1. Keep payload shape and validation exclusively in `bifrost-codec`.
2. Remove duplicate parsing/shape checks from bridge/app layers.
3. Expose only typed validated messages from codec to router/signer.

### Acceptance Criteria

1. No non-codec crate defines protocol-shape validation logic.
2. Malformed payload rejection behavior is unchanged or stricter.
3. Tests enforce codec-as-single-source-of-truth contract.

## Workstream 6: Property-Based Invariant Testing

### Changes

1. Add property tests for router lifecycle invariants.
2. Randomize event ordering, duplication, and timeout/failure delivery.
3. Assert invariant outcomes across sign/ecdh flows.

### Required Invariants

1. No duplicate terminal results for a request.
2. No completion after terminal failure.
3. No stale response acceptance after lock-set finalization.
4. Threshold/locked-peer rules are jointly enforced.

### Acceptance Criteria

1. Property test suite runs in CI.
2. Failing seeds are reproducible and logged.
3. Existing deterministic tests remain and complement property tests.

## Workstream 7: Structured Observability Contract

### Changes

1. Define stable event taxonomy and field schema for signer/router lifecycle.
2. Emit operation correlation IDs and phase transitions.
3. Ensure bridge/app logs can reconstruct full operation timeline.

### Acceptance Criteria

1. Sign/ecdh/onboard/ping each emit predictable lifecycle events.
2. Log consumers can correlate inbound/outbound/terminal states via IDs.
3. No sensitive payload leakage in log fields.

## Execution Order

1. Workstream 1 (`RouterPort` boundary)
2. Workstream 2 (request lifecycle state machine)
3. Workstream 3 (persistence lanes)
4. Workstream 4 (replay/dedupe policy objects)
5. Workstream 5 (canonical codec boundary)
6. Workstream 6 (property testing)
7. Workstream 7 (observability contract)

## Definition of Done

1. All acceptance criteria above are met.
2. Documentation in `README.md`, `docs/API.md`, `docs/ARCHITECTURE.md`, and `TESTING.md` matches implementation.
3. No compatibility shims or legacy fallback paths are introduced.
