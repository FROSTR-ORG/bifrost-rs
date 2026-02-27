# Milestones

## M0: Planner Baseline Complete
- Status: `done`
- Deliverables:
- Planner artifact set created and linked.
- Acceptance checks:
- All files `01` to `08` exist and are internally consistent.
- Blocking dependencies:
- None.
- Effort band: `S`

## M1: Core Cryptographic Parity Freeze
- Status: `in_progress`
- Deliverables:
- FROST signing, session validation, nonce lifecycle correctness in `bifrost-core`.
- Acceptance checks:
- Core tests pass including negative validation and tamper paths.
- Blocking dependencies:
- Batch-sign nonce model decision and implementation.
- Effort band: `M`

## M2: Codec And Schema Parity
- Status: `in_progress`
- Deliverables:
- Wire/rpc parity and schema-level strict parsing/validation.
- Acceptance checks:
- Codec round-trip tests + invalid payload rejection tests.
- Blocking dependencies:
- Final schema strictness policy for compatibility.
- Effort band: `M`

## M3: Node Behavior And Security Parity
- Status: `in_progress`
- Deliverables:
- Request handling parity, member binding checks, policy enforcement, replay protections.
- Acceptance checks:
- Node integration tests for authorization and tamper scenarios.
- Blocking dependencies:
- Event and middleware model choices.
- Effort band: `L`

## M4: Transport-WS Production Hardening
- Status: `todo`
- Deliverables:
- Reconnect/backoff, multi-relay failover, robust timeout handling.
- Acceptance checks:
- Integration tests for relay drop/failover/threshold delivery.
- Blocking dependencies:
- CI/network test environment availability.
- Effort band: `L`

## M5: Batching/Cache/Event Model Parity
- Status: `todo`
- Deliverables:
- Sign/ECDH batch queues, ECDH cache, event stream parity in Rust API.
- Acceptance checks:
- Deterministic queue processing tests and cache eviction tests.
- Blocking dependencies:
- Public API shape locked in `05-interfaces.md`.
- Effort band: `L`

## M6: Integration + Adversarial Test Completion
- Status: `todo`
- Deliverables:
- Cross-crate integration and adversarial suites complete.
- Acceptance checks:
- Required scenarios in `06-test-strategy.md` all green.
- Blocking dependencies:
- Prior milestone implementations.
- Effort band: `M`

## M7: Docs/Examples/Demo Parity
- Status: `todo`
- Deliverables:
- Updated README, crate docs, and Rust examples equivalent to practical TS flows.
- Acceptance checks:
- Example flows execute and are documented.
- Blocking dependencies:
- Stable APIs from M1-M6.
- Effort band: `M`

## M8: Release Readiness + TS Dependency De-Risk
- Status: `todo`
- Deliverables:
- Release checklist, compatibility notes, migration guide for users.
- Acceptance checks:
- CI green for full workspace and release artifacts ready.
- Blocking dependencies:
- All prior milestones complete.
- Effort band: `M`
