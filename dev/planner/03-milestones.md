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
- Status: `done`
- Deliverables:
- FROST signing, session validation, nonce lifecycle correctness in `bifrost-core`.
- Acceptance checks:
- Core tests pass including negative validation and tamper paths.
- Blocking dependencies:
- Batch-sign nonce model decision and implementation.
- Effort band: `M`

## M2: Codec And Schema Parity
- Status: `done`
- Deliverables:
- Wire/rpc parity and schema-level strict parsing/validation.
- Acceptance checks:
- Codec round-trip tests + invalid payload rejection tests.
- Blocking dependencies:
- Final schema strictness policy for compatibility.
- Effort band: `M`

## M3: Node Behavior And Security Parity
- Status: `done`
- Deliverables:
- Request handling parity, member binding checks, policy enforcement, replay protections.
- Acceptance checks:
- Node integration tests for authorization and tamper scenarios.
- Blocking dependencies:
- Event and middleware model choices.
- Effort band: `L`

## M4: Transport-WS Production Hardening
- Status: `done`
- Deliverables:
- Reconnect/backoff, multi-relay failover, robust timeout handling.
- Acceptance checks:
- Integration tests for relay drop/failover/threshold delivery.
- Blocking dependencies:
- CI/network test environment availability.
- Effort band: `L`

## M5: Batching/Cache/Event Model Parity
- Status: `done`
- Deliverables:
- Sign/ECDH batch queues, ECDH cache, event stream parity in Rust API.
- Acceptance checks:
- Deterministic queue processing tests and cache eviction tests.
- Blocking dependencies:
- Public API shape locked in `05-interfaces.md`.
- Effort band: `L`

## M6: Integration + Adversarial Test Completion
- Status: `done`
- Deliverables:
- Cross-crate integration and adversarial suites complete.
- Acceptance checks:
- Required scenarios in `06-test-strategy.md` all green.
- Blocking dependencies:
- Prior milestone implementations.
- Effort band: `M`

## M7: Docs/Examples/Demo Parity
- Status: `done`
- Deliverables:
- Updated README, crate docs, and Rust examples equivalent to practical TS flows.
- Acceptance checks:
- Example flows execute and are documented.
- Blocking dependencies:
- Stable APIs from M1-M6.
- Effort band: `M`

## M8: Release Readiness + TS Dependency De-Risk
- Status: `done`
- Deliverables:
- Release checklist, compatibility notes, migration guide for users.
- Audit kit and internal audit evidence artifacts.
- Canonical audit templates and working execution model (`dev/audit/templates/`, `dev/audit/work/`).
- Multi-agent uninterrupted audit runbook and template pack (`dev/audit/RUNBOOK.md`, `dev/audit/templates/`).
- Acceptance checks:
- CI green for full workspace and release artifacts ready.
- Blocking dependencies:
- All prior milestones complete.
- Effort band: `M`

## M9: Runtime Surface (Daemon + CLI + TUI + Dev Relay)
- Status: `done`
- Deliverables:
- `bifrostd` daemon with local RPC socket for node operations.
- `bifrost-cli` RPC client for scripting/agents.
- `bifrost-tui` operator bench harness connected to daemon.
- Rust dev Nostr relay ported from `bifrost-ts/demo`.
- Acceptance checks:
- Workspace builds these targets.
- Basic local loop validated (`relay` + `bifrostd` + `bifrost-cli status/ping/echo`).
- Blocking dependencies:
- RPC schema/versioning decisions and local auth model.
- Effort band: `L`

## M10: Nostr Transport Interop + Encrypted RPC Stabilization
- Status: `done`
- Deliverables:
- Replace raw websocket envelope flow with Nostr-native relay framing (`REQ`/`EVENT`/`CLOSE`).
- Add encrypted event-content wrapper for peer RPC payloads and sender-tag binding checks.
- Expose explicit daemon/devnet transport settings (`rpc_kind`, retry/backoff, sender keys).
- Tighten node/tui e2e assertions to require success-path RPC behavior in healthy devnet.
- Acceptance checks:
- `cargo test -p bifrost-transport-ws --offline`.
- `scripts/test-node-e2e.sh`.
- `scripts/test-tui-e2e.sh`.
- Blocking dependencies:
- Exact NIP-44 payload compatibility vectors remain follow-up parity hardening.
- Effort band: `M`

## M13: Final Parity Closure
- Status: `done`
- Deliverables:
- Option-A-only single-session multi-hash signing architecture across core/node/codec.
- Validation+sighash utility parity helpers in `bifrost-core`.
- Rust facade parity surface (`NodeClient`, `Signer`, `NoncePoolView`) and middleware hooks.
- Schema/types/package helper parity closure and matrix evidence updates.
- Acceptance checks:
- Remaining `in_progress`/`todo` rows in `02-parity-matrix.md` moved to `done` with evidence.
- Full gate pass: fmt/clippy/check/tests + node/tui e2e + planner verify + cargo audit.
- Blocking dependencies:
- None.
- Effort band: `L`
