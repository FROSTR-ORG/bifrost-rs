# Gap Report: `bifrost-ts` vs `bifrost-rs`

Date: 2026-02-27
Scope baseline:
- TS source and demo: `~/Repos/frostr/bifrost-ts`
- RS parity source: `dev/planner/02-parity-matrix.md`

## Executive Summary

`bifrost-rs` is functionally strong on core cryptography, codec validation, node security controls, WS transport hardening, and runtime surfaces (`bifrostd` + `bifrost-cli` + `bifrost-tui` + dev relay).

Main remaining gaps are not foundational correctness failures; they are parity-completeness and release-hardening gaps.

## Coverage Snapshot

From `dev/planner/02-parity-matrix.md`:
- total mapped rows: `27`
- `done`: `16`
- `in_progress`: `9`
- `todo`: `2`

Current `in_progress`/`todo` rows are concentrated in:
- nonce/signer/pool abstraction parity
- schema/type utility parity
- validation/sighash helper parity

## Gap Classification

## P0 (Release-Critical)

1. Utility validation and sighash parity not complete
- Rows:
  - `src/util/validate.ts` -> `todo`
  - `src/lib/sighash.ts` -> `todo`
- Risk:
  - hidden behavior drift in hash canonicalization and validation edge paths.
- Recommended action:
  - implement explicit Rust utility modules + golden-vector tests from TS behavior.

2. Nonce model parity still marked `in_progress`
- Row:
  - `src/lib/nonce.ts` -> `in_progress` (`intentional_deviation`)
- Risk:
  - internal model is safer, but parity guarantees are not fully closed for all workflow surfaces.
- Recommended action:
  - close remaining batch/no-reuse test matrix and document final deviation contract.

## P1 (High Priority)

1. Node sign orchestration parity not fully complete
- Row:
  - `src/api/sign.ts` -> `in_progress`
- Note:
  - Option-B safe path is implemented; Option-A single-session multi-hash orchestration is deferred.

2. Client/signer/pool abstraction parity incomplete
- Rows:
  - `src/class/client.ts` -> `in_progress`
  - `src/class/pool.ts` -> `in_progress`
  - `src/class/signer.ts` -> `in_progress`
- Risk:
  - operational API drift for users porting directly from TS class ergonomics.

3. Schema/type parity completeness still open
- Rows:
  - `src/schema/*.ts` -> `in_progress`
  - `src/types/*.ts` -> `in_progress`
  - `src/lib/package.ts` -> `in_progress`
- Risk:
  - long-tail incompatibilities across edge payloads and helper usage.

## P2 (Quality/Operational Hardening)

1. Runtime boundary is mature but still intentionally divergent
- Row:
  - `demo/tmux/node.ts` runtime boundary -> `done` with `intentional_deviation`
- Current state:
  - `bifrostd`/CLI/TUI stack is in place and smoke-validated.
- Remaining hardening:
  - socket authn/authz policy, RPC version negotiation, richer daemon supervision semantics.

2. Transport reliability evidence depth
- Current planner notes still call out forced-fault WS integration coverage as a follow-up hardening area.

## Already Closed Well

- FROST core signing/session behavior and adversarial checks.
- Codec strict payload validation and parser helper layer.
- Node security controls: sender binding, replay/staleness, payload limits.
- WS transport reconnect/backoff/failover/threshold behavior at unit-level.
- Runtime stack and demo orchestration (`scripts/devnet.sh`, `scripts/devnet-tmux.sh`).

## Recommended Execution Order

1. Close utility parity first:
- `util/validate` + `sighash` + associated vectors.

2. Close cryptographic parity bookkeeping:
- finalize nonce parity row with remaining race/no-reuse scenario evidence.

3. Close API abstraction parity:
- signer/pool/client ergonomic surfaces and docs.

4. Close schema/types/package long-tail:
- enforce full parity review checklist per row.

5. Final release hardening sweep:
- runtime auth/versioning + WS forced-fault integration evidence + release metadata/audit gates.

## Suggested New Backlog Items

- `M10-001`: Implement `bifrost-core` validation utility parity (`util/validate.ts`).
- `M10-002`: Implement `bifrost-core` sighash helper parity (`lib/sighash.ts`) with vectors.
- `M10-003`: Finalize nonce parity evidence (replenish-race/no-reuse matrix).
- `M10-004`: Introduce Rust signer facade and pool status/event APIs for TS class parity.
- `M10-005`: Runtime hardening pass (RPC auth, versioning, supervision).

## Evidence References

- Parity matrix: `dev/planner/02-parity-matrix.md`
- Interfaces: `dev/planner/05-interfaces.md`
- Tests/gates: `dev/planner/06-test-strategy.md`
- Release checklist: `dev/artifacts/release-checklist-v0.1.0.md`
- Runtime docs: `dev/artifacts/runtime-stack.md`
