# Scope And Goals

## Migration Objective

Port `bifrost-ts` into `bifrost-rs` while preserving external behavior and improving safety with Rust-native invariants.

## In Scope

- `bifrost-ts/src/api` parity into request/handler orchestration in Rust.
- `bifrost-ts/src/class` parity for node orchestration, nonce pool, signer behavior, batchers, cache, and eventing.
- `bifrost-ts/src/lib` parity for group/session/sign/ecdh/package/sighash/parse helpers.
- `bifrost-ts/src/schema` parity into Rust validation boundaries.
- `bifrost-ts/src/types` parity into Rust public structs/enums/traits.
- `bifrost-ts/src/util` parity for crypto/encoding/validation helpers that are part of runtime behavior.
- `bifrost-ts/src/encoder` parity for package wire encoding/decoding.

## Out Of Scope (Phase 1)

- Browser-specific UI/demo assets under TS demo/web.
- Publishing automation scripts for npm release flow.
- Perfect one-to-one internal architecture matching TS classes if behavior is already preserved safely.

## Success Criteria

1. API coverage:
- All externally used TS flows (`echo`, `ping`, `onboard`, `sign`, `ecdh`) available in Rust with documented compatibility.
2. Behavioral parity:
- All parity-matrix rows marked `done` with `exact` or `compatible`, and deviations explicitly documented.
3. Quality and tests:
- Unit + integration + adversarial scenarios passing for all milestones.
4. Release readiness:
- Workspace checks/tests pass in CI across all crates, including WS transport.

## Definition Of Done

- `02-parity-matrix.md`: no `todo`/`blocked` rows for required migration scope.
- `03-milestones.md`: all milestones complete with acceptance evidence.
- `06-test-strategy.md`: all required scenario gates satisfied.
- `07-risks-and-decisions.md`: no unresolved high-risk items.
