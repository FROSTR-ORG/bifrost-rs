# Test Strategy And Acceptance Gates

## Test Pyramid

1. Unit tests:
- Core math/session/nonce validation.
- Codec encoding/decoding and parser checks.
- Node validation and handler-level behavior.

2. Property and adversarial tests:
- malformed/tampered input rejection.
- replay/duplicate/idempotency behavior.
- threshold and nonce edge cases.

3. Integration tests:
- multi-peer flow across node + transport.
- WS transport reliability under disconnect/failover.

4. Regression tests:
- Any bug fix must include reproducer test.

## Required Scenario Matrix

| scenario | layer | required by milestone | status | evidence |
|---|---|---|---|---|
| Valid threshold sign combine/verify | core/node | M1 | in_progress | Existing unit tests; batch variant pending. |
| Tampered partial signature rejection | core/node | M1 | todo | Add negative tests in core/node. |
| Missing nonces and malformed session rejection | node | M1/M3 | done | Node tests added for missing nonces and SID tamper. |
| Nonce exhaustion + replenish race | core/node | M3/M6 | todo | Planned adversarial test. |
| Replay request ID protection | node | M3/M6 | todo | Planned after replay cache design. |
| Sender/member binding enforcement | node | M3 | todo | Planned authorization tests. |
| WS request correlation under concurrency | transport-ws | M4 | todo | Integration tests needed. |
| WS timeout/retry/failover behavior | transport-ws | M4 | todo | Integration tests needed. |
| Batch sign and batch ECDH behavior | node/core | M5 | todo | Pending batcher implementation. |
| End-to-end onboard/ping/sign/ecdh flow | all | M6 | in_progress | Partial via node unit tests; full integration pending. |

## Milestone Acceptance Gates

### M1 Gate
- Core/node cryptographic tests pass.
- Negative session/share validation tests pass.

### M2 Gate
- Codec round-trip and strict reject tests pass.
- Parser helper tests complete.

### M3 Gate
- Security behavior tests complete (auth, replay, payload limits).

### M4 Gate
- WS integration reliability tests pass under forced network faults.

### M5 Gate
- Batching/cache/event model tests pass with deterministic behavior.

### M6 Gate
- Full scenario matrix marked complete.

### M7 Gate
- Example/doc validation steps pass.

### M8 Gate
- CI green for full workspace and release checklist complete.
