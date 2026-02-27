# Execution Backlog

| task_id | milestone | description | owner | status | depends_on | exit_evidence |
|---|---|---|---|---|---|---|
| `M1-001` | M1 | Finalize safe batch-sign nonce model (one-time nonces per hash/signing round). | core | in_progress | none | Design note + tests for nonce reuse rejection. |
| `M1-002` | M1 | Implement batched signing in `bifrost-core::sign` with safe nonce handling. | core | todo | `M1-001` | Passing batch sign tests + parity row updates. |
| `M1-003` | M1 | Expand signature-share verification negative tests (invalid share/member mismatch). | core | todo | none | Added tests in core/node suites. |
| `M2-001` | M2 | Add strict wire payload bounds/shape validation equivalents from TS schema constraints. | codec | in_progress | none | Codec reject tests and documentation. |
| `M2-002` | M2 | Add explicit parse helpers parity map (`parse_session`, `parse_ecdh`, etc.). | codec/node | todo | `M2-001` | New parse modules + tests. |
| `M3-001` | M3 | Enforce strict member binding and sender authorization checks in node handlers. | node | in_progress | none | Node auth tests for unauthorized senders. |
| `M3-002` | M3 | Add replay/idempotency protections for request IDs and stale envelopes. | node | todo | `M3-001` | Replay tests and documented behavior. |
| `M3-003` | M3 | Add payload limit enforcement equivalent to TS security flags. | node | todo | none | Size-limit rejection tests. |
| `M4-001` | M4 | Add websocket reconnect/backoff and connection state transitions. | transport-ws | todo | none | WS integration tests with forced disconnect. |
| `M4-002` | M4 | Add multi-relay strategy/failover and health tracking. | transport-ws | todo | `M4-001` | Relay failover integration tests. |
| `M4-003` | M4 | Stabilize cast/request threshold behavior under partial response loss. | transport-ws | todo | `M4-001` | Deterministic threshold tests. |
| `M5-001` | M5 | Implement sign/ecdh request batchers in node crate. | node | todo | M1 batch design | Queue processing tests. |
| `M5-002` | M5 | Implement ECDH cache (TTL/LRU) equivalent to TS behavior. | node | todo | none | Cache unit tests and docs. |
| `M5-003` | M5 | Add event model/emitter parity for lifecycle, message, bounced/info events. | node | todo | none | API docs + event-driven tests. |
| `M6-001` | M6 | Build cross-crate integration suite for onboard/ping/sign/ecdh happy paths. | qa | todo | M1-M5 | Integration test results. |
| `M6-002` | M6 | Build adversarial suite: tampered signatures, malformed sessions, nonce exhaustion. | qa | todo | M1-M5 | Adversarial test report. |
| `M7-001` | M7 | Update root/crate READMEs to reflect current and target parity status. | docs | todo | M1-M6 | README diff with milestone references. |
| `M7-002` | M7 | Provide runnable examples for node+ws multi-peer flow in `example/`. | docs/qa | todo | M4-M6 | Verified example run notes. |
| `M8-001` | M8 | Add CI matrix for full workspace checks/tests including WS crate. | infra | todo | M4-M6 | CI pipeline passing with artifacts. |
| `M8-002` | M8 | Create migration guide from TS usage to Rust APIs. | docs | todo | M5-M7 | Published migration guide file. |

## Execution Pass 1 (PR-Sized Plan)

| pr_id | scope | backlog_tasks | planned changes | acceptance checks |
|---|---|---|---|---|
| `PR-01` | Batch-sign nonce design and guardrails | `M1-001` | Add a short design note in planner for nonce lifecycle and introduce explicit API invariants in `bifrost-core` docs/errors. | New/updated tests prove nonce single-use and reject reuse paths. |
| `PR-02` | Codec validation hardening | `M2-001` | Add strict bounds/shape checks for wire payloads and reject malformed envelopes early. | Codec tests for invalid payload shapes and size limits pass. |
| `PR-03` | Sender/member binding security | `M3-001` | Enforce sender-to-member checks in sign/ecdh/ping handler paths and reject unauthorized messages. | Node tests demonstrate unauthorized sender rejection and valid sender acceptance. |
| `PR-04` | Batch-sign implementation | `M1-002` | Implement safe multi-hash signing flow after `PR-01` design is locked. | Core/node batch signing tests pass; parity matrix updated. |
| `PR-05` | Signature-share adversarial tests | `M1-003` | Add invalid share/member mismatch/tamper test matrix in core and node layers. | Negative-path tests pass and evidence linked in `06-test-strategy.md`. |
