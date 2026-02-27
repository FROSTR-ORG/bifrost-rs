# Risks And Decisions

## Risk Register

| risk_id | description | impact | likelihood | mitigation | owner | status |
|---|---|---|---|---|---|---|
| `R-001` | Nonce reuse risk in batch signing could compromise keys. | high | medium | Enforce one-time nonce lifecycle per hash/round; add adversarial tests before enabling batch sign. | core | open |
| `R-002` | WS transport lacks reconnect/failover and can stall distributed operations. | high | high | Implement relay state machine with backoff and failover tests. | transport-ws | open |
| `R-003` | Behavioral drift between TS and Rust on policy/security checks. | medium | medium | Track every flow in parity matrix and add security scenario tests. | node | open |
| `R-004` | Incomplete schema strictness may permit malformed payloads. | medium | medium | Add explicit validation layer and reject tests in codec/node. | codec/node | open |
| `R-005` | Full workspace CI confidence is limited if WS deps/tests are not consistently run. | medium | medium | Add CI matrix with online integration stage for WS transport. | infra | open |

## Decision Log (ADR-lite)

| decision_id | date | context | decision | consequences |
|---|---|---|---|---|
| `D-001` | 2026-02-27 | Need migration target behavior definition. | Target behavioral parity with Rust safety improvements. | Internal designs may differ from TS; deviations must be documented. |
| `D-002` | 2026-02-27 | Need migration tracking model. | Track by module parity mapped to Rust crates. | Clear coverage accounting; easier ownership assignment. |
| `D-003` | 2026-02-27 | Need planning artifact format. | Use Markdown as source of truth. | Simple collaboration, low tooling overhead. |
| `D-004` | 2026-02-27 | Current signing flow safety during migration. | Keep single-message sign constraint until safe batch nonce model is complete. | Batch sign parity delayed but key-safety risk reduced. |
| `D-005` | 2026-02-27 | Rust nonce architecture diverges from TS. | Store generated FROST `SigningNonces` in pool, not derivable secret nonce bytes. | Safer integration with FROST APIs; requires explicit state handling. |
