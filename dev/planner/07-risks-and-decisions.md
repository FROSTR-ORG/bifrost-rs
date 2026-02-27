# Risks And Decisions

## Risk Register

| risk_id | description | impact | likelihood | mitigation | owner | status |
|---|---|---|---|---|---|---|
| `R-001` | Nonce reuse risk in batch signing could compromise keys. | high | medium | Enforce one-time nonce lifecycle per hash/round; add adversarial tests before enabling batch sign. | core | open |
| `R-002` | WS transport lacks reconnect/failover and can stall distributed operations. | high | high | Implement relay state machine with backoff and failover tests. | transport-ws | open |
| `R-003` | Behavioral drift between TS and Rust on policy/security checks. | medium | medium | Track every flow in parity matrix and add security scenario tests. | node | open |
| `R-004` | Incomplete schema strictness may permit malformed payloads. | medium | medium | Add explicit validation layer and reject tests in codec/node. | codec/node | open |
| `R-005` | Full workspace CI confidence is limited if WS deps/tests are not consistently run. | medium | medium | Add CI matrix with online integration stage for WS transport. | infra | open |
| `R-006` | Local daemon RPC socket currently has no authentication/authorization guardrails. | high | medium | Restrict to local unix socket, document secure permissions, and add auth model before production release. | runtime | open |
| `R-007` | NIP-44 transport compatibility needs deeper external vector/interoperability coverage beyond current internal tests. | medium | low | Baseline + expanded malformed/roundtrip fixtures and deterministic matrix tests are covered in `bifrost-transport-ws` unit tests and CI target; next step is importing larger upstream corpus + external implementation interop runs. | transport-ws | open |

## Decision Log (ADR-lite)

| decision_id | date | context | decision | consequences |
|---|---|---|---|---|
| `D-001` | 2026-02-27 | Need migration target behavior definition. | Target behavioral parity with Rust safety improvements. | Internal designs may differ from TS; deviations must be documented. |
| `D-002` | 2026-02-27 | Need migration tracking model. | Track by module parity mapped to Rust crates. | Clear coverage accounting; easier ownership assignment. |
| `D-003` | 2026-02-27 | Need planning artifact format. | Use Markdown as source of truth. | Simple collaboration, low tooling overhead. |
| `D-004` | 2026-02-27 | Current signing flow safety during migration. | Keep single-message sign constraint until safe batch nonce model is complete. | Batch sign parity delayed but key-safety risk reduced. |
| `D-005` | 2026-02-27 | Rust nonce architecture diverges from TS. | Store generated FROST `SigningNonces` in pool, not derivable secret nonce bytes. | Safer integration with FROST APIs; requires explicit state handling. |
| `D-006` | 2026-02-27 | Need safe path to batch signing rollout. | Adopt nonce claim/finalize lifecycle model documented in `09-batch-sign-nonce-model.md`, with Option B per-hash session fallback allowed. | Enables incremental batch rollout with explicit anti-reuse guardrails. |
| `D-007` | 2026-02-27 | Need runtime architecture that supports headless operation and multiple UX surfaces. | Split runtime into `bifrostd` (daemon), `bifrost-cli`, and `bifrost-tui` over shared local RPC contracts. | Cleaner boundaries for automation and service deployment; introduces RPC lifecycle/auth/versioning requirements. |
| `D-008` | 2026-02-27 | Dev relay and WS transport protocols were mismatched (`EVENT/REQ` vs raw envelope frames), causing `ping/echo` timeouts in demo/devnet. | Hard-switch transport to Nostr-native frame handling (`REQ`/`EVENT`/`CLOSE`) while preserving `Transport` trait and daemon transport-agnostic boundary. | Restores RPC interoperability across real devnet nodes; encryption remains an explicit follow-up task (`M10-002`). |
| `D-009` | 2026-02-27 | Need encrypted peer RPC payloads quickly without blocking on full NIP-44 parity implementation. | Initial encrypted wrapper shipped for immediate confidentiality, then upgraded to NIP-44-v2-compatible payload processing in `bifrost-transport-ws` while retaining sender-tag binding and existing transport trait/runtime boundaries. | Restores secure E2E RPC transport with Nostr framing and compatibility-oriented crypto behavior; remaining work is extended interop/vector coverage. |
