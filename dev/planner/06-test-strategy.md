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
| Valid threshold sign combine/verify | core/node | M1 | done | Core and node signing tests pass, including `sign::combine_signatures_batch_signs_multiple_sessions`. |
| Tampered partial signature rejection | core/node | M1 | done | `bifrost-core::sign::tests::verify_partial_sig_rejects_tampered_signature_share` + integration `adversarial_rejects_tampered_signature_share`. |
| Missing nonces and malformed session rejection | node | M1/M3 | done | Node tests added for missing nonces and SID tamper. |
| Nonce exhaustion + replenish race | core/node | M3/M6 | in_progress | Adversarial nonce exhaustion rejection test added (`adversarial_nonce_exhaustion_fails_second_sign`); replenish race scenario still pending. |
| Replay request ID protection | node | M3/M6 | done | `bifrost-node::node::tests::{handle_incoming_rejects_replayed_request_id,handle_incoming_rejects_stale_request_id}`. |
| Sender/member binding enforcement | node | M3 | done | `handle_incoming_sign_rejects_sender_peer_mismatch`, `handle_incoming_onboard_rejects_sender_idx_mismatch`. |
| Node payload limit enforcement | node | M3 | done | `handle_incoming_rejects_oversized_echo_payload`, `handle_incoming_rejects_oversized_sign_content`. |
| ECDH cache TTL/LRU behavior | node | M5 | done | `bifrost-node::node::tests::{ecdh_uses_cache_for_repeated_pubkey,ecdh_cache_entry_expires_after_ttl}`. |
| Node event model/emitter behavior | node | M5 | done | `bifrost-node::node::tests::{connect_emits_ready_and_info_events,handle_incoming_emits_message_event}`. |
| WS request correlation under concurrency | transport-ws | M4 | in_progress | Concurrent cast threshold logic covered in ws unit tests; high-concurrency relay integration tests still pending. |
| Encrypted event payload roundtrip and sender tag binding | transport-ws | M10 | done | `bifrost-transport-ws::ws_transport::tests::{encrypt_decrypt_roundtrip,nip44_vector_conversation_key_matches_spec,nip44_vector_encrypt_matches_spec_payload,nip44_vector_decrypt_matches_spec_payload,nip44_fixture_vectors,nip44_deterministic_matrix_and_mutation_rejects}` using expanded fixture corpus `crates/bifrost-transport-ws/tests/nip44_vectors.json` (valid, malformed, wrong-key, url-safe decode, deterministic and random roundtrips) + devnet `scripts/test-node-e2e.sh` and `scripts/test-tui-e2e.sh` pass with encrypted content transport enabled. |
| WS reconnect/backoff state transitions | transport-ws | M4 | done | `bifrost-transport-ws::ws_transport::tests::{backoff_is_exponential_and_capped,connect_without_relays_sets_disconnected_state,close_transitions_to_disconnected}`. |
| WS relay health/failover ordering | transport-ws | M4 | done | `bifrost-transport-ws::ws_transport::tests::{relay_order_prefers_healthier_relays,relay_health_snapshot_tracks_success_and_failure}`. |
| WS timeout/retry/failover behavior | transport-ws | M4 | in_progress | Unit-level reconnect/backoff/failover/threshold tests are in place; forced network-fault integration tests still needed. |
| Batch sign and batch ECDH behavior | node/core | M5 | done | Node/core batch APIs + queue/batch tests pass (`sign_batch`, `sign_queue`, `ecdh_batch`, core batch sign helpers). |
| End-to-end onboard/ping/sign/ecdh flow | all | M6 | done | Cross-crate happy-path integration test `crates/bifrost-node/tests/happy_paths.rs::integration_happy_paths_echo_ping_onboard_sign_ecdh`. |
| Nonce claim-once and no-reuse guarantees | core/node | M1/M5 | in_progress | `bifrost-core::nonce::tests::outgoing_signing_nonces_are_single_use`; batch-level no-reuse tests still pending. |
| Batch hash-index to nonce binding correctness | core/node | M1/M5 | todo | Defined in `09-batch-sign-nonce-model.md`; tests pending. |
| Codec malformed envelope/wire rejection | codec | M2 | done | `rpc::decode_envelope_rejects_empty_id`, `rpc::decode_envelope_rejects_oversized_echo`, wire reject tests for empty hash/psig/ecdh entries. |
| Parse helper parity entrypoints | codec/node | M2 | done | `bifrost-codec::parse::tests::{parse_session_rejects_wrong_payload_kind,parse_ecdh_and_psig_roundtrip,parse_group_and_share_package_json,parse_ping_and_onboard_payloads}` and node tests passing with parser call-sites. |
| Dev relay BIP-340 verification and filter matching | relay | M9 | done | `cargo test -p bifrost-relay-dev --offline` (`verify_event_accepts_valid_signature`, `filter_matches_kind_author_and_tag`). |
| Daemon/CLI/TUI compile-level contract stability | runtime | M9 | done | `cargo check -p bifrostd -p bifrost-cli -p bifrost-tui --offline` + `scripts/devnet.sh smoke` (relay + 3 daemons + CLI health/status/events); includes pane-based `ratatui` TUI build validation. |
| Node RPC method e2e coverage (`echo`, `ping`, `onboard`, `sign`, `ecdh`) | node | M9 | done | `cargo test -p bifrost-node --test happy_paths --offline` (`integration_rpc_echo_e2e`, `integration_rpc_ping_e2e`, `integration_rpc_onboard_e2e`, `integration_rpc_sign_e2e`, `integration_rpc_ecdh_e2e`). |
| `bifrost-cli` command-to-RPC e2e mapping | runtime/cli | M9 | done | `cargo test -p bifrost-cli --test e2e_cli --offline` (run in environment allowing local Unix socket bind). |
| `bifrost-tui` devnet e2e RPC method exercise | runtime/tui | M9/M10 | done | `scripts/test-tui-e2e.sh` (real devnet daemons + scripted TUI commands for `health/status/events/ping/echo/onboard/sign/ecdh`; asserts success-path outputs). |
| `bifrost-tui` UX regression guardrails (peer selectors + nonce-health status formatting + tail-follow rendering) | runtime/tui | M9 | done | `cargo test -p bifrost-tui --offline` (`resolve_peer_selector_supports_index_alias_and_prefix`, `format_status_lines_includes_nonce_columns`) + `scripts/test-tui-e2e.sh`; includes alias selectors (`alice,bob,carol`) and status progress bars based on daemon nonce-pool thresholds. |
| `bifrost-node` devnet e2e flow (keygen/distribution/onboard/RPC) | runtime/node | M9/M10 | done | `scripts/test-node-e2e.sh` (real devnet daemons; validates generated/distributed key material and requires successful `ping/echo/onboard/sign/ecdh` through `bifrostd`/`bifrost-cli`). |
| Release audit command matrix | release/security | M8 | done | `dev/audit/internal-audit-2026-02-27.md` + `dev/audit/AUDIT.md` command matrix (`cargo check --workspace --offline`, core/ws/runtime tests, serial devnet e2e). |
| Canonical audit template framework | release/security | M8 | done | `dev/audit/templates/` provides ordered category templates (`01`-`11`) plus `00-index.template.md` and `99-summary.template.md` using severity+status model; execution target is `dev/audit/work/`. |
| Multi-agent audit execution runbook | release/security | M8 | done | `dev/audit/RUNBOOK.md` + `dev/audit/templates/*` defines parallel delegation, shared notes cadence, findings normalization, and remediation queue handoff. |

## Milestone Acceptance Gates

### M1 Gate
- Core/node cryptographic tests pass.
- Negative session/share validation tests pass.
- Nonce claim/reuse guardrail tests pass per `09-batch-sign-nonce-model.md`.

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

### M9 Gate
- Runtime targets build and pass relay/rpc unit coverage.
- Local loop validation (`relay` + `bifrostd` + `bifrost-cli`) captured with reproducible evidence.
