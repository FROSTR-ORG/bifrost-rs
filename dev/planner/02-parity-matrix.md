# TS → RS Parity Matrix

Legend:
- `parity_status`: `todo` | `in_progress` | `blocked` | `done`
- `parity_type`: `exact` | `compatible` | `intentional_deviation`

| ts_path | rust_target_crate | rust_target_module | parity_status | parity_type | tests_linked | notes |
|---|---|---|---|---|---|---|
| `src/lib/group.ts` | `bifrost-core` | `group.rs` | done | compatible | `bifrost-core::group::tests` | Deterministic group ID implemented. |
| `src/lib/session.ts` | `bifrost-core` | `session.rs` | done | compatible | `bifrost-core::session::tests` | Session ID/verification implemented with stricter validation. |
| `src/lib/sign.ts` | `bifrost-core` | `sign.rs` | done | compatible | `bifrost-core::sign::tests`, `bifrost-node::node::tests` | FROST round logic integrated; batch-capable core APIs (`create_partial_sig_packages_batch`, `combine_signatures_batch`) added with nonce/session count guards. |
| `src/lib/nonce.ts` | `bifrost-core` | `nonce.rs` | in_progress | intentional_deviation | `bifrost-core::nonce::tests` (`nonce_pool_generate_and_consume`, `outgoing_signing_nonces_are_single_use`) | Rust stores FROST `SigningNonces` state with one-time claim semantics; TS used deterministic derivation model. |
| `src/lib/ecdh.ts` | `bifrost-core` | `ecdh.rs` | done | compatible | `bifrost-core::ecdh::tests`, `bifrost-node::node::tests::ecdh` | Package create/combine implemented. |
| `src/encoder/*.ts` | `bifrost-codec` | `wire.rs`, `rpc.rs` | done | compatible | `bifrost-codec::rpc::tests` | JSON envelope/wire conversions implemented. |
| `src/api/echo.ts` | `bifrost-node` | `node.rs` | done | compatible | `bifrost-node::node::tests` | Request/response flow implemented. |
| `src/api/ping.ts` | `bifrost-node` | `node.rs` | done | compatible | `bifrost-node::node::tests` | Nonce exchange implemented. |
| `src/api/onboard.ts` | `bifrost-node` | `node.rs` | done | compatible | `bifrost-node::node::tests` | Onboard response/nonce provisioning implemented. |
| `src/api/sign.ts` | `bifrost-node` | `node.rs` | in_progress | compatible | `bifrost-node::node::tests::{sign_flow_returns_signature,sign_batch_flow_returns_signatures}`, validation tests | `sign_batch` uses safe per-session multiplexing (Option B). Node orchestration for Option-A single-session multi-hash remains intentionally deferred. |
| `src/api/ecdh.ts` | `bifrost-node` | `node.rs` | done | compatible | `bifrost-node::node::tests::ecdh` | Cast/combine flow implemented. |
| `src/class/client.ts` | `bifrost-node` | `node.rs` | in_progress | compatible | `bifrost-node` unit tests (incl. sender-binding, replay/stale-id, and event emissions) | Core lifecycle implemented; sender/member binding, replay/stale-id checks, and event emissions added; middleware parity remains incomplete. |
| `src/class/pool.ts` | `bifrost-core` | `nonce.rs` | in_progress | compatible | `bifrost-core::nonce::tests` | Pool exists; evented pool and richer status APIs pending. |
| `src/class/signer.ts` | `bifrost-core` + `bifrost-node` | `sign.rs`, `ecdh.rs`, `node.rs` | in_progress | compatible | sign/ecdh tests | Missing dedicated signer facade type in Rust. |
| `src/class/batcher.ts` | `bifrost-node` | `node.rs` (`sign_queue`, `ecdh_batch`) | done | compatible | `bifrost-node::node::tests::{sign_queue_processes_multiple_chunks,ecdh_batch_processes_multiple_chunks}` | Queue-oriented sign/ECDH batcher entrypoints implemented with deterministic chunking by configured batch size. |
| `src/class/cache.ts` | `bifrost-node` | `node.rs` (ecdh cache) | done | compatible | `bifrost-node::node::tests::{ecdh_uses_cache_for_repeated_pubkey,ecdh_cache_entry_expires_after_ttl}` | TTL/LRU-style ECDH result cache implemented with configurable TTL/max entries. |
| `src/class/emitter.ts` | `bifrost-node` | `node.rs` (`subscribe_events`) | done | compatible | `bifrost-node::node::tests::{connect_emits_ready_and_info_events,handle_incoming_emits_message_event}` | Event stream parity implemented for lifecycle/message/bounced/info/error channels via node broadcast events. |
| `src/schema/*.ts` | `bifrost-codec` + `bifrost-node` | validators | in_progress | compatible | `bifrost-codec::rpc::tests`, `bifrost-codec::wire::tests`, node validation tests (sender/replay/payload limits) | Codec and node enforce payload shape/bounds, sender binding, replay/stale-id checks, and node payload limits; deeper TS schema utility parity remains pending. |
| `src/types/*.ts` | all crates | `types.rs` | in_progress | compatible | compile/tests | Most core types migrated, parity review still open. |
| `src/util/validate.ts` | `bifrost-core` + `bifrost-codec` | validation helpers | todo | compatible | none | Hex/pubkey/signature utility parity pending. |
| `src/util/crypto.ts` | `bifrost-core` | new utility module | in_progress | intentional_deviation | sign/ecdh tests | Rust uses crate APIs; utility-level parity catalog needed. |
| `src/lib/parse.ts` | `bifrost-codec` + `bifrost-node` | `parse.rs` + node parse call-sites | done | compatible | `bifrost-codec::parse::tests`, `bifrost-node::node::tests` | Explicit parser helpers implemented (`parse_session`, `parse_ecdh`, `parse_psig`, `parse_onboard_*`, `parse_ping`, `parse_group_package`, `parse_share_package`) and integrated in node response/request parsing paths. |
| `src/lib/sighash.ts` | `bifrost-core` | new module | todo | compatible | none | Sighash formatting/binder helpers pending. |
| `src/lib/package.ts` | `bifrost-codec` | wire/serialization | in_progress | compatible | codec tests | Package helper parity partially covered by wire conversions. |
| `src/class/client.ts` WS behavior | `bifrost-transport-ws` | `ws_transport.rs` | done | compatible | `bifrost-transport-ws::ws_transport::tests`, `scripts/test-node-e2e.sh`, `scripts/test-tui-e2e.sh` | Transport now uses Nostr-native `REQ`/`EVENT`/`CLOSE` framing with signed events, peer-targeted tags, and RPC request correlation; retry/backoff, relay health failover, and cast threshold behavior retained. |
| `demo/tmux/relay.ts` + `test/src/lib/relay.ts` | `bifrost-relay-dev` | `src/lib.rs`, `src/main.rs` | done | compatible | `bifrost-relay-dev::tests::{verify_event_accepts_valid_signature,filter_matches_kind_author_and_tag}` | Rust relay ports TS dev relay flow with REQ/EVENT/CLOSE handling, cache replay + EOSE, filter matching, and BIP-340 event validation. |
| `demo/tmux/node.ts` (runtime boundary) | `bifrostd` + `bifrost-cli` + `bifrost-tui` | daemon/client bins | done | intentional_deviation | `cargo check -p bifrostd -p bifrost-cli -p bifrost-tui --offline`, `scripts/devnet.sh smoke`, `scripts/test-tui-e2e.sh` | Rust runtime split introduces daemon RPC boundary for headless services and automation; `bifrost-tui` ships a pane-based `ratatui`/`crossterm` dashboard over daemon RPC with peer selector resolution and nonce-pool health status telemetry. |
