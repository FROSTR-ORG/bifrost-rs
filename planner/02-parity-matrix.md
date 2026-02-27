# TS → RS Parity Matrix

Legend:
- `parity_status`: `todo` | `in_progress` | `blocked` | `done`
- `parity_type`: `exact` | `compatible` | `intentional_deviation`

| ts_path | rust_target_crate | rust_target_module | parity_status | parity_type | tests_linked | notes |
|---|---|---|---|---|---|---|
| `src/lib/group.ts` | `bifrost-core` | `group.rs` | done | compatible | `bifrost-core::group::tests` | Deterministic group ID implemented. |
| `src/lib/session.ts` | `bifrost-core` | `session.rs` | done | compatible | `bifrost-core::session::tests` | Session ID/verification implemented with stricter validation. |
| `src/lib/sign.ts` | `bifrost-core` | `sign.rs` | in_progress | compatible | `bifrost-core::sign::tests`, `bifrost-node::node::tests` | FROST round logic integrated; batched signing still pending. |
| `src/lib/nonce.ts` | `bifrost-core` | `nonce.rs` | in_progress | intentional_deviation | `bifrost-core::nonce::tests` | Rust stores FROST `SigningNonces` state; TS used deterministic derivation model. |
| `src/lib/ecdh.ts` | `bifrost-core` | `ecdh.rs` | done | compatible | `bifrost-core::ecdh::tests`, `bifrost-node::node::tests::ecdh` | Package create/combine implemented. |
| `src/encoder/*.ts` | `bifrost-codec` | `wire.rs`, `rpc.rs` | done | compatible | `bifrost-codec::rpc::tests` | JSON envelope/wire conversions implemented. |
| `src/api/echo.ts` | `bifrost-node` | `node.rs` | done | compatible | `bifrost-node::node::tests` | Request/response flow implemented. |
| `src/api/ping.ts` | `bifrost-node` | `node.rs` | done | compatible | `bifrost-node::node::tests` | Nonce exchange implemented. |
| `src/api/onboard.ts` | `bifrost-node` | `node.rs` | done | compatible | `bifrost-node::node::tests` | Onboard response/nonce provisioning implemented. |
| `src/api/sign.ts` | `bifrost-node` | `node.rs` | in_progress | compatible | `bifrost-node::node::tests::sign`, validation tests | Single-message signing only; batch flow pending. |
| `src/api/ecdh.ts` | `bifrost-node` | `node.rs` | done | compatible | `bifrost-node::node::tests::ecdh` | Cast/combine flow implemented. |
| `src/class/client.ts` | `bifrost-node` | `node.rs` | in_progress | compatible | `bifrost-node` unit tests | Core lifecycle implemented; event/middleware/security parity incomplete. |
| `src/class/pool.ts` | `bifrost-core` | `nonce.rs` | in_progress | compatible | `bifrost-core::nonce::tests` | Pool exists; evented pool and richer status APIs pending. |
| `src/class/signer.ts` | `bifrost-core` + `bifrost-node` | `sign.rs`, `ecdh.rs`, `node.rs` | in_progress | compatible | sign/ecdh tests | Missing dedicated signer facade type in Rust. |
| `src/class/batcher.ts` | `bifrost-node` | `node.rs` + new module | todo | compatible | none | Sign/ECDH queue batchers not implemented. |
| `src/class/cache.ts` | `bifrost-node` | new module | todo | compatible | none | ECDH cache with TTL/LRU not implemented. |
| `src/class/emitter.ts` | `bifrost-node` | new module/trait | todo | compatible | none | Event bus parity pending. |
| `src/schema/*.ts` | `bifrost-codec` + `bifrost-node` | validators | in_progress | compatible | node session validation tests | More strict payload/schema enforcement pending. |
| `src/types/*.ts` | all crates | `types.rs` | in_progress | compatible | compile/tests | Most core types migrated, parity review still open. |
| `src/util/validate.ts` | `bifrost-core` + `bifrost-codec` | validation helpers | todo | compatible | none | Hex/pubkey/signature utility parity pending. |
| `src/util/crypto.ts` | `bifrost-core` | new utility module | in_progress | intentional_deviation | sign/ecdh tests | Rust uses crate APIs; utility-level parity catalog needed. |
| `src/lib/parse.ts` | `bifrost-codec` + `bifrost-node` | rpc/wire parse | in_progress | compatible | codec/node tests | Message-type-specific parsers not fully mapped. |
| `src/lib/sighash.ts` | `bifrost-core` | new module | todo | compatible | none | Sighash formatting/binder helpers pending. |
| `src/lib/package.ts` | `bifrost-codec` | wire/serialization | in_progress | compatible | codec tests | Package helper parity partially covered by wire conversions. |
| `src/class/client.ts` WS behavior | `bifrost-transport-ws` | `ws_transport.rs` | in_progress | compatible | none | Missing reconnect/failover and production reliability behavior. |
