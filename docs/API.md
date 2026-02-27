# API Reference (Rust)

Concrete API map for the current `bifrost-rs` surface.

## `bifrost-core`

Primary domain types (`crates/bifrost-core/src/types.rs`):

- `GroupPackage`, `SharePackage`, `SignSessionTemplate`, `SignSessionPackage`
- `PartialSigPackage`, `EcdhPackage`, `PingPayload`, `OnboardRequest`, `OnboardResponse`

Primary functions:

- Group/session:
  - `get_group_id(group) -> CoreResult<[u8;32]>`
  - `create_session_package(group, template) -> CoreResult<SignSessionPackage>`
  - `verify_session_package(group, session) -> CoreResult<()>`
  - `get_session_id(group_id, template) -> CoreResult<[u8;32]>`
- Signing:
  - `create_partial_sig_package(group, share, session, nonce_code)`
  - `create_partial_sig_packages_batch(group, share, sessions, nonce_codes)`
  - `verify_partial_sig_package(group, session, package)`
  - `combine_signatures(group, session, partials)`
  - `combine_signatures_batch(group, sessions, partials)`
- ECDH:
  - `create_ecdh_package(group, share, members, pubkeys)`
  - `combine_ecdh_packages(pkgs, ecdh_pk)`
  - `local_pubkey_from_share(share)`

Errors: `CoreError` includes nonce safety and session integrity variants (`MissingNonces`, `NonceAlreadyClaimed`, `SessionIdMismatch`, etc.).

## `bifrost-codec`

RPC envelope (`crates/bifrost-codec/src/rpc.rs`):

- `RpcEnvelope { version, id, sender, payload }`
- `RpcPayload`:
  - `Ping`, `Echo`, `Sign`, `SignResponse`, `Ecdh`, `OnboardRequest`, `OnboardResponse`
- `encode_envelope`, `decode_envelope`

Wire payloads (`crates/bifrost-codec/src/wire.rs`):

- Group/share/session/partial-signature/ecdh/ping/onboard wire structs
- strict `TryFrom` validation with bounded sizes

Parse helpers (`crates/bifrost-codec/src/parse.rs`):

- `parse_ping`, `parse_session`, `parse_psig`, `parse_ecdh`
- `parse_onboard_request`, `parse_onboard_response`
- `parse_group_package`, `parse_share_package`

## `bifrost-transport`

Transport trait (`crates/bifrost-transport/src/traits.rs`):

- `connect`, `close`
- `request(msg, timeout_ms)`
- `cast(msg, peers, threshold, timeout_ms)`
- `send_response(handle, response)`
- `next_incoming`

Shared transport types:

- `OutgoingMessage { peer, envelope }`
- `IncomingMessage { peer, envelope }`
- `ResponseHandle { peer, request_id }`

## `bifrost-node`

Node constructor and lifecycle:

- `BifrostNode::new(group, share, peer_pubkeys, transport, clock, options)`
- `connect`, `close`, `is_ready`, `subscribe_events`

Operations:

- `echo(peer, challenge)`
- `ping(peer)`
- `onboard(peer)`
- `sign(message32)`
- `ecdh(pubkey33)`
- queue/batch helpers for sign/ecdh

Security/runtime controls in `BifrostNodeOptions`:

- timeouts, replay TTL/cache bounds
- payload length bounds
- sign/ecdh batch caps
- ECDH cache TTL/LRU bounds
- nonce pool config

Events:

- `NodeEvent::{Ready, Closed, Message, Bounced, Info, Error}`

## `bifrost-rpc`

Daemon RPC schema (`crates/bifrost-rpc/src/types.rs`):

- Request envelope: `RpcRequestEnvelope { id, request }`
- Response envelope: `RpcResponseEnvelope { id, response }`
- Request enum `BifrostRpcRequest` methods:
  - `Health`, `Status`, `Events`, `Echo`, `Ping`, `Onboard`, `Sign`, `Ecdh`, `Shutdown`
- Response enum `BifrostRpcResponse`:
  - `Ok(Value)` or `Err { code, message }`

Client helpers:

- `next_request_id()`
- `request(id, req)`
- `send_request_to(path, req)` / `send_request(stream, req)`

## Runtime binaries

- `bifrostd`: local Unix socket JSON-RPC daemon wrapping node + WS transport
- `bifrost-cli`: command-oriented RPC client
- `bifrost-tui`: interactive `ratatui` dashboard with scripted mode
- `bifrost-relay-dev`: development relay for REQ/EVENT/CLOSE flows
- `bifrost-devnet`: local key/config generation for multi-node runtime

Change management reference:

- `dev/planner/05-interfaces.md`
