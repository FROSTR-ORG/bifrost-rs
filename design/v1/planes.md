# Architectural Planes

bifrost-rs decomposes its 11 crates into three architectural planes, each with numbered layers. The planes enforce a strict downward-only dependency rule: higher layers may depend on lower layers, but never the reverse. Within a plane, layers follow the same rule. Across planes, the Control plane depends on both Data and Crypto; the Data plane depends on Crypto; the Crypto plane is self-contained with no upward dependencies.

This decomposition separates concerns along three axes:

- **Crypto plane** -- Pure deterministic computation over FROST primitives. No I/O, no async, no network. Testable in isolation with fixed inputs.
- **Data plane** -- Serialization, wire formats, transport trait definitions, and the concrete WebSocket transport implementation. Bridges the gap between in-memory crypto types and on-the-wire representations.
- **Control plane** -- Orchestration logic, daemon lifecycle, RPC schema, user-facing interfaces, and developer tooling. Owns all I/O, async coordination, and policy enforcement.

---

## Crypto Plane

**Purpose:** Stateless cryptographic operations over FROST threshold signing and ECDH primitives. All functions are pure (except `NoncePool`, which manages mutable nonce state with single-use enforcement). No network I/O, no async runtime.

**Responsibilities:**
- Group/share/session construction and validation
- Partial signature creation, verification, and aggregation
- ECDH key-share computation and combination
- Nonce lifecycle: generation, storage, consumption, spent tracking
- Sighash binding and message digest computation
- Hex encoding/decoding utilities for fixed-size byte arrays

**Ownership boundaries:** This plane owns all `frost-secp256k1-tr-unofficial` usage and all raw byte-array types (`Bytes32`, `Bytes33`). No crate outside this plane should call FROST APIs directly.

### L1: Cryptographic Primitives -- `bifrost-core`

| Property | Value |
|----------|-------|
| **Crate** | `bifrost-core` |
| **Dependencies** | (none within workspace) |
| **Layer deps** | -- |

**Modules:**

| Module | Responsibility |
|--------|---------------|
| `types` | Core byte-array types and protocol data structures |
| `group` | Group identity derivation (`get_group_id`) |
| `session` | Sign session construction and verification |
| `sign` | Partial signature creation, verification, and aggregation (single and batch) |
| `ecdh` | ECDH key-share creation and combination |
| `nonce` | `NoncePool` with single-use enforcement, per-peer generation/consumption |
| `sighash` | Message digest and session-bound sighash computation |
| `validate` | Hex decode/encode utilities, pubkey/signature format validation |
| `error` | `CoreError` / `CoreResult` error types |

**Key types:**

| Type | Description |
|------|-------------|
| `GroupPackage` | Group public key, threshold, and member list |
| `SharePackage` | Member index and secret key share (zeroized on drop) |
| `SignSessionPackage` | Full session: group ID, session ID, members, hashes, nonce commitments |
| `SignSessionTemplate` | Template for session creation (before ID derivation) |
| `PartialSigPackage` | Partial signatures from a single member with nonce replenishment |
| `PartialSigEntry` | Single hash-index partial signature |
| `SignatureEntry` | Finalized Schnorr signature with sighash and pubkey |
| `NoncePool` | Per-peer nonce pool with spent tracking and FIFO consumption |
| `NoncePoolConfig` | Pool size, min/critical thresholds, replenish count |
| `NoncePeerStats` | Per-peer nonce availability snapshot |
| `DerivedPublicNonce` | Public nonce commitment (binder, hidden, code) |
| `MemberPublicNonce` | Indexed public nonce for a specific member |
| `IndexedPublicNonceCommitment` | Hash-index-scoped nonce commitment (batch signing) |
| `MemberNonceCommitmentSet` | Per-member set of indexed nonce commitments |
| `EcdhPackage` | ECDH key-share entries for a member |
| `EcdhEntry` | Single ECDH public key and computed key-share |
| `PingPayload` | Peer ping with version, nonces, and policy profile |
| `PeerScopedPolicyProfile` | Per-peer policy revision with method-level controls |
| `OnboardRequest` / `OnboardResponse` | Onboarding handshake types |
| `PeerError` | Structured peer error (code + message) |
| `Bytes32` / `Bytes33` | Fixed-size byte array type aliases |
| `CoreError` / `CoreResult` | Error enum covering all crypto-layer failures |

**Key public functions:**

| Function | Signature summary |
|----------|-------------------|
| `get_group_id` | `(&GroupPackage) -> CoreResult<Bytes32>` |
| `create_session_package` | `(&GroupPackage, SignSessionTemplate) -> CoreResult<SignSessionPackage>` |
| `get_session_id` | Derives deterministic session ID from template |
| `verify_session_package` | Validates session against group |
| `create_partial_sig_package` | Single-hash partial signature creation |
| `create_partial_sig_packages_batch` | Multi-hash batch partial signature creation |
| `verify_partial_sig_package` | Verifies a peer's partial signature |
| `combine_signatures` / `combine_signatures_batch` | Aggregates partial sigs into Schnorr signatures |
| `create_ecdh_package` | Creates ECDH key-share from share |
| `combine_ecdh_packages` | Combines ECDH key-shares into shared secret |
| `local_pubkey_from_share` | Derives compressed public key from share |
| `message_sighash` | `SHA256(message)` digest |
| `bind_sighash` | `SHA256(session_id || sighash)` binding |
| `decode_fixed_hex` / `decode_hex32` / `decode_hex33` / `decode_sig64` | Fixed-size hex decoding |
| `encode_hex` | Fixed-size hex encoding |
| `validate_pubkey33` / `validate_signature64` | Format validation |

---

### L2: Protocol Helpers -- `frostr-utils`

| Property | Value |
|----------|-------|
| **Crate** | `frostr-utils` |
| **Dependencies** | `bifrost-core` |
| **Layer deps** | L1 |

**Modules:**

| Module | Responsibility |
|--------|---------------|
| `keyset` | Dealer-based keyset creation and rotation |
| `onboarding` | Bech32m encode/decode of onboarding packages, binary serialization |
| `protocol` | Stateless sign/ECDH helpers consumed by the node layer |
| `recovery` | Lagrange-interpolation key recovery from threshold shares |
| `verify` | Group config, keyset, and individual share verification |
| `types` | High-level lifecycle types (keyset bundles, onboarding, recovery) |
| `errors` | `FrostUtilsError` / `FrostUtilsResult` error types |

**Key types:**

| Type | Description |
|------|-------------|
| `CreateKeysetConfig` | Threshold and count for new keyset generation |
| `KeysetBundle` | Group package + all share packages |
| `KeysetVerificationReport` | Verification result: member count, threshold, verified shares |
| `RotateKeysetRequest` / `RotateKeysetResult` | Key rotation input/output |
| `RecoverKeyInput` / `RecoveredKeyMaterial` | Key recovery from shares |
| `OnboardingPackage` | Share + peer public key + relay list |
| `FrostUtilsError` / `FrostUtilsResult` | Error types for this layer |

**Key public functions:**

| Function | Signature summary |
|----------|-------------------|
| `create_keyset` | `(CreateKeysetConfig) -> FrostUtilsResult<KeysetBundle>` |
| `rotate_keyset_dealer` | Generates new keyset with rotation tracking |
| `verify_keyset` / `verify_group_config` / `verify_share` | Verification functions |
| `recover_key` | `(&RecoverKeyInput) -> FrostUtilsResult<RecoveredKeyMaterial>` |
| `build_onboarding_package` | Constructs `OnboardingPackage` |
| `encode_onboarding_package` / `decode_onboarding_package` | Bech32m encode/decode |
| `serialize_onboarding_data` / `deserialize_onboarding_data` | Binary serialization |
| `sign_create_partial` | Wraps core partial sig creation with pubkey derivation |
| `sign_verify_partial` | Wraps core partial sig verification |
| `sign_finalize` | Wraps core signature aggregation |
| `ecdh_create_from_share` | Creates ECDH package from share |
| `ecdh_finalize` | Combines ECDH key-shares |
| `validate_sign_session` | Validates session against group |

---

## Data Plane

**Purpose:** Serialization, wire-format conversion, transport abstractions, and the concrete WebSocket transport. This plane translates between the Crypto plane's in-memory types and the on-the-wire JSON representations used by the Nostr relay network.

**Responsibilities:**
- JSON-RPC envelope encoding/decoding for peer-to-peer messages
- Wire type definitions that maintain external compatibility with bifrost-ts
- Typed parser entry points for each protocol message kind
- Group/share package JSON serialization
- Transport trait definitions (connect, close, request, cast, next_incoming)
- Clock and Sleeper trait abstractions for testability
- WebSocket transport with Nostr event wrapping, NIP-44-style encryption, relay failover

**Ownership boundaries:** This plane owns all wire-format types (`*Wire` structs), the `RpcEnvelope` peer-to-peer envelope, and the `Transport`/`Clock`/`Sleeper` trait definitions. The WebSocket transport owns all relay connection state, backoff logic, and Nostr event construction.

### L3: Codec -- `bifrost-codec`

| Property | Value |
|----------|-------|
| **Crate** | `bifrost-codec` |
| **Dependencies** | `bifrost-core` |
| **Layer deps** | L1 |

**Modules:**

| Module | Responsibility |
|--------|---------------|
| `rpc` | Peer-to-peer JSON-RPC envelope encode/decode, method enum, payload variants |
| `wire` | Wire-format structs (`*Wire`) with `From`/`TryInto` conversions to/from core types |
| `parse` | Typed parser entry points for each message kind |
| `package` | Group/share package JSON encode/decode |
| `hexbytes` | Hex encode/decode utilities for wire-layer use |
| `error` | `CodecError` / `CodecResult` error types |

**Key types:**

| Type | Description |
|------|-------------|
| `RpcEnvelope` | Peer-to-peer envelope: version, id, sender, payload |
| `RpcMethod` | Method discriminant: `Ping`, `Echo`, `Sign`, `Ecdh`, `Onboard`, `Error` |
| `RpcPayload` | Tagged payload enum with all message variants |
| `GroupPackageWire` / `SharePackageWire` | Wire representations of group/share with hex-encoded fields |
| `SignSessionPackageWire` | Wire sign session with hex-string hashes and nonce commitments |
| `PartialSigPackageWire` | Wire partial signature with hex-string fields |
| `EcdhPackageWire` / `EcdhEntryWire` | Wire ECDH types |
| `PingPayloadWire` | Wire ping with optional nonces and policy profile |
| `OnboardRequestWire` / `OnboardResponseWire` | Wire onboarding types |
| `PeerErrorWire` | Wire peer error |
| `DerivedPublicNonceWire` / `MemberPublicNonceWire` | Wire nonce types |
| `CodecError` / `CodecResult` | Error types |

**Key public functions:**

| Function | Signature summary |
|----------|-------------------|
| `encode_envelope` / `decode_envelope` | `RpcEnvelope` JSON serialization with validation |
| `parse_ping` / `parse_session` / `parse_psig` / `parse_ecdh` | Typed parsers from `RpcEnvelope` to core types |
| `parse_onboard_request` / `parse_onboard_response` / `parse_error` | Additional typed parsers |
| `parse_group_package` / `parse_share_package` | JSON string to core types |
| `encode_group_package_json` / `encode_share_package_json` | Core types to JSON string |
| `decode_group_package_json` / `decode_share_package_json` | JSON string to core types |

---

### L4: Transport Traits -- `bifrost-transport`

| Property | Value |
|----------|-------|
| **Crate** | `bifrost-transport` |
| **Dependencies** | `bifrost-codec` |
| **Layer deps** | L3 |

**Modules:**

| Module | Responsibility |
|--------|---------------|
| `traits` | `Transport`, `Clock`, `Sleeper` trait definitions |
| `types` | Message and handle types used across trait boundaries |
| `error` | `TransportError` / `TransportResult` error types |

**Key types:**

| Type | Description |
|------|-------------|
| `Transport` | Async trait: `connect`, `close`, `request`, `cast` (threshold gather), `send_response`, `next_incoming` |
| `Clock` | Trait for abstracting wall-clock time (testability) |
| `Sleeper` | Async trait for abstracting sleep/delay |
| `OutgoingMessage` | Outbound: target peer + `RpcEnvelope` |
| `IncomingMessage` | Inbound: source peer + `RpcEnvelope` |
| `ResponseHandle` | Reply handle: peer + request ID for response routing |
| `TransportError` / `TransportResult` | Error types |

---

### L5: WebSocket Transport -- `bifrost-transport-ws`

| Property | Value |
|----------|-------|
| **Crate** | `bifrost-transport-ws` |
| **Dependencies** | `bifrost-transport`, `bifrost-codec` |
| **Layer deps** | L3, L4 |

**Modules:**

| Module | Responsibility |
|--------|---------------|
| `ws_transport` | Full WebSocket `Transport` implementation with Nostr event wrapping |

**Key types:**

| Type | Description |
|------|-------------|
| `WebSocketTransport` | Concrete `Transport` impl: multi-relay WebSocket connections, NIP-44-style encryption, Nostr signed event wrapping |
| `WsTransportConfig` | Connection config: max retries, backoff timing, RPC kind |
| `WsNostrConfig` | Nostr identity: sender pubkey/seckey, peer pubkey list |
| `ConnectionState` | Enum: `Disconnected`, `Connecting`, `Backoff`, `Connected`, `Closing` |
| `RelayHealth` | Per-relay health tracking: success/failure counts, timestamps, last error |

**Implementation details:**
- Multi-relay support with health-ranked failover
- Exponential backoff reconnection
- Pending-request cleanup on disconnect
- ChaCha20 content encryption with ECDH-derived shared secrets
- BIP-340 Schnorr signing of Nostr events
- Subscription management for relay-based message routing

---

## Control Plane

**Purpose:** Application orchestration, daemon lifecycle, RPC interfaces, user-facing tools, and developer utilities. This plane owns all I/O coordination, policy enforcement, event streaming, and user interaction.

**Responsibilities:**
- Node-level orchestration of sign, ECDH, ping, echo, onboard flows
- Nonce pool lifecycle management and replenishment signaling
- Replay cache and stale-envelope rejection
- Per-peer policy enforcement (block, request, respond controls)
- Event emission and subscription
- Headless daemon with Unix socket JSON-RPC server
- Authentication and authorization (fail-closed by default)
- CLI and TUI client interfaces
- Keygen and local relay for development/testing

**Ownership boundaries:** This plane owns the `BifrostNode` orchestrator, all daemon/client state, and the RPC schema. It coordinates between the Crypto and Data planes but delegates all cryptographic work downward.

### L6: Node Orchestrator -- `bifrost-node`

| Property | Value |
|----------|-------|
| **Crate** | `bifrost-node` |
| **Dependencies** | `bifrost-core`, `bifrost-codec`, `bifrost-transport`, `frostr-utils` |
| **Layer deps** | L1, L2, L3, L4 |

**Modules:**

| Module | Responsibility |
|--------|---------------|
| `node` | `BifrostNode<T, C>` -- main orchestrator with all protocol operations |
| `client` | `NodeClient<T, C>`, `Signer<T, C>`, `NoncePoolView<T, C>` -- typed client wrappers |
| `types` | Configuration, peer data, policy, event types |
| `error` | `NodeError` / `NodeResult` error types |

**Key types:**

| Type | Description |
|------|-------------|
| `BifrostNode<T: Transport, C: Clock>` | Generic orchestrator: owns nonce pool, replay cache, ECDH cache, peer state, event emitter |
| `NodeClient<T, C>` | Middleware-aware client wrapper around `BifrostNode` |
| `NodeMiddleware` | Trait for before/after request hooks |
| `Signer<T, C>` | Focused signing interface (`sign_message`, `sign_messages`) |
| `NoncePoolView<T, C>` | Read-only view of nonce pool health and config |
| `BifrostNodeConfig` | Resolved runtime config with peer list |
| `BifrostNodeOptions` | Tunable parameters: timeouts, cache limits, batch sizes, nonce pool config |
| `PeerData` | Peer snapshot: pubkey, status, policy, last-updated timestamp |
| `PeerStatus` | Enum: `Online`, `Offline` |
| `PeerPolicy` / `MethodPolicy` | Per-peer policy with per-method (echo/ping/onboard/sign/ecdh) controls |
| `PeerNonceHealth` | Per-peer nonce health: available, spent, can-sign, should-send |
| `NodeEvent` | Event enum: `Ready`, `Closed`, `Message`, `Bounced`, `Info`, `Error` |
| `NodeError` / `NodeResult` | Error types |

**Key operations on `BifrostNode`:**
- `connect` / `close` -- transport lifecycle
- `echo` / `ping` / `onboard` -- peer interaction
- `sign` / `sign_batch` / `sign_queue` -- threshold signing (single, batch, queued)
- `ecdh` / `ecdh_batch` -- ECDH shared secret computation
- `process_next_incoming` -- inbound message handler loop
- `subscribe_events` -- broadcast event channel
- `set_peer_policy` / `peer_policy` / `peer_policies` -- policy management
- `peer_nonce_health` / `nonce_pool_config` -- nonce introspection
- `peers_snapshot` / `share_idx` / `is_ready` -- state queries

---

### L7: RPC Schema -- `bifrost-rpc`

| Property | Value |
|----------|-------|
| **Crate** | `bifrost-rpc` |
| **Dependencies** | (none within workspace) |
| **Layer deps** | -- |

**Modules:**

| Module | Responsibility |
|--------|---------------|
| `types` | RPC envelope, request/response enums, daemon status, peer/policy views |
| `client` | Low-level Unix socket request/response helpers |
| `app_client` | `DaemonClient` high-level typed client |

**Key types:**

| Type | Description |
|------|-------------|
| `RpcRequestEnvelope` | Daemon RPC request: id, rpc_version, auth_token, request body |
| `RpcResponseEnvelope` | Daemon RPC response: id, result (Ok data / Err code+message) |
| `BifrostRpcRequest` | Request enum: `Negotiate`, `Health`, `Status`, `Events`, `Echo`, `Ping`, `Onboard`, `Sign`, `Ecdh`, `GetPeerPolicies`, `GetPeerPolicy`, `SetPeerPolicy`, `RefreshPeerPolicy`, `Shutdown` |
| `BifrostRpcResponse` | Response enum: `Ok(Value)`, `Err { code, message }` |
| `DaemonStatus` | Daemon state snapshot: ready, share_idx, nonce pool config, peer list |
| `PeerView` | RPC-facing peer snapshot with nonce health columns |
| `PeerPolicyView` / `MethodPolicyView` | RPC-facing policy representations |
| `DaemonClient` | Typed async client: wraps Unix socket with methods for each RPC operation |
| `RPC_VERSION` | Protocol version constant (`1`) |

**Key public functions:**

| Function | Signature summary |
|----------|-------------------|
| `send_request_to` | `(&Path, RpcRequestEnvelope) -> Result<RpcResponseEnvelope>` |
| `send_request` | `(UnixStream, RpcRequestEnvelope) -> Result<RpcResponseEnvelope>` |
| `next_request_id` | Generates millisecond-precision request ID |
| `request` | Builds `RpcRequestEnvelope` with version and env-based auth token |

---

### L8: Daemon -- `bifrostd`

| Property | Value |
|----------|-------|
| **Crate** | `bifrostd` |
| **Dependencies** | `bifrost-core`, `bifrost-codec`, `bifrost-node`, `bifrost-rpc`, `bifrost-transport`, `bifrost-transport-ws` |
| **Layer deps** | L1, L3, L4, L5, L6, L7 |

**Modules:**

| Module | Responsibility |
|--------|---------------|
| `main` | Daemon entry point: config loading, node setup, Unix socket server, RPC dispatch |

**Key types:**

| Type | Description |
|------|-------------|
| `DaemonConfig` | Top-level config: socket path, group/share paths, peers, relays, options, transport, auth |
| `DaemonPeerConfig` | Per-peer config: pubkey + policy view |
| `DaemonTransportConfig` | Transport tuning: RPC kind, retries, backoff, optional sender identity |
| `DaemonAuthConfig` | Auth config: token, allow_unauthenticated_read, insecure_no_auth |
| `DaemonState` | Runtime state: node handle, event buffer, stop flag, auth config |
| `SystemClock` | `Clock` trait implementation using `SystemTime` |

**Key constants:**

| Constant | Value | Purpose |
|----------|-------|---------|
| `RPC_MAX_LINE_BYTES` | 65536 | Maximum RPC frame size |
| `SOCKET_MODE_SECURE` | `0o600` | Unix socket file permission mode |

**Key behaviors:**
- Fail-closed auth: requires `auth.token` unless `insecure_no_auth` is set
- Read-only exception: `allow_unauthenticated_read` permits status/health without token
- RPC version negotiation with min/max supported range
- Bounded line framing (64 KiB max per RPC line)
- Event collector task: buffers up to 1024 events from node broadcast channel
- Inbound processor task: continuous `process_next_incoming` loop

---

### L9: User Interfaces -- `bifrost-cli`, `bifrost-tui`

#### `bifrost-cli`

| Property | Value |
|----------|-------|
| **Crate** | `bifrost-cli` |
| **Dependencies** | `bifrost-rpc` |
| **Layer deps** | L7 |

**Modules:**

| Module | Responsibility |
|--------|---------------|
| `main` | CLI entry point: argument parsing, command dispatch, JSON output |

**Key behaviors:**
- Scriptable CLI over daemon RPC via Unix socket
- Commands: `negotiate`, `health`, `status`, `events`, `echo`, `ping`, `onboard`, `sign`, `ecdh`, `policy` (list/get/set/refresh), `shutdown`
- Flags: `--socket PATH`, `--json` (compact output)
- Uses `DaemonClient` for all RPC communication
- Auth token sourced from `BIFROST_RPC_TOKEN` environment variable

#### `bifrost-tui`

| Property | Value |
|----------|-------|
| **Crate** | `bifrost-tui` |
| **Dependencies** | `bifrost-core`, `bifrost-rpc` |
| **Layer deps** | L1, L7 |

**Modules:**

| Module | Responsibility |
|--------|---------------|
| `main` | TUI entry point: terminal setup, event loop, rendering, command execution |

**Key types:**

| Type | Description |
|------|-------------|
| `App` | Application state: client, input buffer, message history, peers, active peer |
| `Theme` | Color scheme for TUI panels |

**Key behaviors:**
- `ratatui`/`crossterm` interactive dashboard with three-panel layout (header, peers, output+input)
- Auto-refresh of status and events on 2-second interval
- Peer selectors: 1-based index, alias (alice/bob/carol/dave), pubkey prefix
- `use <peer>` sets active peer target for subsequent commands
- Smart echo routing: explicit peer selector or falls back to active peer
- `sign` command: text mode (`sign hello`) with SHA256 digest, hex mode (`sign hex:...` or `sign 0x:...`)
- `--script` mode for non-interactive execution from a file
- Nonce health visualization with progress bars per peer

---

### L10: Dev Tooling -- `bifrost-devtools`

| Property | Value |
|----------|-------|
| **Crate** | `bifrost-devtools` |
| **Dependencies** | `bifrost-core`, `bifrost-codec`, `frostr-utils` |
| **Layer deps** | L1, L2, L3 |

**Modules:**

| Module | Responsibility |
|--------|---------------|
| `main` | Entry point: command dispatch (`keygen`, `relay`) |
| `keygen` | Key generation: creates group/share packages and daemon configs |
| `relay` | Local Nostr relay with BIP-340 signature verification |

**Key types:**

| Type | Description |
|------|-------------|
| `NostrRelay` | Local Nostr relay: TCP listener, subscription management, event cache, BIP-340 verify |
| `EventFilter` | Nostr subscription filter: ids, authors, kinds, since, until, limit |
| `SignedEvent` | Nostr signed event structure |

**Key behaviors:**
- `keygen`: Generates threshold keyset via `create_keyset`, writes group/share JSON files and per-participant daemon config files
- `relay`: Lightweight local Nostr relay for development and testing; verifies BIP-340 signatures on incoming events; configurable purge interval via `BIFROST_RELAY_PURGE_SECS`
- Flags: `--out-dir`, `--threshold`, `--count`, `--relay`, `--socket-dir`, `--port`

---

## Dependency Summary

The table below shows each layer's direct workspace dependencies using L-numbers.

| Layer | Crate | Direct layer dependencies |
|-------|-------|---------------------------|
| L1 | `bifrost-core` | -- |
| L2 | `frostr-utils` | L1 |
| L3 | `bifrost-codec` | L1 |
| L4 | `bifrost-transport` | L3 |
| L5 | `bifrost-transport-ws` | L3, L4 |
| L6 | `bifrost-node` | L1, L2, L3, L4 |
| L7 | `bifrost-rpc` | -- |
| L8 | `bifrostd` | L1, L3, L4, L5, L6, L7 |
| L9a | `bifrost-cli` | L7 |
| L9b | `bifrost-tui` | L1, L7 |
| L10 | `bifrost-devtools` | L1, L2, L3 |

Note: L7 (`bifrost-rpc`) has no workspace dependencies -- it defines a self-contained RPC schema using only `serde`, `serde_json`, and `tokio`. This makes it independently consumable by any client without pulling in protocol crates.
