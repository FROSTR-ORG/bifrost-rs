# Implicit Behaviors Catalog

This document catalogs undocumented, implicit, and conventionally-enforced behaviors
across the bifrost-rs workspace. Each entry includes the exact source file and line
number where the behavior originates. Operators, auditors, and contributors should
treat this as a reference for behaviors that are not obvious from public type
signatures or API documentation alone.

All file paths are relative to the repository root.

---

## 1. Environment Variables

The following environment variables affect runtime behavior. None are validated at
build time; all are read at process start or first use.

| Variable | Purpose | Location |
|---|---|---|
| `BIFROST_RPC_TOKEN` | Attached as `auth_token` on every outgoing RPC request envelope when set and non-empty. Omitted when unset or empty. | `crates/bifrost-rpc/src/client.rs:54` |
| `BIFROST_RELAY_PURGE_SECS` | Controls the periodic event cache purge interval (in seconds) for the devtools relay. When unset, the relay never purges its cache. Parsed as `u64`; unparseable values are silently treated as unset. | `crates/bifrost-devtools/src/main.rs:49` |
| `RELAY_URL` | Default relay URL for the contrib example binary. Falls back to `wss://relay.damus.io`. | `contrib/example/src/main.rs:22` |
| `RUN_NETWORK` | When set to `"1"`, the contrib example binary performs a live network sign round instead of exiting after local key generation. | `contrib/example/src/main.rs:23` |

---

## 2. Hardcoded Constants and Magic Values

### 2.1 Protocol Constants

| Constant | Value | Purpose | Location |
|---|---|---|---|
| `PEER_ENVELOPE_VERSION` | `1` | Version field written into every outgoing `RpcEnvelope` by `BifrostNode`. Receivers do not currently reject mismatched versions at the node layer (only at the codec validation layer). | `crates/bifrost-node/src/node.rs:36` |
| `RPC_VERSION` | `1` | Protocol version stamped on every `RpcRequestEnvelope`. Used by both client and daemon for version negotiation. | `crates/bifrost-rpc/src/types.rs:3` |
| `RPC_VERSION_MIN_SUPPORTED` | `1` | Minimum RPC version the daemon will accept. Requests below this are rejected with code 426. | `crates/bifrostd/src/main.rs:73` |
| `RPC_VERSION_MAX_SUPPORTED` | `1` | Maximum RPC version the daemon will accept. | `crates/bifrostd/src/main.rs:74` |
| `PREFIX_ONBOARD` | `"bfonboard"` | Bech32m human-readable prefix for onboarding package encoding. | `crates/frostr-utils/src/onboarding.rs:7` |
| Default `rpc_kind` | `20_000` | Nostr ephemeral event kind used for all RPC transport messages. Hardcoded as the default in both daemon config and `WsTransportConfig`. | `crates/bifrostd/src/main.rs:92`, `crates/bifrost-transport-ws/src/ws_transport.rs:56` |
| NIP-44 HKDF salt | `b"nip44-v2"` | Fixed salt for HKDF-Extract in the NIP-44 conversation key derivation. | `crates/bifrost-transport-ws/src/ws_transport.rs:362` |
| NIP-44 version byte | `2` | First byte of the NIP-44 encrypted payload. Decryption rejects any other version. | `crates/bifrost-transport-ws/src/ws_transport.rs:470` (encrypt), `crates/bifrost-transport-ws/src/ws_transport.rs:515` (decrypt) |
| Nostr event `"b"` tag | sender's 33-byte compressed pubkey | Custom tag attached to every outgoing Nostr event for sender binding. Inbound events are matched by extracting the `"b"` tag to identify the sender's compressed pubkey. | `crates/bifrost-transport-ws/src/ws_transport.rs:557` |

### 2.2 Daemon Security Constants

| Constant | Value | Purpose | Location |
|---|---|---|---|
| `RPC_MAX_LINE_BYTES` | `65536` (64 KiB) | Maximum size of a single newline-delimited RPC request line. Lines exceeding this cause a 413 error and connection close. | `crates/bifrostd/src/main.rs:75` |
| `SOCKET_MODE_SECURE` | `0o600` | Unix file permission mode applied to the daemon socket immediately after bind. Owner-only read/write. | `crates/bifrostd/src/main.rs:76` |

### 2.3 Codec Size Limits

These constants guard against oversized wire payloads during deserialization:

| Constant | Value | Purpose | Location |
|---|---|---|---|
| `MAX_GROUP_MEMBERS` | `1000` | Maximum members in a group or sign session wire package. | `crates/bifrost-codec/src/wire.rs:12` |
| `MAX_SIGN_BATCH_SIZE` | `100` | Maximum hashes in a sign session, entries in a nonce commitment set, or partial signatures in a package. | `crates/bifrost-codec/src/wire.rs:13` |
| `MAX_ECDH_BATCH_SIZE` | `100` | Maximum entries in an ECDH package. | `crates/bifrost-codec/src/wire.rs:14` |
| `MAX_NONCE_PACKAGE` | `1000` | Maximum nonce packages in a ping, sign session, or onboard response. | `crates/bifrost-codec/src/wire.rs:15` |
| Envelope ID max length | `256` | Codec-level validation rejects envelope IDs longer than 256 bytes. | `crates/bifrost-codec/src/rpc.rs:60` |
| Envelope sender max length | `256` | Codec-level validation rejects envelope senders longer than 256 bytes. | `crates/bifrost-codec/src/rpc.rs:63` |
| Echo payload max length | `8192` | Codec-level validation rejects echo payloads longer than 8192 bytes. | `crates/bifrost-codec/src/rpc.rs:69` |

### 2.4 Node Default Options

All values from `BifrostNodeOptions::default()`:

| Option | Default Value | Purpose | Location |
|---|---|---|---|
| `sign_timeout_ms` | `30_000` | Timeout for sign operations (ms). | `crates/bifrost-node/src/types.rs:77` |
| `ecdh_timeout_ms` | `30_000` | Timeout for ECDH operations (ms). | `crates/bifrost-node/src/types.rs:78` |
| `ping_timeout_ms` | `15_000` | Timeout for ping operations (ms). | `crates/bifrost-node/src/types.rs:79` |
| `request_ttl_secs` | `300` | Maximum age (seconds) of a request ID before it is considered stale. | `crates/bifrost-node/src/types.rs:80` |
| `request_cache_limit` | `4096` | Maximum entries in the replay cache before LRU eviction. | `crates/bifrost-node/src/types.rs:81` |
| `max_sign_batch` | `100` | Maximum hashes per sign session at the node layer. | `crates/bifrost-node/src/types.rs:82` |
| `max_ecdh_batch` | `100` | Maximum entries per ECDH batch at the node layer. | `crates/bifrost-node/src/types.rs:83` |
| `max_request_id_len` | `256` | Maximum byte length of a request ID in an inbound envelope. | `crates/bifrost-node/src/types.rs:84` |
| `max_sender_len` | `256` | Maximum byte length of a sender field in an inbound envelope. | `crates/bifrost-node/src/types.rs:85` |
| `max_echo_len` | `8192` | Maximum byte length of an echo payload in an inbound envelope. | `crates/bifrost-node/src/types.rs:86` |
| `max_sign_content_len` | `16384` | Maximum byte length of a sign session content field. | `crates/bifrost-node/src/types.rs:87` |
| `ecdh_cache_ttl_secs` | `300` | Time-to-live (seconds) for cached ECDH results. | `crates/bifrost-node/src/types.rs:88` |
| `ecdh_cache_max_entries` | `1024` | Maximum entries in the ECDH result cache. | `crates/bifrost-node/src/types.rs:89` |

### 2.5 Nonce Pool Defaults

All values from `NoncePoolConfig::default()`:

| Option | Default Value | Purpose | Location |
|---|---|---|---|
| `pool_size` | `100` | Maximum nonces stored per peer direction (incoming or outgoing). | `crates/bifrost-core/src/nonce.rs:20` |
| `min_threshold` | `20` | When outgoing nonce count for a peer drops below this, `should_send_nonces_to()` returns true. | `crates/bifrost-core/src/nonce.rs:21` |
| `critical_threshold` | `5` | When incoming nonce count for a peer drops to this or below, `can_sign()` returns false. | `crates/bifrost-core/src/nonce.rs:22` |
| `replenish_count` | `50` | Number of nonces to generate when replenishing for a peer. | `crates/bifrost-core/src/nonce.rs:23` |

### 2.6 Transport Defaults

All values from `WsTransportConfig::default()` and `DaemonTransportConfig::default()`:

| Option | Default Value | Purpose | Location |
|---|---|---|---|
| `max_retries` | `3` | Maximum reconnection attempts before giving up on a relay. | `crates/bifrost-transport-ws/src/ws_transport.rs:53`, `crates/bifrostd/src/main.rs:96` |
| `backoff_initial_ms` | `250` | Initial backoff delay (ms) for reconnection. Doubles each attempt. | `crates/bifrost-transport-ws/src/ws_transport.rs:54`, `crates/bifrostd/src/main.rs:100` |
| `backoff_max_ms` | `5_000` | Maximum backoff delay (ms) cap. | `crates/bifrost-transport-ws/src/ws_transport.rs:55`, `crates/bifrostd/src/main.rs:104` |
| Broadcast channel capacity | `256` | Capacity of the `tokio::sync::broadcast` channel for node events. | `crates/bifrost-node/src/node.rs:142` |

### 2.7 Onboarding Binary Layout Constants

These govern the binary serialization format of onboarding packages:

| Constant | Value | Purpose | Location |
|---|---|---|---|
| `SHARE_INDEX_SIZE` | `4` | Bytes for share index in onboarding package. | `crates/frostr-utils/src/onboarding.rs:8` |
| `SHARE_SECKEY_SIZE` | `32` | Bytes for share secret key. | `crates/frostr-utils/src/onboarding.rs:9` |
| `PEER_PK_SIZE` | `32` | Bytes for peer public key. | `crates/frostr-utils/src/onboarding.rs:10` |
| `RELAY_COUNT_SIZE` | `2` | Bytes for relay count header. | `crates/frostr-utils/src/onboarding.rs:11` |
| `RELAY_LEN_SIZE` | `2` | Bytes for each relay URL length prefix. | `crates/frostr-utils/src/onboarding.rs:12` |
| `MAX_RELAY_LENGTH` | `512` | Maximum length of a single relay URL. | `crates/frostr-utils/src/onboarding.rs:13` |
| `MAX_RELAY_COUNT` | `100` | Maximum number of relays in an onboarding package. | `crates/frostr-utils/src/onboarding.rs:14` |
| `MIN_RELAY_COUNT` | `1` | Minimum number of relays required. | `crates/frostr-utils/src/onboarding.rs:15` |

---

## 3. Conventions Not Enforced by Types

### 3.1 Hex Encoding for All Byte Arrays in Wire Types

All byte array fields (`Bytes32`, `Bytes33`, variable-length) are hex-encoded as
lowercase strings in wire types. The codec module provides the `hexbytes::encode`
and `hexbytes::decode` functions used by every `TryFrom`/`From` implementation.

- Encode: `crates/bifrost-codec/src/hexbytes.rs:3`
- Decode (fixed): `crates/bifrost-codec/src/hexbytes.rs:7`
- Decode (variable): `crates/bifrost-codec/src/hexbytes.rs:21`

Every wire struct field (`GroupPackageWire::group_pk`, `SharePackageWire::seckey`,
`SignSessionPackageWire::gid`, `SignSessionPackageWire::sid`, `PartialSigPackageWire::pubkey`,
etc.) uses `String` for these fields and relies on hex encode/decode at the boundary.
See `crates/bifrost-codec/src/wire.rs:151-706` for all conversions.

### 3.2 Canonical Ascending Sort of Session Members

Session members must be sorted in ascending order by their `u16` index. This is
enforced at multiple layers:

- **Core session creation**: `canonicalize_and_validate_members()` sorts members
  and validates the result. `crates/bifrost-core/src/session.rs:111-113`
- **Core session verification**: `validate_canonical_members()` rejects non-ascending
  or duplicate members. `crates/bifrost-core/src/session.rs:121-133`
- **Node sign validation**: `validate_sign_session()` independently checks ascending
  sort order and rejects violations. `crates/bifrost-node/src/node.rs:1184-1190`
- **Node ECDH validation**: `validate_ecdh_request()` independently checks ascending
  sort order. `crates/bifrost-node/src/node.rs:1270-1276`

### 3.3 Deterministic Group ID

The group ID is computed as `SHA-256(group_pk || threshold_le32 || sorted_member_pubkeys)`.
Members are sorted by index before hashing. The threshold is encoded as a little-endian
`u32`.

- Implementation: `crates/bifrost-core/src/group.rs:6-25`
- Hash construction: `crates/bifrost-core/src/group.rs:14-24`

### 3.4 Deterministic Session ID

The session ID is computed as:
```
SHA-256(
  group_id
  || for each member: (idx as u32).to_le_bytes()
  || for each sighash: sighash
  || content (or [0x00] if absent/empty)
  || kind.as_bytes()
  || stamp.to_le_bytes()
)
```

Members must already be in canonical ascending order (validated before hashing).

- Implementation: `crates/bifrost-core/src/session.rs:71-97`
- Group ID input: `crates/bifrost-core/src/session.rs:78`
- Member indices: `crates/bifrost-core/src/session.rs:80-82`
- Hashes: `crates/bifrost-core/src/session.rs:84-86`
- Content (with absent/empty sentinel): `crates/bifrost-core/src/session.rs:88-91`
- Kind and stamp: `crates/bifrost-core/src/session.rs:93-94`

### 3.5 Sighash Binding

Before signing, each sighash is bound to its session ID via
`bind_sighash(session_id, sighash) = SHA-256(session_id || sighash)`. This prevents
cross-session signature reuse.

- Implementation: `crates/bifrost-core/src/sighash.rs:7-12`

### 3.6 ECDH Shared Secret Derivation

The final ECDH shared secret is `SHA-256(combined_point)` where `combined_point` is
the SEC1-compressed sum of all threshold keyshares for a given ECDH public key.

- Implementation: `crates/bifrost-core/src/ecdh.rs:57-60`

### 3.7 FIFO Incoming Nonce Consumption Order

Incoming nonces from each peer are consumed in FIFO order. The nonce pool maintains a
per-peer `VecDeque<Bytes32>` that records insertion order. `consume_incoming()` pops
from the front.

- Order queue: `crates/bifrost-core/src/nonce.rs:38` (`incoming_order` field)
- Insertion (push_back): `crates/bifrost-core/src/nonce.rs:143`
- Consumption (pop_front): `crates/bifrost-core/src/nonce.rs:151`
- Test confirming FIFO: `crates/bifrost-core/src/nonce.rs:339-359`

### 3.8 Atomic All-or-Nothing Batch Nonce Claims

`take_outgoing_signing_nonces_many()` validates all requested nonce codes exist before
consuming any. If any code is missing or already spent, the entire batch fails and no
nonces are consumed.

- Validation pass: `crates/bifrost-core/src/nonce.rs:197-214`
- Consumption pass: `crates/bifrost-core/src/nonce.rs:216-221`

### 3.9 SharePackage Implements Zeroize/Drop

`SharePackage` derives `Zeroize` with `#[zeroize(drop)]`, which causes the `seckey`
field (32-byte secret key) to be zeroed on drop.

- Derive: `crates/bifrost-core/src/types.rs:19-20`
- Struct definition: `crates/bifrost-core/src/types.rs:21-24`

### 3.10 Nonce Single-Use Enforcement

`take_outgoing_signing_nonces()` removes the signing nonce from the secret map,
inserts the code into the spent set, and returns the nonce. A second call with the
same code returns `NonceAlreadyClaimed`.

- Remove from secret map: `crates/bifrost-core/src/nonce.rs:175`
- Spent set check: `crates/bifrost-core/src/nonce.rs:176-179`
- Insert into spent set: `crates/bifrost-core/src/nonce.rs:185`

### 3.11 Request ID Format

Request IDs follow the format `{unix_timestamp}-{member_idx}-{sequence}`, parsed by
`parse_request_id_components()`. The timestamp component is used for TTL-based stale
envelope rejection.

- Parser: `crates/bifrost-node/src/node.rs:1539-1548`
- TTL check: `crates/bifrost-node/src/node.rs:1024-1028`

### 3.12 Nostr Event ID Computation

Nostr event IDs are computed as `SHA-256(json([0, pubkey, created_at, kind, tags, content]))`.
This follows the NIP-01 canonical serialization format.

- Preimage construction: `crates/bifrost-transport-ws/src/ws_transport.rs:560-568`
- Hash computation: `crates/bifrost-transport-ws/src/ws_transport.rs:569`

### 3.13 Relay Health-Ranked Failover

When multiple relays are configured, the transport sorts them by (fewest failures,
most successes, lexicographic URL) before each connection attempt.

- Sort implementation: `crates/bifrost-transport-ws/src/ws_transport.rs:255-260`

### 3.14 Exponential Backoff with Cap

Reconnection backoff follows `initial_ms * 2^attempt`, capped at `backoff_max_ms`.
The exponent is clamped at 20 to prevent overflow.

- Backoff computation: `crates/bifrost-transport-ws/src/ws_transport.rs:172-178`

---

## 4. RPC Error Code Conventions

The daemon uses numeric error codes in `BifrostRpcResponse::Err`. These are not
HTTP status codes but follow similar conventions:

| Code | Meaning | Trigger | Location |
|---|---|---|---|
| `400` | Bad Request | Malformed JSON, invalid RPC line, or unparseable request envelope. | `crates/bifrostd/src/main.rs:319`, `crates/bifrostd/src/main.rs:339` |
| `401` | Unauthorized | Missing or incorrect `auth_token` when authentication is required. | `crates/bifrostd/src/main.rs:402` |
| `413` | Payload Too Large | RPC request line exceeds `RPC_MAX_LINE_BYTES` (64 KiB). | `crates/bifrostd/src/main.rs:317` |
| `426` | Upgrade Required | `rpc_version` in the request is outside the supported range. | `crates/bifrostd/src/main.rs:389` |
| `500` | Internal Error | Any unhandled error from the node during request execution. | `crates/bifrostd/src/main.rs:542` |

### Authentication Logic

The `is_request_authorized()` function implements three authorization modes:

1. **No token configured + `insecure_no_auth=true`**: All requests are allowed.
2. **Token configured + request token matches**: All requests are allowed.
3. **Token configured + `allow_unauthenticated_read=true` + no/wrong token**: Only
   read-only requests (Negotiate, Health, Status, Events, GetPeerPolicies,
   GetPeerPolicy) are allowed.

Read-only request classification: `crates/bifrostd/src/main.rs:553-563`
Authorization logic: `crates/bifrostd/src/main.rs:565-575`

---

## 5. Default Behaviors

### 5.1 Peer Policy Defaults

When a peer is initialized, its policy defaults to all methods allowed and
`block_all = false`:

```
PeerPolicy {
    block_all: false,
    request: MethodPolicy { echo: true, ping: true, onboard: true, sign: true, ecdh: true },
    respond: MethodPolicy { echo: true, ping: true, onboard: true, sign: true, ecdh: true },
}
```

- `MethodPolicy::default()`: `crates/bifrost-core/src/types.rs:134-143`
- `PeerPolicy` derives `Default`: `crates/bifrost-core/src/types.rs:118`
- Node-level `MethodPolicy::default()`: `crates/bifrost-node/src/types.rs:19-28`
- Node-level `PeerPolicy` derives `Default`: `crates/bifrost-node/src/types.rs:31`
- Keygen generates configs with all methods enabled: `crates/bifrost-devtools/src/keygen.rs:118-134`

### 5.2 TUI Auto-Refresh Interval and Output Buffer

- **Auto-refresh**: The TUI polls daemon status every 2 seconds.
  `crates/bifrost-tui/src/main.rs:21`
- **Output buffer**: The TUI retains the last 5,000 messages in its output buffer.
  `crates/bifrost-tui/src/main.rs:20`
- **Event poll interval**: The TUI polls for terminal input events every 120ms.
  `crates/bifrost-tui/src/main.rs:152`

### 5.3 Default Socket Paths

- **CLI default**: `/tmp/bifrostd.sock` (overridable with `--socket`).
  `crates/bifrost-cli/src/main.rs:14`
- **TUI default**: `/tmp/bifrostd.sock` (overridable with `--socket`).
  `crates/bifrost-tui/src/main.rs:100`
- **Keygen socket pattern**: `{socket_dir}/bifrostd-{name}.sock` where `socket_dir`
  defaults to `/tmp`. `crates/bifrost-devtools/src/keygen.rs:139`

### 5.4 Devtools Keygen Defaults

- **Default names**: `["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi"]`
  (8 names, max count). `crates/bifrost-devtools/src/keygen.rs:10-12`
- **Default threshold**: `2`. `crates/bifrost-devtools/src/keygen.rs:69`
- **Default count**: `3`. `crates/bifrost-devtools/src/keygen.rs:72`
- **Default relay**: `ws://127.0.0.1:8194`. `crates/bifrost-devtools/src/keygen.rs:73`
- **Default socket dir**: `/tmp`. `crates/bifrost-devtools/src/keygen.rs:74`
- **Default output dir**: `dev/data`. `crates/bifrost-devtools/src/keygen.rs:66`
- **Default auth**: `insecure_no_auth=true`, no token. `crates/bifrost-devtools/src/keygen.rs:158-162`

### 5.5 Devtools Relay Default Port

- **Default port**: `8194`. `crates/bifrost-devtools/src/main.rs:33`

### 5.6 Daemon Event Buffer

The daemon's event collector maintains a capped `VecDeque` of event labels. When it
reaches 1024 entries, the oldest is evicted.

- Capacity check and eviction: `crates/bifrostd/src/main.rs:263-265`

### 5.7 Daemon Inbound Processing Poll Interval

The inbound processor loop sleeps 10ms between calls to `process_next_incoming()`.

- Poll interval: `crates/bifrostd/src/main.rs:278`

### 5.8 Daemon Auth Default Behavior

`DaemonAuthConfig` derives `Default`, which means:
- `token`: `None`
- `allow_unauthenticated_read`: `false`
- `insecure_no_auth`: `false`

With these defaults, the daemon will reject all requests (fail-closed) because no
token is configured and insecure mode is not enabled. The config loader enforces that
either `token` is set or `insecure_no_auth` is explicitly `true`.

- Default derive: `crates/bifrostd/src/main.rs:62`
- Config validation: `crates/bifrostd/src/main.rs:294-303`

### 5.9 RPC Request ID Generation

`next_request_id()` returns the current Unix timestamp in milliseconds (as `u64`).
This is used as the `id` field in RPC request envelopes.

- Implementation: `crates/bifrost-rpc/src/client.rs:43-51`

### 5.10 CLI Default Events Limit

When the CLI `events` command is run without an explicit limit, it defaults to `20`.

- Default: `crates/bifrost-cli/src/main.rs:58`

### 5.11 NIP-44 Payload Length Constraints

The transport enforces both minimum and maximum payload lengths for NIP-44 encrypted
content:
- Base64 payload: 132 to 87,472 characters.
- Decoded binary: 99 to 65,603 bytes.
- Plaintext: 1 to 65,535 bytes (encoded as big-endian u16 length prefix).

- Base64 length check: `crates/bifrost-transport-ws/src/ws_transport.rs:500`
- Binary length check: `crates/bifrost-transport-ws/src/ws_transport.rs:510`
- Plaintext length check: `crates/bifrost-transport-ws/src/ws_transport.rs:400`

### 5.12 Socket Cleanup on Shutdown

The daemon removes the Unix socket file on both startup (if it already exists) and
clean shutdown.

- Startup cleanup: `crates/bifrostd/src/main.rs:206-208`
- Shutdown cleanup: `crates/bifrostd/src/main.rs:234`
