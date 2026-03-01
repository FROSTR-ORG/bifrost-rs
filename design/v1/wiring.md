# Wiring Diagrams

This document provides Mermaid diagrams illustrating data flow, dependency edges, and shared state within bifrost-rs. Each diagram is annotated with layer numbers (L1--L10) and plane names (Crypto, Data, Control) as defined in `planes.md`.

---

## 1. Crate Dependency Graph

The 11 workspace crates grouped by architectural plane. Directed edges represent workspace-level `Cargo.toml` dependencies (higher depends on lower). The Crypto plane is self-contained, the Data plane depends on Crypto, and the Control plane depends on both.

```mermaid
graph TD
    subgraph Crypto["Crypto Plane"]
        L1["L1: bifrost-core"]
        L2["L2: frostr-utils"]
    end

    subgraph Data["Data Plane"]
        L3["L3: bifrost-codec"]
        L4["L4: bifrost-transport"]
        L5["L5: bifrost-transport-ws"]
    end

    subgraph Control["Control Plane"]
        L6["L6: bifrost-node"]
        L7["L7: bifrost-rpc"]
        L8["L8: bifrostd"]
        L9a["L9a: bifrost-cli"]
        L9b["L9b: bifrost-tui"]
        L10["L10: bifrost-devtools"]
    end

    %% Crypto internal
    L2 --> L1

    %% Data depends on Crypto
    L3 --> L1
    L4 --> L3
    L5 --> L3
    L5 --> L4

    %% Control depends on Crypto + Data
    L6 --> L1
    L6 --> L2
    L6 --> L3
    L6 --> L4

    L8 --> L1
    L8 --> L3
    L8 --> L4
    L8 --> L5
    L8 --> L6
    L8 --> L7

    L9a --> L7
    L9b --> L1
    L9b --> L7

    L10 --> L1
    L10 --> L2
    L10 --> L3
```

---

## 2. Sign Flow

Traces `BifrostNode::sign()`, which delegates to `sign_batch()` for a single message. The flow begins with peer selection and nonce consumption, creates a session package, multicasts to peers via `Transport::cast`, collects and verifies partial signatures, then aggregates them into the final Schnorr signature. All nonce operations are guarded by `Mutex<NoncePool>`.

```mermaid
sequenceDiagram
    participant Caller
    participant Node as L6: BifrostNode
    participant Policy as L6: policies (Mutex)
    participant Pool as L1: NoncePool (Mutex)
    participant Session as L1: create_session_package
    participant Transport as L4/L5: Transport
    participant Codec as L3: bifrost-codec
    participant Utils as L2: frostr-utils
    participant Core as L1: bifrost-core

    Caller->>Node: sign(message)
    Node->>Node: sign_batch(&[message])
    Node->>Node: ensure_ready()

    Note over Node,Policy: Peer Selection
    Node->>Policy: lock() -- read policies
    Node->>Pool: lock() -- check can_sign per peer
    Node-->>Node: select_signing_peers()
    Note right of Node: If InsufficientPeers,<br/>refresh_unknown_policy_peers<br/>then retry selection

    Note over Node,Pool: Nonce Consumption
    Node->>Pool: lock()
    loop For each selected peer, for each hash
        Pool->>Pool: consume_incoming(peer_idx)
    end
    Pool->>Pool: generate_for_peer(self_idx, count)
    Note right of Pool: Self nonce codes saved<br/>for later signing nonce retrieval

    Note over Node,Session: Session Creation
    Node->>Session: create_session_package(group, template)
    Session-->>Node: SignSessionPackage
    Node->>Node: validate_sign_session()

    Note over Node,Transport: Multicast to Peers (async)
    Node->>Codec: SignSessionPackageWire::from(session)
    Codec-->>Node: RpcEnvelope with Sign payload
    Node->>Transport: cast(envelope, selected_peers, threshold, timeout)
    Transport-->>Node: Vec of IncomingMessage responses

    Note over Node,Core: Local Partial Signature
    Node->>Pool: lock()
    Pool->>Pool: take_outgoing_signing_nonces_many(self_idx, codes)
    Pool-->>Node: signing nonces
    Node->>Utils: sign_create_partial(group, session, share, nonces)
    Utils->>Core: create_partial_sig_packages_batch(...)
    Core-->>Utils: PartialSigPackage
    Utils-->>Node: local PartialSigPackage

    Note over Node,Core: Verify Peer Responses
    loop For each peer response
        Node->>Node: assert_expected_response_peer()
        Node->>Codec: parse_psig(envelope)
        Codec-->>Node: PartialSigPackage
        Node->>Utils: sign_verify_partial(group, session, pkg)
        Utils->>Core: verify partial signature
    end

    Note over Node,Core: Aggregate Signatures
    Node->>Utils: sign_finalize(group, session, all_pkgs)
    Utils->>Core: combine_signatures_batch(...)
    Core-->>Utils: Vec of SignatureEntry
    Utils-->>Node: Vec of SignatureEntry
    Node-->>Caller: [u8; 64] signature
```

---

## 3. ECDH Flow

Traces `BifrostNode::ecdh()`. The method first checks the in-memory ECDH cache for a non-expired entry (shortcut path). On cache miss, it selects peers, computes a local key-share, multicasts to peers, collects and combines key-shares, then stores the result in the cache before returning.

```mermaid
sequenceDiagram
    participant Caller
    participant Node as L6: BifrostNode
    participant Cache as L6: EcdhCache (Mutex)
    participant Policy as L6: policies (Mutex)
    participant Transport as L4/L5: Transport
    participant Codec as L3: bifrost-codec
    participant Utils as L2: frostr-utils

    Caller->>Node: ecdh(pubkey)
    Node->>Node: ensure_ready()

    Note over Node,Cache: Cache Check (shortcut path)
    Node->>Cache: lock() -- get_cached_ecdh(pubkey, now)
    alt Cache hit and not expired
        Cache-->>Node: Some(shared_secret)
        Node-->>Caller: [u8; 32] shared_secret
    else Cache miss or expired
        Cache-->>Node: None

        Note over Node,Policy: Peer Selection
        Node->>Policy: lock() -- read policies + remote profiles
        Node-->>Node: select_signing_peers(Ecdh)

        Note over Node,Utils: Local ECDH Key-Share
        Node->>Utils: ecdh_create_from_share(members, share, [pubkey])
        Utils-->>Node: local EcdhPackage

        Note over Node,Transport: Multicast to Peers (async)
        Node->>Codec: EcdhPackageWire::from(local_pkg)
        Codec-->>Node: RpcEnvelope with Ecdh payload
        Node->>Transport: cast(envelope, selected_peers, threshold, timeout)
        Transport-->>Node: Vec of IncomingMessage responses

        Note over Node,Utils: Collect and Verify Peer Responses
        loop For each peer response
            Node->>Node: assert_expected_response_peer()
            Node->>Codec: parse_ecdh(envelope)
            Codec-->>Node: EcdhPackage
        end

        Note over Node,Utils: Combine Key-Shares
        Node->>Utils: ecdh_finalize(all_pkgs, pubkey)
        Utils-->>Node: [u8; 32] shared_secret

        Note over Node,Cache: Store in Cache
        Node->>Cache: lock() -- store_cached_ecdh(pubkey, secret, now)
        Node-->>Caller: [u8; 32] shared_secret
    end
```

---

## 4. Ping / Nonce Exchange

Traces the outbound `BifrostNode::ping()` method and the corresponding inbound ping handler within `handle_incoming()`. Ping is the primary mechanism for exchanging nonce commitments between peers. Each side conditionally generates outgoing nonces (if the pool indicates the peer needs them) and stores any received nonces. Policy profiles are also exchanged during the ping.

```mermaid
sequenceDiagram
    participant NodeA as L6: BifrostNode (initiator)
    participant PoolA as L1: NoncePool (initiator)
    participant Transport as L4/L5: Transport
    participant PoolB as L1: NoncePool (responder)
    participant NodeB as L6: BifrostNode (responder)

    Note over NodeA: Outbound ping()
    NodeA->>NodeA: ensure_ready()
    NodeA->>NodeA: enforce_outbound_request_policy(peer, Ping)

    NodeA->>PoolA: lock()
    PoolA->>PoolA: should_send_nonces_to(peer_idx)?
    alt Should send nonces
        PoolA->>PoolA: generate_for_peer(peer_idx, replenish_count)
        PoolA-->>NodeA: Vec of DerivedPublicNonce
    else No nonces needed
        PoolA-->>NodeA: None
    end

    Note right of NodeA: Build PingPayload with<br/>nonces + local policy profile

    NodeA->>Transport: request(OutgoingMessage, ping_timeout_ms)

    Note over Transport,NodeB: --- Relay Network ---

    Note over NodeB: Inbound handle_incoming()
    NodeB->>NodeB: validate_sender_binding(peer, sender)
    NodeB->>PoolB: lock()

    alt Ping carries nonces
        PoolB->>PoolB: store_incoming(peer_idx, nonces)
    end

    Note right of NodeB: Store remote scoped policy if present

    PoolB->>PoolB: should_send_nonces_to(peer_idx)?
    alt Should send reply nonces
        PoolB->>PoolB: generate_for_peer(peer_idx, replenish_count)
        PoolB-->>NodeB: Vec of DerivedPublicNonce
    else No nonces needed
        PoolB-->>NodeB: None
    end

    Note right of NodeB: Build reply PingPayload with<br/>nonces + local policy profile

    NodeB->>Transport: send_response(handle, OutgoingMessage)

    Note over Transport,NodeA: --- Relay Network ---

    Transport-->>NodeA: IncomingMessage (ping response)

    alt Response carries nonces
        NodeA->>PoolA: lock()
        PoolA->>PoolA: store_incoming(peer_idx, nonces)
    end
    Note right of NodeA: Store remote scoped policy if present

    NodeA-->>NodeA: return parsed PingPayload
```

---

## 5. Daemon RPC Flow

Traces a request from a CLI or TUI client through the `bifrostd` daemon to the underlying `BifrostNode` and transport layer. The daemon listens on a Unix socket, reads newline-delimited JSON frames (bounded at 64 KiB), performs auth and version checks, dispatches to the node, and writes the response back.

```mermaid
sequenceDiagram
    participant Client as L9: CLI / TUI
    participant Socket as Unix Socket
    participant Daemon as L8: bifrostd
    participant Auth as L8: Auth Check
    participant Node as L6: BifrostNode
    participant Transport as L5: WebSocketTransport
    participant Relay as Nostr Relay

    Client->>Socket: connect()
    Socket->>Daemon: accept()

    Client->>Socket: write JSON line (RpcRequestEnvelope)
    Socket->>Daemon: read_rpc_line (max 64 KiB)
    Daemon->>Daemon: parse RpcRequestEnvelope

    Daemon->>Daemon: is_rpc_version_supported(rpc_version)?
    Daemon->>Auth: is_request_authorized(auth_config, req)?

    alt Unauthorized
        Auth-->>Daemon: false
        Daemon->>Socket: RpcResponseEnvelope { code: 401 }
        Socket->>Client: JSON error response
    else Authorized
        Auth-->>Daemon: true

        alt Simple query (Health / Status / Events)
            Daemon->>Node: is_ready(), peers_snapshot(), nonce_pool_config()
            Node-->>Daemon: state data
        else Protocol operation (Sign / Ecdh / Ping / Echo)
            Daemon->>Node: sign(msg) / ecdh(pk) / ping(peer) / echo(peer, msg)
            Node->>Transport: cast() / request()
            Transport->>Relay: Nostr signed event (NIP-44 encrypted)
            Relay-->>Transport: peer response events
            Transport-->>Node: IncomingMessage(s)
            Node-->>Daemon: result
        else Policy management (Get/Set/Refresh)
            Daemon->>Node: peer_policy() / set_peer_policy() / ping()
            Node-->>Daemon: policy data
        else Shutdown
            Daemon->>Daemon: stop.store(true)
        end

        Daemon->>Socket: RpcResponseEnvelope { Ok(data) }
        Socket->>Client: JSON success response
    end

    Note over Daemon: Background tasks running concurrently:
    Note over Daemon: 1. Event collector: node.subscribe_events() -> VecDeque buffer (max 1024)
    Note over Daemon: 2. Inbound processor: loop { node.process_next_incoming() }
```

---

## 6. Shared State Map

All shared mutable state within `BifrostNode` (L6). Each entry below identifies the guarded data, the synchronization primitive, and which operations read or write it. The `BifrostNode` struct also contains two atomic values (`AtomicBool` for readiness and `AtomicU64` for request sequencing) that do not require locking.

```mermaid
graph LR
    subgraph BifrostNode["BifrostNode Shared State"]

        subgraph Policies["Arc&lt;Mutex&lt;HashMap&lt;String, PeerPolicy&gt;&gt;&gt;"]
            P["policies"]
        end

        subgraph RemotePolicies["Arc&lt;Mutex&lt;HashMap&lt;String, PeerScopedPolicyProfile&gt;&gt;&gt;"]
            RP["remote_scoped_policies"]
        end

        subgraph NoncePoolState["Arc&lt;Mutex&lt;NoncePool&gt;&gt;"]
            NP["pool"]
        end

        subgraph ReplayCache["Arc&lt;Mutex&lt;HashMap&lt;String, u64&gt;&gt;&gt;"]
            RC["replay_cache"]
        end

        subgraph EcdhCacheState["Arc&lt;Mutex&lt;EcdhCache&gt;&gt;"]
            EC["ecdh_cache"]
        end

        subgraph Atomics["Atomic Values (lock-free)"]
            RDY["ready: AtomicBool"]
            SEQ["request_seq: AtomicU64"]
        end
    end
```

### Detailed Access Table

| State | Guard | Readers | Writers |
|-------|-------|---------|---------|
| `policies` | `Arc<Mutex<HashMap<String, PeerPolicy>>>` | `peer_policy()`, `peer_policies()`, `peers_snapshot()`, `select_signing_peers()`, `enforce_outbound_request_policy()`, `is_respond_allowed()`, `local_policy_profile_for()` | `set_peer_policy()` |
| `remote_scoped_policies` | `Arc<Mutex<HashMap<String, PeerScopedPolicyProfile>>>` | `select_signing_peers()`, `has_remote_profile_for()` | `store_remote_scoped_policy()` (called from `ping()` outbound handler and `handle_incoming()` ping responder) |
| `pool` (NoncePool) | `Arc<Mutex<NoncePool>>` | `peer_nonce_health()`, `select_signing_peers()` (via `can_sign`) | `ping()` (generate_for_peer, store_incoming), `onboard()` (store_incoming), `sign_batch()` (consume_incoming, generate_for_peer, take_outgoing_signing_nonces_many), `handle_incoming()` Ping/Sign/Onboard handlers |
| `replay_cache` | `Arc<Mutex<HashMap<String, u64>>>` | `check_and_track_request()` (read + write combined) | `check_and_track_request()` (insert, retain, evict) |
| `ecdh_cache` | `Arc<Mutex<EcdhCache>>` | `get_cached_ecdh()` | `store_cached_ecdh()`, `get_cached_ecdh()` (evicts expired entries) |
| `ready` | `AtomicBool` | `is_ready()`, `ensure_ready()` | `connect()` (set true), `close()` (set false) |
| `request_seq` | `AtomicU64` | `request_id()` (fetch_add is read+write) | `request_id()` |
| `events_tx` | `broadcast::Sender<NodeEvent>` (lock-free) | -- | `emit_event()` (called throughout all operations) |

### NoncePool Internal Operations

The `NoncePool` is the most contention-sensitive shared state. Sign operations acquire the lock up to three times in a single `sign_batch()` call:

1. **First lock** -- consume incoming nonces for each peer and generate local nonce commitments
2. **Second lock** -- `take_outgoing_signing_nonces_many()` to retrieve private signing nonces by code
3. (Inbound sign handler) **Third lock** -- optionally generate replenishment nonces for the requesting peer

All NoncePool mutations enforce the single-use nonce invariant. The `take_outgoing_signing_nonces_many` method marks nonce codes as spent and will reject any attempt to reuse a code.
