# Refactor Plan: Separate Signing Device from Nostr Subscription Service

## Summary

Split the system into two isolated runtimes:
- a **Signing Device** (crypto, state, protocol, NIP-44 encryption, request-response correlation),
- and a **Nostr Client** (dumb relay transport: WebSocket connections, subscription management, raw event forwarding).

The Nostr Client has no knowledge of FROST, envelopes, or encryption. It forwards raw Nostr events to signing devices based on a `sub_id → device` index. Signing devices own all protocol intelligence: they encrypt, decrypt, build Nostr events, track pending requests, gather threshold responses, and manage nonces.

The new shape supports multiple signing devices in one process sharing a single Nostr connection pool, with strictly isolated cryptographic state per device.

## Assumptions and defaults

1. This is a hard-cut refactor. No backward compatibility with `bifrost-ts` wire format is required. Both implementations will be upgraded to the new spec.
2. A single process may host many devices, but each device has strictly separated signing state (nonces, replay cache, policy, ECDH cache, pending request map).
3. We start with one Nostr Client instance per process. Multiple relays are managed internally as a pool within that instance.
4. Hot-load (add/remove devices at runtime) is deferred. Initial implementation supports static device configuration at startup.
5. Backpressure policy: when a device outbound queue fills, drop oldest events and warn via the event emitter.

## Current-state problems to address

1. `BifrostNode` mixes signing orchestration with transport concerns, creating coupling that prevents multi-device scaling.
2. The `Transport` trait exposes request/response/cast semantics that leak protocol details (thresholds, gather logic) into the transport layer.
3. NIP-44 encryption and Nostr event construction live in `bifrost-transport-ws`, but these are key operations that belong to the signing device.
4. Request-response correlation (the `pending` map of `request_id|peer → oneshot`) lives in the transport, but only the device understands what constitutes a valid response.
5. Relay subscriptions are static and node-level. There is no mechanism for per-device subscription filters.

## New component boundaries

### 1. Nostr Client (`bifrost-transport` trait + `bifrost-transport-ws` impl)

A dumb relay forwarder. Knows nothing about FROST, envelopes, or encryption.

**Owns:**
- WebSocket connections to relays (pool, failover, reconnect with backoff)
- Subscription lifecycle (REQ/CLOSE)
- Raw event publishing
- Relay health tracking
- `sub_id → device_id` routing index (populated when devices register subscriptions)

**Does not own:**
- NIP-44 encryption/decryption
- Nostr event construction or signing
- Request-response correlation
- Any protocol state

### 2. Signing Device (`bifrost-node`)

Owns all protocol intelligence and cryptographic state for one FROST identity.

**Owns:**
- `GroupPackage`, `SharePackage` (FROST identity)
- `NoncePool` (incoming/outgoing nonce tracking, single-use enforcement)
- Replay cache (request ID dedup + stale rejection)
- ECDH cache (TTL/LRU)
- Per-peer policies (local + remote scoped)
- NIP-44 encryption/decryption (using device secret key)
- Nostr event construction and BIP-340 signing
- Request-response correlation (pending request map, threshold gather tracking)
- Event emitter (NodeEvent broadcast channel)
- Protocol operations: echo, ping, onboard, sign, sign_batch, sign_queue, ecdh, ecdh_batch
- Inbound request handling (validate, process, respond)

**Communicates with Nostr Client via:**
- `subscribe(sub_id, filters)` / `unsubscribe(sub_id)` — register/remove relay subscriptions
- `publish(event: NostrEvent)` — send a pre-encrypted, pre-signed Nostr event
- Inbound channel: receives raw `(sub_id, NostrEvent)` pairs from the client

### 3. Device Router (`bifrostd` or shared orchestration)

Minimal glue between the Nostr Client and signing devices.

**Owns:**
- `sub_id → device_id` index (populated from device subscription registrations)
- Per-device inbound channel (bounded, drop-oldest-on-full + warn)
- Forwarding loop: pull `next_event()` from Nostr Client, look up device by sub_id, push to device channel

### 4. Orchestrator (`bifrostd`)

Lifecycle and wiring only.

**Owns:**
- Creates one Nostr Client instance
- Creates signing devices from config (one per group/share pair)
- Creates the device router and wires inbound/outbound channels
- Exposes local Unix socket RPC, dispatching to the appropriate device
- Startup/shutdown sequencing

## Trait definitions

### NostrClient trait (replaces current `Transport` trait)

```rust
/// A dumb Nostr relay client. No protocol knowledge.
pub trait NostrClient: Send + Sync {
    /// Connect to relay pool.
    async fn connect(&self) -> Result<()>;

    /// Disconnect from all relays.
    async fn close(&self) -> Result<()>;

    /// Register a subscription. The client tracks sub_id → device_id internally.
    async fn subscribe(
        &self,
        device_id: &str,
        sub_id: &str,
        filters: Vec<NostrFilter>,
    ) -> Result<()>;

    /// Remove a subscription.
    async fn unsubscribe(&self, sub_id: &str) -> Result<()>;

    /// Publish a pre-built, pre-encrypted, pre-signed Nostr event.
    async fn publish(&self, event: NostrEvent) -> Result<()>;

    /// Receive the next inbound event. Returns (sub_id, event).
    async fn next_event(&self) -> Result<(String, NostrEvent)>;
}
```

### SigningDevice interface (in `bifrost-node`)

```rust
pub struct SigningDevice<C: Clock> {
    // Identity
    group: GroupPackage,
    share: SharePackage,
    device_id: DeviceId,

    // Crypto state (all per-device, no sharing)
    pool: NoncePool,
    replay_cache: HashMap<String, u64>,
    ecdh_cache: EcdhCache,
    policies: HashMap<String, PeerPolicy>,
    remote_scoped_policies: HashMap<String, PeerScopedPolicyProfile>,

    // NIP-44 conversation keys (cached per peer)
    conversation_keys: HashMap<String, ConversationKey>,

    // Request-response correlation
    pending: HashMap<String, PendingRequest>,

    // Communication channels
    inbound_rx: mpsc::Receiver<RawInboundEvent>,
    outbound_tx: NostrClientHandle,  // handle to publish + subscribe/unsubscribe

    // Observability
    events_tx: broadcast::Sender<NodeEvent>,
    clock: Arc<C>,
    config: DeviceConfig,
    ready: AtomicBool,
    request_seq: AtomicU64,
}
```

The device exposes the same public API as the current `BifrostNode` (sign, ecdh, ping, echo, onboard, etc.) but internally:
- Builds RPC envelopes, encrypts with NIP-44, constructs + signs Nostr events
- Publishes via `outbound_tx.publish(event)`
- Receives raw events via `inbound_rx`, decrypts, matches against pending requests or dispatches as inbound requests
- Tracks its own threshold gather state per operation (how many responses collected vs. required)

## Refactor steps

### Phase 0: Define new traits and types (no behavior change)

**0a — Define `NostrClient` trait and supporting types in `bifrost-transport`**
- `NostrClient` trait (connect, close, subscribe, unsubscribe, publish, next_event)
- `NostrFilter` (Nostr REQ filter structure)
- `NostrEvent` (raw Nostr event: id, pubkey, created_at, kind, tags, content, sig)
- `RawInboundEvent { sub_id: String, event: NostrEvent }`
- `DeviceId` (newtype over String, derived from group_id + share_idx)
- Keep the existing `Transport` trait in place. Both traits coexist temporarily.

**0b — Extract NIP-44 and Nostr event utilities into a shared module**
- Move NIP-44 encrypt/decrypt from `bifrost-transport-ws` into a shared location (either a new module in `bifrost-core` or a standalone `bifrost-nostr` utility module in the workspace).
- Move Nostr event construction (canonical event ID, BIP-340 signing) alongside it.
- `bifrost-transport-ws` continues to call these functions from the new location (no behavior change yet).

**0c — Build `NostrClient` adapter around existing `WebSocketTransport`**
- Implement `NostrClient` for `WebSocketTransport` (or a new wrapper struct).
- `subscribe` sends `["REQ", sub_id, filter_json]` to the active relay.
- `unsubscribe` sends `["CLOSE", sub_id]`.
- `publish` sends `["EVENT", event_json]` (raw, no encryption — event is pre-built).
- `next_event` returns raw `(sub_id, NostrEvent)` — no decryption, no envelope parsing.
- The old `Transport` impl continues to work alongside the new `NostrClient` impl.

**0d — Verify all existing tests pass with no behavior change**

### Phase 1: Build SigningDevice and split BifrostNode

**1a — Build `SigningDevice` struct in `bifrost-node`**
- Move all per-device state from `BifrostNode` into `SigningDevice`: group, share, pool, replay_cache, ecdh_cache, policies, remote_scoped_policies, events_tx, ready, request_seq.
- Move NIP-44 encrypt/decrypt ownership into the device (conversation key cache per peer).
- Implement request-response correlation inside the device: a `pending` map of `request_id|peer → oneshot`, with timeout tracking.
- Implement internal threshold gather: for `cast`-equivalent operations, the device publishes N events (one per peer), then collects responses from `inbound_rx` matching the request IDs, resolving when threshold is met or timeout expires.

**1b — Implement the device event loop**
- The device runs a background task that:
  1. Pulls raw events from `inbound_rx`
  2. Decrypts NIP-44 using the device's secret key
  3. Decodes the RPC envelope
  4. Checks if the event matches a pending request (correlate by `request_id|sender`) — if so, delivers via oneshot
  5. Otherwise, treats it as an inbound request: validates (replay, staleness, sender binding, policy), processes, builds response, encrypts, publishes

**1c — Wire single-device startup path**
- `bifrostd` creates one `NostrClient` + one `SigningDevice` + a forwarding loop (router).
- The router loop: `client.next_event() → look up device by sub_id → push to device.inbound_rx`.
- The device registers its subscription on connect: `client.subscribe(device_id, sub_id, filters)`.
- All existing daemon RPC methods dispatch to the single device.
- All existing tests pass against the new wiring.

**1d — Remove old `Transport` usage from `BifrostNode` / deprecate**
- Once `SigningDevice` is proven, remove the old `BifrostNode` or reduce it to a thin compatibility wrapper.
- Remove `Transport::request`, `Transport::cast`, `Transport::send_response`, `Transport::next_incoming` — these are no longer needed.
- The `Transport` trait is replaced by `NostrClient`.

### Phase 2: Multi-device support (static)

**2a — Device registry in `bifrostd`**
- Orchestrator creates N devices from config (one per group/share pair).
- Each device registers its own subscription filters with the shared `NostrClient`.
- The router maintains a `sub_id → device_id` index across all devices.

**2b — Router dispatch**
- The router loop pulls events from `NostrClient::next_event()`.
- Looks up `sub_id` in the index → finds device → pushes to that device's inbound channel.
- If `sub_id` is unknown, logs a warning and drops the event.

**2c — Daemon RPC dispatch**
- RPC requests include a device selector (or default to the single device for backward compat).
- Orchestrator dispatches RPC calls to the correct device instance.

### Phase 3: Production hardening

- Metrics: per-device event counts, publish latency, queue depths, nonce pool health.
- Backpressure tuning: configurable queue bounds per device, drop-oldest + warn policy.
- Relay pool improvements: connection-level health propagated to device status events.
- Hot-load path: add/remove devices at runtime with safe subscription teardown (deferred from Phase 2).

### Phase 4: Cleanup

- Remove the old `Transport` trait entirely.
- Remove any remaining compatibility shims.
- Clean up `bifrost-transport-ws` to only implement `NostrClient` (no encryption, no envelope parsing, no pending map).

## Routing strategy

Routing is based on **subscription ID**, not trial decryption.

1. Each signing device registers subscriptions with the Nostr Client, providing a `sub_id` that is deterministic and unique per device (e.g., derived from `device_id`).
2. The Nostr Client (and/or router) maintains a `sub_id → device_id` index, populated at subscription registration time.
3. When a relay delivers an event on a subscription, the router looks up the owning device by `sub_id` and forwards the raw event.
4. The device decrypts and validates the event internally. Invalid events (wrong key, malformed, unknown sender) are dropped at the device level with an error event emitted.
5. No trial decryption. No overlapping filter ambiguity. One sub_id, one device.

## Backpressure policy

Per-device inbound channels are bounded (configurable, default 256).

When a device's inbound channel is full:
1. Drop the oldest event in the channel.
2. Emit a `NodeEvent::Error` warning with the dropped event metadata.
3. Push the new event.

This prevents a slow device from blocking the router or other devices. Signing operations are time-sensitive — a stale event is worse than a dropped one, since replay/TTL checks would reject it anyway.

Outbound publishing is non-blocking. If the Nostr Client cannot publish (relay down), the publish call returns an error. The device emits an error event and continues. No outbound queue — publish failures are surfaced immediately.

## Security and state-isolation requirements

1. **No shared mutable signing state.** Each device owns its own nonce pool, replay cache, ECDH cache, policies, and pending request map. No `Arc<Mutex<_>>` shared across devices.
2. **NIP-44 keys are device-scoped.** Conversation keys are derived from each device's secret key. A device can only decrypt events addressed to it.
3. **Transport is plaintext-blind.** The Nostr Client never sees decrypted content. It handles raw encrypted Nostr events only. Connection metadata and raw event frames are the only state it holds.
4. **Transport failures cannot corrupt device state.** A relay disconnect does not mutate nonce pools, replay caches, or pending operations. The device handles timeouts on its pending requests independently.
5. **Bounded channels prevent cross-device interference.** A slow or stuck device cannot block event delivery to other devices.

## State ownership audit

| State | Owner | Notes |
|---|---|---|
| WebSocket connections | Nostr Client | Pool, failover, reconnect |
| Relay health counters | Nostr Client | Per-relay success/failure |
| Subscription registry | Nostr Client + Router | `sub_id → device_id` index |
| NIP-44 conversation keys | Signing Device | Per-peer, derived from device secret key |
| Nostr event construction | Signing Device | BIP-340 signing with device key |
| Pending request map | Signing Device | `request_id\|peer → oneshot` |
| NoncePool | Signing Device | Incoming/outgoing nonce tracking |
| Replay cache | Signing Device | Request ID dedup + TTL |
| ECDH cache | Signing Device | TTL/LRU per target pubkey |
| Peer policies | Signing Device | Local + remote scoped |
| Group/Share packages | Signing Device | Immutable identity |
| Event emitter | Signing Device | `broadcast::Sender<NodeEvent>` |

## Test plan

### Unit tests
1. **Device state isolation**: two devices in the same process cannot observe each other's nonces, replay cache, or policies.
2. **Device request-response correlation**: device correctly matches inbound events to pending requests by `request_id|sender`.
3. **Device threshold gather**: device collects threshold responses and resolves, times out correctly, handles partial responses.
4. **Router dispatch**: events routed to correct device by `sub_id`. Unknown `sub_id` events are dropped with warning.
5. **Backpressure**: when device inbound channel is full, oldest event is dropped, new event is delivered, warning is emitted.
6. **NIP-44 ownership**: device encrypts/decrypts correctly. Nostr Client never calls encrypt/decrypt.

### Integration tests
1. **Single device, full sign flow**: device publishes sign request events, receives partial sig responses, aggregates signature. Equivalent to current `happy_paths` tests but through the new wiring.
2. **Single device, full ECDH flow**: same pattern for ECDH.
3. **Single device, ping/nonce exchange**: device-level ping with nonce replenishment.
4. **Two devices, disjoint subscriptions**: two devices on the same Nostr Client, each receiving only their own events.
5. **Transport reconnection**: relay disconnect and reconnect preserves device subscription state (re-subscribe on reconnect).

### E2E tests
1. **Full daemon flow**: `bifrostd` with new wiring, CLI commands produce correct results.
2. **Relay unavailable**: publish failures surface as device error events, device continues operating when relay returns.

### Regression
1. All existing `bifrost-node` unit and integration tests pass against the `SigningDevice` (may require test harness updates to provide a mock `NostrClient` instead of mock `Transport`).
2. All existing devnet smoke tests pass with the new `bifrostd` wiring.
