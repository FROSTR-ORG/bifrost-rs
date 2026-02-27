# Migration Guide: bifrost-ts -> bifrost-rs

This guide maps practical TypeScript usage patterns to current Rust equivalents.

## Crate Mapping

- TS `src/lib/*` cryptographic/session utilities -> `bifrost-core`
- TS encoder/schema/parse helpers -> `bifrost-codec`
- TS transport contracts -> `bifrost-transport`
- TS websocket client internals -> `bifrost-transport-ws`
- TS client orchestration APIs -> `bifrost-node`

## Core Usage Mapping

### Group + Share

TS:
- group/share package objects consumed by signer/client classes.

Rust:
- `bifrost_core::types::{GroupPackage, SharePackage}`
- pass into `BifrostNode::new(...)`.

### Signing

TS:
- signer/client sign paths, plus batching helpers.

Rust:
- single sign: `node.sign(message32).await`
- bounded batch: `node.sign_batch(&messages).await`
- queued/chunked batch: `node.sign_queue(&messages).await`

### ECDH

TS:
- ecdh helper and cache class.

Rust:
- single ECDH: `node.ecdh(pubkey33).await`
- batch: `node.ecdh_batch(&pubkeys).await`
- built-in cache via options:
  - `ecdh_cache_ttl_secs`
  - `ecdh_cache_max_entries`

## Node Setup Mapping

TS conceptual flow:
1. Build client with group/share + transport.
2. Connect.
3. Onboard/ping peers.
4. Run sign/ecdh operations.

Rust flow:
1. Construct transport (`Arc<impl Transport>`).
2. Construct node:
   - `BifrostNode::new(group, share, peer_pubkeys, transport, clock, options)`
3. `connect().await`
4. Optional peer prep:
   - `onboard(peer).await`
   - `ping(peer).await`
5. Run operations:
   - `echo`, `sign`, `ecdh`, queue/batch variants.

## Security/Policy Mapping

Rust currently enforces:
- sender/member binding checks
- replay and stale request-id protections
- payload size/shape limits
- nonce one-time claim semantics

Relevant options in `BifrostNodeOptions`:
- replay/staleness:
  - `request_ttl_secs`, `request_cache_limit`
- payload limits:
  - `max_request_id_len`, `max_sender_len`, `max_echo_len`, `max_sign_content_len`
- batching/caching:
  - `max_sign_batch`, `max_ecdh_batch`, `ecdh_cache_ttl_secs`, `ecdh_cache_max_entries`

## Events Mapping

TS emitter model -> Rust event stream:
- subscribe via `node.subscribe_events()`
- emitted variants:
  - `Ready`, `Closed`, `Message(String)`, `Bounced(String)`, `Info(String)`, `Error(String)`

## Transport WS Mapping

TS websocket behavior -> Rust `bifrost-transport-ws`:
- explicit connection state (`ConnectionState`)
- reconnect/backoff config (`WsTransportConfig`)
- relay health snapshots + active relay tracking
- cast threshold stabilization under partial response loss

## Known Differences

- Batch signing uses safe Option-B orchestration (session-per-hash style behavior), with core batch helpers available.
- Full forced network-fault integration coverage for websocket transport remains a follow-up hardening item.

## Verification Checklist

- `cargo test -p bifrost-core -p bifrost-codec -p bifrost-node --offline`
- `cargo test -p bifrost-transport-ws --offline`
- `cargo test -p bifrost-node --test happy_paths --offline`
- `cargo test -p bifrost-node --test adversarial --offline`

