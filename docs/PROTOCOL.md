# Wire Protocol Overview

`bifrost-rs` has two protocol layers:

1. peer protocol (`bifrost-codec::rpc::RpcEnvelope`) over transport
2. local daemon RPC (`bifrost-rpc`) over Unix sockets

## 1) Peer Envelope (`bifrost-codec`)

Envelope shape:

```json
{
  "version": 1,
  "id": "1700000000-2",
  "sender": "<peer_pubkey_hex>",
  "payload": { "method": "...", "data": { } }
}
```

Payload methods:

- `Ping`
- `Echo`
- `Sign`
- `SignResponse`
- `Ecdh`
- `OnboardRequest`
- `OnboardResponse`

Current validation boundaries:

- envelope id non-empty, max length 256
- sender non-empty, max length 256
- echo max length 8192

Wire payload bounds (selected, from `wire.rs`):

- `MAX_GROUP_MEMBERS = 1000`
- `MAX_SIGN_BATCH_SIZE = 100`
- `MAX_ECDH_BATCH_SIZE = 100`
- `MAX_NONCE_PACKAGE = 1000`

Examples of enforced rejects:

- empty members/hashes
- oversized nonce/sign/ecdh arrays
- malformed fixed-width hex payloads

## 2) Daemon RPC (`bifrost-rpc`)

Transport: newline-delimited JSON on Unix socket.

Request envelope:

```json
{ "id": 123, "request": { "method": "Status" } }
```

Response envelope:

```json
{ "id": 123, "response": { "result": "Ok", "data": { } } }
```

Methods:

- `Health`
- `Status`
- `Events { limit }`
- `Echo { peer, message }`
- `Ping { peer }`
- `Onboard { peer }`
- `Sign { message32_hex }`
- `Ecdh { pubkey33_hex }`
- `Shutdown`

## Request Flow

1. Client sends RPC request to daemon.
2. Daemon invokes node operation.
3. Node uses transport request/cast over relay(s).
4. Peer envelope parsed and validated.
5. Response returns as RPC `Ok(data)` or `Err(code,message)`.

## Compatibility Notes

- Runtime daemon boundary is an intentional architecture split from TS in-process demo flow.
- Core operation semantics (`ping`, `echo`, `ecdh`, `sign`, `onboard`) are preserved.

See also:

- `dev/artifacts/runtime-stack.md`
- `docs/API.md`
- `dev/planner/05-interfaces.md`
