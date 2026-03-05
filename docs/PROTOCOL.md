# Wire Protocol Overview

`bifrost-rs` uses encrypted peer envelopes over Nostr relay events.

## Peer Envelope (`bifrost-codec`)

Envelope shape (`BridgeEnvelope`):

```json
{
  "request_id": "1700000000-2-1",
  "sent_at": 1700000000,
  "payload": { "type": "...", "data": {} }
}
```

Payload variants:
- `PingRequest`, `PingResponse`
- `SignRequest`, `SignResponse`
- `EcdhRequest`, `EcdhResponse`
- `OnboardRequest`, `OnboardResponse`
- `Error`

Validation boundaries:
- request id must be non-empty and canonical (`<unix_ts>-<member_idx>-<seq>`)
- payload-specific bounds and shape checks are enforced in wire conversions

## Relay Event Layer

- Events are subscribed by `authors` and `kind` (default `20000`).
- Event `content` carries an encrypted blob.
- No payload structure should be inferred from relay metadata.

## Request Flow

1. Caller starts operation through bridge command.
2. Signer emits encrypted request event(s).
3. Peers decrypt, validate, process, and emit encrypted response event(s).
4. Initiator signer verifies responses against the locked peer set selected at round start.
5. Round succeeds only if all locked peers return valid responses before timeout.
6. On missing/invalid locked-peer response, round fails terminally and caller must start a new request.

## Compatibility Notes

- This is a hard-cut design replacing the legacy daemon/RPC runtime path.
- Core operation semantics (`ping`, `onboard`, `sign`, `ecdh`) are preserved.
