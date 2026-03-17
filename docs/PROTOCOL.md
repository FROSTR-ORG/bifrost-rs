# Wire Protocol Overview

`bifrost-rs` uses encrypted peer envelopes over Nostr relay events.

Cross-repo protocol context is documented in [../../../docs/PROTOCOL.md](../../../docs/PROTOCOL.md). This manual stays focused on the signer-to-signer wire layer implemented in `bifrost-rs`.

## Peer Envelope (`bifrost-codec`)

Envelope shape (`BridgeEnvelope`):

```json
{
  "request_id": "6d12e4af53c84965a91b1130b0a940cf",
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
- request id must be non-empty and bounded; it is opaque to the peer protocol
- payload-specific bounds and shape checks are enforced in wire conversions

## Relay Event Layer

- Events are subscribed by `authors`, `#p`, and `kind` (default `20000`).
- Event `content` carries an encrypted blob.
- No payload structure should be inferred from relay metadata.

### Recipient Routing (`p` tag)

- Every Bifrost protocol event MUST include exactly one lowercase `p` tag.
- The `p` value MUST be the recipient identity key (`pubkey32`, lowercase hex).
- Events with zero `p` tags or multiple `p` tags are invalid and must be dropped.
- Events whose single `p` does not match a local device recipient are ignored.

## Request Flow

1. Caller starts operation through bridge command.
2. Signer emits encrypted request event(s).
3. Peers decrypt, validate, process, and emit encrypted response event(s).
4. Initiator signer verifies responses against the locked peer set selected at round start.
5. Round succeeds only if all locked peers return valid responses before timeout.
6. On missing/invalid locked-peer response, round fails terminally and caller must start a new request.

## Notes

- This is a hard-cut runtime design.
- Core operation semantics (`ping`, `onboard`, `sign`, `ecdh`) are preserved.
- `bfonboard` is the import artifact for onboarding, but the over-the-wire runtime protocol here begins at signer commands and encrypted peer envelopes.
