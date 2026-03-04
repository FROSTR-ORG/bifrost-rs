# Security Model

Threat model and control map for `bifrost-rs`.

## System Boundary

- Encrypted peer protocol over relay transport (`bifrost-bridge` + adapter).
- Stateful cryptographic engine (`bifrost-signer`).
- Core cryptographic/session primitives (`bifrost-core`).

## Adversary Assumptions

- Relay can observe metadata and availability but not trusted plaintext.
- Peer may be malicious, malformed, replaying, or out-of-policy.
- Local process boundary is untrusted; config/state files require filesystem controls.

## Security Goals

1. Prevent unauthorized sign/ECDH actions.
2. Preserve nonce and session integrity.
3. Reject malformed payloads at strict boundaries.
4. Detect replay/stale request ids.
5. Limit resource exhaustion from untrusted input.

## Control Matrix

| Threat | Control | Location |
|---|---|---|
| malformed payloads | strict wire parsing + bounds checks | `bifrost-codec` |
| sender spoofing | sender/member binding checks | `bifrost-signer` |
| replay/stale requests | replay cache + TTL checks | `bifrost-signer` |
| nonce misuse | claim/consume guardrails | `bifrost-core`, `bifrost-signer` |
| quorum misuse | explicit threshold checks | `bifrost-signer` |
| relay metadata leakage | opaque encrypted `content` payloads | `bifrost-signer` |

## Runtime Security Notes

- Keep config/state paths permission-restricted.
- Keep relay list controlled.
- Keep event kind aligned across peers.
- Treat development key material as disposable.

## Related Docs

- `SECURITY.md`
- `docs/CRYPTOGRAPHY.md`
- `docs/PROTOCOL.md`
