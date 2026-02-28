# Security Model

Threat model and control map for `bifrost-rs`.

## System Boundary

- Peer-to-peer protocol over relay transport (`bifrost-node` + transport crates)
- Local daemon control plane over Unix socket (`bifrostd` + `bifrost-rpc`)
- Cryptographic core operations (`bifrost-core`)

## Adversary Assumptions

- Relay can observe metadata and availability but should not be trusted with sensitive plaintext.
- A peer may be malicious, malformed, replaying, or out-of-policy.
- Local machine users/processes may attempt unauthorized daemon RPC access.

## Security Goals

1. Prevent unauthorized signing/ECDH actions.
2. Preserve nonce and session integrity.
3. Reject malformed/bounds-violating payloads at boundaries.
4. Avoid replay/stale-envelope processing.
5. Limit resource exhaustion vectors from untrusted payloads.

## Control Matrix

| Threat | Control | Location |
|---|---|---|
| malformed payloads | strict wire parsing + bounded arrays/fields | `bifrost-codec` |
| oversized message abuse | envelope + node payload limits | `bifrost-codec`, `bifrost-node` |
| sender spoofing / peer mismatch | sender/member binding checks | `bifrost-node` |
| replay/stale request IDs | replay cache + TTL checks | `bifrost-node` |
| nonce misuse | nonce claim/consume guardrails | `bifrost-core`, `bifrost-node` |
| quorum underflow misuse | explicit threshold and insufficient-peer errors | `bifrost-node`, transport |
| daemon RPC misuse | token-based authn/authz policy + local Unix socket boundary | `bifrostd` |
| daemon RPC frame exhaustion | bounded RPC line framing | `bifrostd` |

## Runtime Security Notes

- `bifrostd` enforces token auth when `auth.token` is configured.
- If `auth.token` is omitted, startup fails unless `auth.insecure_no_auth=true` is explicitly set (dev-only mode).
- RPC request lines are bounded (`64 KiB`) to reduce local resource-exhaustion exposure.
- `Shutdown` RPC remains privileged; operators should restrict socket path and process ownership.

## Deployment Guidance

- Use restrictive socket file permissions (`600` where practical).
- Run daemon under dedicated service user.
- Keep relay list controlled in production-like environments.
- Treat devnet-generated key material as ephemeral, never production.

## Residual Risks / Open Work

- dev environments that choose `auth.insecure_no_auth=true` accept a local control-plane trust risk
- formal protocol version negotiation policy
- deeper adversarial transport tests (fault injection, prolonged reconnect stress)

## Related Docs

- `SECURITY.md`
- `docs/CRYPTOGRAPHY.md`
- `dev/planner/07-risks-and-decisions.md`
