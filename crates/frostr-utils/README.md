# frostr-utils

`frostr-utils` is the shared utility crate for FROSTR integration workflows.

## Scope

- Keyset lifecycle:
  - create keysets
  - verify keysets
  - rotate keysets (dealer reissue)
  - recover group signing key from threshold shares
- Group/share verification helpers
- Onboarding package helpers:
  - build share-free invite tokens
  - assemble encrypted onboarding packages from `invite token + share`
  - invite token JSON encode/decode
  - encrypted bech32 onboarding encode/decode
- Stateless protocol helpers:
  - sign session validation
  - partial signature creation/verification/finalization
  - ECDH package creation/finalization

## Onboarding Package

Prefix:
- `bfonboard`

Encrypted payload contents:
- `share` (`idx`, `seckey`)
- `peer_pk` (callback 32-byte BIP340 pubkey)
- `relays` (relay URLs)
- `challenge` (32-byte one-time invite challenge)
- `created_at` / `expires_at`

Invite token format:
- JSON string

## Notes

- Invite creation is split into two phases: inviter creates a share-free token, then provisioning combines that token with the recipient share and a password.
- `bfonboard` exports are password-protected by default and require at least 8 characters.
- New device uses the decrypted package to contact `peer_pk` over `relays` and complete the existing `onboard` RPC flow.
- `bifrost-core` remains runtime-focused; `frostr-utils` is for tooling/integration.
- `bifrost` signer/runtime crates consume `frostr-utils::protocol` stateless sign/ECDH helpers as a runtime foundation.
- APIs are intended for external integration and internal utility reuse.
