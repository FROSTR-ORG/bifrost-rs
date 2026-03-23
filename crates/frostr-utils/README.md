# frostr-utils

`frostr-utils` is the shared utility crate for FROSTR integration workflows.

## Scope

- Keyset lifecycle:
  - create keysets
  - verify keysets
  - rotate existing keysets from threshold shares while preserving the group public key
  - recover group signing key from threshold shares
- Group/share verification helpers
- Onboarding package helpers:
  - encode/decode encrypted `bfshare`
  - encode/decode encrypted `bfonboard`
  - encode/decode encrypted `bfprofile`
  - build and parse encrypted profile backup events
- Stateless protocol helpers:
  - sign session validation
  - partial signature creation/verification/finalization
  - ECDH package creation/finalization

## Onboarding Package

Prefix:
- `bfonboard`

Encrypted payload contents:
- `share_secret` (32-byte share secret hex)
- `peer_pk` (callback 32-byte BIP340 pubkey)
- `relays` (relay URLs)

## Notes

- `bfonboard` is a compact URI-like encrypted package, not a JSON invite envelope.
- `bfonboard` exports are password-protected by default and require at least 8 characters.
- New device uses the decrypted package to contact `peer_pk` over `relays` and complete the existing `onboard` RPC flow.
- `bifrost-core` remains runtime-focused; `frostr-utils` is for tooling/integration.
- `bifrost` signer/runtime crates consume `frostr-utils::protocol` stateless sign/ECDH helpers as a runtime foundation.
- APIs are intended for external integration and internal utility reuse.
