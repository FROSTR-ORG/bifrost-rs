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
  - build package
  - bech32m encode/decode (minimal onboarding payload)
  - binary serialize/deserialize for QR/out-of-band transport
- Stateless protocol helpers:
  - sign session validation
  - partial signature creation/verification/finalization
  - ECDH package creation/finalization

## Onboarding Package

Prefix:
- `bfonboard`

Payload (TS parity model):
- `share` (`idx`, `seckey`)
- `peer_pk` (32-byte BIP340 pubkey)
- `relays` (relay URLs)

## Notes

- Onboarding package is intentionally minimal for bootstrap/phone-home flow.
- New device uses this package to contact a peer and fetch full `group + nonces` through `onboard` RPC.
- `bifrost-core` remains runtime-focused; `frostr-utils` is for tooling/integration.
- `bifrost-node` consumes `frostr-utils::protocol` stateless sign/ECDH helpers as a runtime foundation.
- APIs are intended for external integration and internal utility reuse.
