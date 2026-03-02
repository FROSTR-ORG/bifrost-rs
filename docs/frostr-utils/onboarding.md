# Onboarding Package

Onboarding utilities produce a portable package containing:

- recipient share (`idx`, `seckey`)
- peer public key for first contact (`peer_pk`, 32-byte BIP340 hex)
- relay list for bootstrap connectivity

## API

- `build_onboarding_package(share, peer_pk, relays)`
- `encode_onboarding_package(&pkg)` (bech32m)
- `decode_onboarding_package(&str)`
- `serialize_onboarding_data(&pkg)`
- `deserialize_onboarding_data(&[u8])`

## Design Intent

Onboarding is intentionally minimal. A new device uses this package to phone home to `peer_pk`
over `relays`, then receives the full group package and initial nonces through the `onboard` RPC.
