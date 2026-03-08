# Invite And Onboarding Package

Invite tooling now uses a two-step flow:

- inviter creates a share-free invite token JSON string
- provisioning combines `token + share + password` into an encrypted `bfonboard1...` package

The final onboarding package contains:

- recipient share (`idx`, `seckey`)
- peer public key for first contact (`peer_pk`, 32-byte BIP340 hex)
- relay list for bootstrap connectivity
- one-time invite challenge
- invite `created_at` / `expires_at`

## API

- `build_invite_token(callback_peer_pk, relays, challenge, created_at, expires_at, label)`
- `encode_invite_token(&token)`
- `decode_invite_token(&str)`
- `build_onboarding_package(share, peer_pk, relays)`
- `assemble_onboarding_package(&token, share)`
- `encode_onboarding_package(&pkg, password)` (encrypted `bfonboard1...`)
- `decode_onboarding_package(&str, Option<&str>)`

Operational contract:
- the package is always encrypted and callers must supply a password
- `decode_onboarding_package(..., None)` fails with `PassphraseRequired`
- recipient apps should treat the package as consume-only input, not persistent state

## Design Intent

Invite creation does not require share custody on the inviting node.

A new device uses the decrypted package to phone home to `peer_pk` over `relays`, presents the
embedded invite challenge during `onboard`, and then receives the full group package and initial
nonces through the existing onboarding RPC.
