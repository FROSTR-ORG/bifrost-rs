# Cryptography Foundations

This document summarizes implemented cryptographic behavior and constraints in `bifrost-rs`.

## Primitive and Protocol Scope

- Threshold signatures: FROST over secp256k1 (Taproot/Schnorr context)
- Signature format target: BIP-340 compatible 64-byte Schnorr outputs
- Symmetric encryption and transport confidentiality are handled at higher protocol layers

## Key Data Types

- `GroupPackage`: threshold, group pubkey, member list
- `SharePackage`: member index + secret share (`Zeroize` on drop)
- `SignSessionPackage`: group/session IDs + signing payload context
- `PartialSigPackage`: signer share contribution package
- `EcdhPackage`: per-member keyshare package for collaborative ECDH derivation

## Signing Lifecycle (Current Baseline)

1. Build `SignSessionTemplate`.
2. Derive session package (`create_session_package`).
3. Verify session integrity (`verify_session_package`).
4. Consume nonce material and create partial signature.
5. Verify partial signatures from peers.
6. Aggregate into final Schnorr signatures.

## Nonce Safety Model

- Signing nonces are treated as single-use.
- Missing or already-claimed nonce state is rejected (`MissingNonces`, `NonceAlreadyClaimed`).
- Batch signing currently uses guarded helper flow (`create_partial_sig_packages_batch`, `combine_signatures_batch`) with explicit bounds and mismatch checks.

Design note:

- `dev/planner/09-batch-sign-nonce-model.md`

## ECDH Flow

- `create_ecdh_package`: computes per-target keyshares from local share.
- `combine_ecdh_packages`: combines threshold keyshares for shared secret material.
- Node adds TTL/LRU cache controls for repeated ECDH public keys.

## Security Invariants

- Session IDs must bind to session payload (`SessionIdMismatch` rejection path).
- Group/session/member consistency must hold for every signing flow.
- Sender binding is enforced by node boundary before crypto operations.

## Known Hardening Follow-Ups

- Continue Option-A single-session multi-hash orchestration work.
- Expand adversarial/fault injection coverage around transport-driven crypto workflows.

## References

- `docs/SECURITY-MODEL.md`
- `dev/planner/06-test-strategy.md`
