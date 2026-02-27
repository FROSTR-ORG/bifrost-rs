# bifrost-core

Core cryptographic primitives for the Rust Bifrost migration.

## Includes
- Deterministic group/session package helpers.
- FROST partial signature creation/verification/aggregation.
- Batch-safe core signing helpers (`create_partial_sig_packages_batch`, `combine_signatures_batch`).
- Nonce pool with one-time claim semantics.
- ECDH package creation and combination.

## Status
- Parity state: implemented for core TS cryptographic paths.
- Safety model: nonce one-time-use and replay-resistant flow are enforced in current APIs.

## Verify
- `cargo test -p bifrost-core --offline`
