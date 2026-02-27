# frost_bip340_example

Starter scaffold for building threshold Schnorr signing using:

- `frost-secp256k1-tr` (FROST over secp256k1 Taproot/BIP-340 style signatures)

## Run

```bash
cd /home/cscott/Repos/frostr/bifrost-rs/example/frost_bip340_example
cargo run
```

## What is included

- `src/main.rs`: app entrypoint and flow wiring
- `src/frost_flow.rs`: signing flow skeleton with TODOs for FROST rounds

## Next implementation steps

1. Add DKG or key-package loading for each signer.
2. Implement Round 1 nonce generation and commitment collection.
3. Build a signing package in the coordinator.
4. Implement Round 2 signature share creation.
5. Aggregate signature shares into one BIP-340-compatible group signature.
6. Verify the aggregate signature against the group public key.
