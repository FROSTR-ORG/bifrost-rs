# bifrost-node

High-level node orchestration for Bifrost Rust.

## Includes
- Lifecycle and operational APIs (`echo`, `ping`, `onboard`, `sign`, `ecdh`).
- Batch APIs (`sign_batch`, `sign_queue`, `ecdh_batch`).
- Security controls: sender binding, replay/stale request protections, payload limits.
- ECDH TTL/LRU cache.
- Event stream API (`subscribe_events`).

## Status
- Core node parity and security controls implemented for current migration milestones.

## Verify
- `cargo test -p bifrost-node --offline`
