# bifrost-codec

Wire and RPC codec layer for Bifrost Rust.

## Includes
- RPC envelope encode/decode.
- Strict payload shape/size validation.
- TS-parity parse helpers (`parse_session`, `parse_ecdh`, `parse_psig`, `parse_onboard_*`, `parse_ping`, package parsers).

## Status
- Parity state: implemented for current encoder/schema equivalents used by node + transport.

## Verify
- `cargo test -p bifrost-codec --offline`
