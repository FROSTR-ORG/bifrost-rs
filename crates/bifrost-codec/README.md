# bifrost-codec

Wire codec layer for Bifrost Rust.

## Includes
- Bridge envelope encode/decode.
- Strict payload shape/size validation.
- Group/share package parsers.

## Status
- Implemented for the active bridge and package schemas used by signer + bridge runtime.

## Verify
- `cargo test -p bifrost-codec --offline`
