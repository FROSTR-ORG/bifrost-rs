# bifrost-transport

Transport abstraction traits used by node and ws transport crates.

## Includes
- `Transport` trait (`connect`, `close`, `request`, `cast`, `send_response`, `next_incoming`).
- Shared transport types and errors.

## Status
- Stable trait boundary for current migration phase.

## Verify
- `cargo check -p bifrost-transport --offline`
