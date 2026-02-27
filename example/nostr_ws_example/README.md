# nostr_ws_example

A minimal Rust Nostr websocket client reference.

What it does:
- Connects to a relay (`NOSTR_RELAY`, default `wss://relay.damus.io`)
- Sends a Nostr `REQ` subscription for recent kind-1 notes
- Prints incoming `EVENT`s
- Stops when `EOSE` is received

## Run

```bash
cd /home/cscott/Repos/frostr/bifrost-rs/example/nostr_ws_example
cargo run
```

Use a custom relay:

```bash
NOSTR_RELAY=wss://relay.nostr.band cargo run
```

## Notes

- This is intentionally low-level for protocol learning.
- For production apps, prefer `nostr-sdk` from `rust-nostr`.
