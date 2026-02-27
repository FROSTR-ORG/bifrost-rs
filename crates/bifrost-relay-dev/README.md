# bifrost-relay-dev

Rust port of the TypeScript development Nostr relay used in `bifrost-ts/demo`.

Implemented behaviors:
- `REQ` / `EVENT` / `CLOSE` handling.
- Event cache replay + `EOSE`.
- Filter matching (`ids`, `authors`, `kinds`, `since`, `until`, `limit`, tag filters).
- BIP-340 event ID/signature verification.

Run:

```bash
cargo run -p bifrost-relay-dev -- 8194
```
