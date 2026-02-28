# bifrost-devtools

Consolidated local development tooling for `bifrost-rs`.

Commands:
- `bifrost-devtools keygen`: generate group/share/daemon configs.
- `bifrost-devtools relay`: run local Nostr relay for dev/test.

Examples:

```bash
cargo run -p bifrost-devtools -- keygen \
  --out-dir dev/data \
  --threshold 2 \
  --count 3 \
  --relay ws://127.0.0.1:8194 \
  --socket-dir /tmp

cargo run -p bifrost-devtools -- relay --port 8194
```
