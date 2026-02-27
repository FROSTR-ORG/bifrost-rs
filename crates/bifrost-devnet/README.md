# bifrost-devnet

Utilities for local runtime/devnet setup.

Current command:

```bash
cargo run -p bifrost-devnet -- keygen \
  --out-dir dev/data \
  --threshold 2 \
  --count 3 \
  --relay ws://127.0.0.1:8194 \
  --socket-dir /tmp
```

Generates:
- `group.json`
- `share-*.json`
- `daemon-*.json`
