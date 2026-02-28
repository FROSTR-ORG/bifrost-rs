# bifrost-tui

Interactive `ratatui` + `crossterm` terminal dashboard over `bifrostd` local RPC.

Example:

```bash
cargo run -p bifrost-tui -- --socket /tmp/bifrostd.sock
```

Scripted mode (for automation/e2e):

```bash
cargo run -p bifrost-tui -- --socket /tmp/bifrostd.sock --script ./commands.txt
```

Command highlights:

- `use <peer>` sets the active target peer for shorthand operations.
- `sign <text...>` hashes UTF-8 text with SHA-256 and signs the digest.
- `sign hex:<64-hex>` or `sign 0x<64-hex>` signs an explicit digest.
- `ecdh <peer>` accepts alias/index/pubkey-prefix/full pubkey selectors.
- `echo <message...>` sends to the active target peer (`use <peer>`), while `echo <peer> <message...>` remains supported.
- policy runtime controls:
  - `policy list`
  - `policy get <peer>`
  - `policy set <peer> <json-policy>`
  - `policy refresh <peer>`
