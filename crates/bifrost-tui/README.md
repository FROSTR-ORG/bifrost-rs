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
