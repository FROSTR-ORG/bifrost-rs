# Devnet Runtime Example

This folder stores generated runtime devnet artifacts used by `bifrostd`.

Expected files:
- `group.json`
- `share-alice.json`
- `share-bob.json`
- `share-carol.json`
- `daemon-alice.json`
- `daemon-bob.json`
- `daemon-carol.json`

Generate/start/stop with:

```bash
scripts/devnet.sh gen
scripts/devnet.sh start
scripts/devnet.sh status
scripts/devnet.sh stop
```

Or run the full smoke loop:

```bash
scripts/devnet.sh smoke
```

TS-style tmux demo:

```bash
scripts/devnet-tmux.sh start
```

Use [dev/artifacts/runtime-stack.md](../artifacts/runtime-stack.md) for details.
