# Runtime Stack (Daemon + CLI + TUI + Dev Relay)

This document tracks the Rust runtime surface that mirrors and extends the `bifrost-ts/demo` workflow.

## Targets

- `bifrost-relay-dev`: local Nostr relay for development/testing.
- `bifrost-devnet`: local key/config generator for multi-node daemon setups.
- `bifrostd`: headless Bifrost daemon exposing local JSON-RPC over a Unix socket.
- `bifrost-cli`: script/agent-friendly RPC client.
- `bifrost-tui`: interactive operator shell connected to `bifrostd`.

## Build

```bash
cargo check -p bifrost-devnet -p bifrost-relay-dev -p bifrostd -p bifrost-cli -p bifrost-tui --offline
```

## One-Command Devnet

```bash
scripts/devnet.sh smoke
```

Other commands:

```bash
scripts/devnet.sh gen
scripts/devnet.sh start
scripts/devnet.sh status
scripts/devnet.sh stop
```

## tmux Demo Layout

Run a TS-style 4-pane layout (relay + alice/bob/carol):

```bash
scripts/devnet-tmux.sh start
```

Controls:

```bash
scripts/devnet-tmux.sh status
scripts/devnet-tmux.sh stop
```

## Relay

```bash
cargo run -p bifrost-relay-dev -- 8194
# or
cargo run -p bifrost-relay-dev -- --port 8194
```

Environment:
- `BIFROST_RELAY_PURGE_SECS=<n>`: optional event cache purge interval.

## Daemon

Create a JSON config (example below) and run:

```bash
cargo run -p bifrostd -- --config ./dev/data/daemon-alice.json
```

Config schema:

```json
{
  "socket_path": "/tmp/bifrostd-alice.sock",
  "group_path": "./dev/data/group.json",
  "share_path": "./dev/data/share-alice.json",
  "peers": ["<peer-member-pubkey-hex>", "<peer-member-pubkey-hex>"],
  "relays": ["ws://127.0.0.1:8194"],
  "options": null,
  "transport": {
    "rpc_kind": 20000,
    "max_retries": 3,
    "backoff_initial_ms": 250,
    "backoff_max_ms": 5000,
    "sender_pubkey33": "<local-member-pubkey-hex>",
    "sender_seckey32_hex": "<local-member-seckey-hex>"
  }
}
```

## CLI

```bash
cargo run -p bifrost-cli -- --socket /tmp/bifrostd-alice.sock status
cargo run -p bifrost-cli -- --socket /tmp/bifrostd-alice.sock events 20
cargo run -p bifrost-cli -- --socket /tmp/bifrostd-alice.sock ping <peer_pubkey_hex>
```

Use `--json` for machine-readable output.

## TUI (`ratatui` + `crossterm`)

```bash
cargo run -p bifrost-tui -- --socket /tmp/bifrostd-alice.sock
```

Scripted mode for automation/e2e:

```bash
cargo run -p bifrost-tui -- --socket /tmp/bifrostd-alice.sock --script ./commands.txt
```

Interactive commands:
- `status`
- `events [n]`
- `ping <peer>`
- `echo <peer> <message>`
- `sign <32-byte-hex>`
- `ecdh <33-byte-hex>`
- `onboard <peer>`
- `quit`

## TUI e2e (real devnet)

```bash
scripts/test-tui-e2e.sh
```

## Node e2e (real devnet)

```bash
scripts/test-node-e2e.sh
```

## Notes

- Current RPC is local, newline-delimited JSON over Unix sockets.
- Inter-node transport is now Nostr-native (`REQ`/`EVENT`/`CLOSE`) through `bifrost-transport-ws` and `bifrost-relay-dev` (no raw JSON websocket envelope mode).
- Inter-node event content is encrypted with NIP-44-v2-compatible payload processing (secp256k1 ECDH + HKDF + ChaCha20 + HMAC).
- Production hardening tasks remain: authz, schema versioning policy, and stronger lifecycle supervision.
