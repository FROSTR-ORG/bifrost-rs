# Configuration Reference

`bifrostd` loads a JSON config file (default CLI arg `--config <path>`).

## Daemon Config Schema

```json
{
  "socket_path": "/tmp/bifrostd-alice.sock",
  "group_path": "<data-dir>/group.json",
  "share_path": "<data-dir>/share-alice.json",
  "peers": [
    {
      "pubkey": "<peer-member-pubkey-hex>",
      "policy": {
        "block_all": false,
        "request": { "echo": true, "ping": true, "onboard": true, "sign": true, "ecdh": true },
        "respond": { "echo": true, "ping": true, "onboard": true, "sign": true, "ecdh": true }
      }
    }
  ],
  "relays": ["ws://127.0.0.1:8194"],
  "options": null,
  "transport": {
    "rpc_kind": 20000,
    "max_retries": 3,
    "backoff_initial_ms": 250,
    "backoff_max_ms": 5000,
    "sender_pubkey33": "<local-member-pubkey-hex>",
    "sender_seckey32_hex": "<local-member-seckey-hex>"
  },
  "auth": {
    "token": null,
    "allow_unauthenticated_read": false,
    "insecure_no_auth": true
  }
}
```

## Field Semantics

Top-level fields:
- `socket_path`: Unix socket path for local RPC server.
- `group_path`: JSON file path for group package.
- `share_path`: JSON file path for local share package.
- `peers`: allowed peer member pubkeys with granular request/respond policy.
- `relays`: websocket relay URLs (must be non-empty).
- `options`: optional `BifrostNodeOptions` overrides.
- `transport`: websocket transport tuning.
- `auth`: RPC authentication/authorization policy.

`transport` defaults:
- `rpc_kind`: `20000`
- `max_retries`: `3`
- `backoff_initial_ms`: `250`
- `backoff_max_ms`: `5000`
- `sender_pubkey33`: derived from share if omitted
- `sender_seckey32_hex`: share secret key if omitted

Validation rule:
- If `sender_pubkey33` is supplied, it must match the share-derived local pubkey.

`auth` fields:
- `token`: bearer token for authenticated requests.
- `allow_unauthenticated_read`: if `true`, read-only methods may be called without token.
- `insecure_no_auth`: explicit development-only bypass; when `true` and `token` is unset, all RPC methods are unauthenticated.

Auth validation rules:
- `auth.token` is required unless `auth.insecure_no_auth=true`.
- `allow_unauthenticated_read` requires `auth.token` to be set.

## RPC Versioning

Supported RPC versions are currently fixed to:
- minimum: `1`
- maximum: `1`

Clients should call `negotiate` during startup.

## CLI Runtime Flags

`bifrost-cli`:
- `--socket <PATH>` (default `/tmp/bifrostd.sock`)
- `--json` for machine-readable response output

`bifrost-tui`:
- `--socket <PATH>` (default `/tmp/bifrostd.sock`)
- `--script <PATH>` for non-interactive scripted mode

## Recommended Production-Like Baseline

- Set explicit `auth.token`.
- Keep `auth.insecure_no_auth=false`.
- Keep `allow_unauthenticated_read=false` unless deliberately required.
- Use dedicated service user and restrictive socket permissions.
- Pin a controlled relay set.
