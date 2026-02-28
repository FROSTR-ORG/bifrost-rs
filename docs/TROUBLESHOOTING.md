# Troubleshooting

Common issues and fast diagnostics for `bifrost-rs` runtime and audit workflows.

## `cargo` Or `cargo-audit` Not Found

Symptoms:
- preflight failures
- scripts aborting before runtime actions

Fix:

```bash
./dev/scripts/toolchain_preflight.sh --require-cargo --require-cargo-audit
```

Install missing tooling, then re-run preflight.

## Devnet Start Succeeds But RPC Socket Is Missing

Symptoms:
- CLI errors connecting to `/tmp/bifrostd-*.sock`
- e2e scripts timeout waiting for sockets

Checks:

```bash
scripts/devnet.sh status
ls -l /tmp/bifrostd-*.sock
ls -l dev/data/logs
```

Inspect daemon logs:

```bash
tail -n 100 dev/data/logs/bifrostd-alice.log
```

Typical causes:
- invalid daemon config paths (`group_path`, `share_path`)
- relay not running/reachable
- socket permission conflicts

## RPC `unsupported rpc_version`

Symptoms:
- server replies with code `426`

Fix:
- send `negotiate` request first and use supported version range.

Example:

```bash
cargo run -p bifrost-cli -- --socket /tmp/bifrostd-alice.sock negotiate bifrost-cli 1
```

## RPC `unauthorized`

Symptoms:
- methods rejected despite healthy daemon

Checks:
- inspect daemon config `auth` section.
- confirm token usage for protected methods.

If running in local-dev mode and intentionally disabling auth for all methods, set:
- `insecure_no_auth: true`

## `ping`/`echo`/`sign`/`ecdh` Intermittently Fail

Checks:

```bash
cargo run -p bifrost-cli -- --socket /tmp/bifrostd-alice.sock status
cargo run -p bifrost-cli -- --socket /tmp/bifrostd-alice.sock events 50
```

Look for:
- peer offline/unready
- bounced/error events
- stale/replay rejections

Then verify relay and peer daemons:

```bash
scripts/devnet.sh status
tail -n 100 dev/data/logs/relay.log
```

## First-Run E2E Flakes

The e2e scripts include warm-up and socket readiness waits. If failures persist:
- re-run serially after `scripts/devnet.sh stop` and clean restart.
- check log tails printed by scripts on timeout.

Recommended sequence:

```bash
scripts/devnet.sh stop || true
scripts/devnet.sh smoke
scripts/test-node-e2e.sh
scripts/test-tui-e2e.sh
```

## `cargo audit` Warning For `atomic-polyfill`

Current status:
- accepted transitive risk (`RUSTSEC-2023-0089`)
- chain: `frost-secp256k1-tr-unofficial -> frost-core-unofficial -> postcard -> heapless -> atomic-polyfill`

Action:
- keep release-cycle audit checks active and close risk when upstream chain updates.
- owner: `security/runtime`; next review: `2026-03-31`.

References:
- `dev/audit/internal-audit-2026-02-27.md`
- `dev/audit/work/evidence/cargo-audit-report.txt`

## Escalation Checklist

If blocked, collect and share:
- failing command
- exact stderr output
- relevant log tail (`dev/data/logs/*`)
- current config (`dev/data/daemon-*.json`, redacting secrets)
- audit evidence path if applicable (`dev/audit/work/evidence/*`)
