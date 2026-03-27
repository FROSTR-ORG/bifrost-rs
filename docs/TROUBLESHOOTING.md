# Troubleshooting

Common issues and fast diagnostics for `bifrost-rs` runtime workflows.

## `cargo` Not Found

Run:

```bash
cargo --version
```

## Config File Not Found

Symptoms:
- `read config ... No such file or directory`

Fix:
- Confirm `--config <path>` points to a valid generated runtime config file.
- Re-generate local artifacts if missing:

```bash
cargo run -p bifrost-devtools --manifest-path Cargo.toml -- keygen --out-dir ./data --threshold 2 --count 3 --relay ws://127.0.0.1:8194
```

## Relay Connection Failures

Checks:

```bash
cargo run -p bifrost-devtools --manifest-path Cargo.toml -- relay --host 127.0.0.1 --port 8194
```

Typical causes:
- relay not running
- wrong relay URL in config
- local firewall/port conflicts

## `ping` / `sign` / `ecdh` Timeouts

Checks:
- confirm the consuming host has active peer listeners/runtimes
- confirm all peers share the same `event_kind`
- confirm peer pubkeys in config match group members

## State Corruption Errors

Symptoms:
- `state corrupted` errors on load/save

Fix:
- stop process
- back up and remove the corrupted state file (`state_path`)
- rerun command; state will be re-initialized

## Escalation Checklist

If blocked, collect:
- command run
- exact stderr output
- structured runtime logs
- relay logs
- active config JSON (redact sensitive fields)
