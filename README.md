# bifrost-rs

Rust workspace for migrating `bifrost-ts` to a safer, parity-focused Rust implementation.

## Governance Docs

- [CONTRIBUTING.md](./CONTRIBUTING.md)
- [TESTING.md](./TESTING.md)
- [RELEASES.md](./RELEASES.md)
- [SECURITY.md](./SECURITY.md)
- [dev/audit/AUDIT.md](./dev/audit/AUDIT.md)
- [dev/audit/RUNBOOK.md](./dev/audit/RUNBOOK.md)
- [CHANGELOG.md](./CHANGELOG.md)

## Workspace Layout

- `crates/bifrost-core`: cryptographic/session primitives.
- `crates/bifrost-codec`: wire + RPC encoding/validation/parsers.
- `crates/bifrost-transport`: transport traits and shared types.
- `crates/bifrost-node`: orchestration/runtime API.
- `crates/bifrost-transport-ws`: websocket transport backend.
- `crates/bifrost-rpc`: daemon RPC schema/client helpers.
- `crates/bifrost-relay-dev`: Rust dev Nostr relay port.
- `crates/bifrost-devnet`: local key/config generation for daemon devnets.
- `crates/bifrostd`: headless daemon target.
- `crates/bifrost-cli`: daemon RPC CLI.
- `crates/bifrost-tui`: daemon RPC interactive shell.
- `docs/`: product manual and technical knowledgebase.
- `dev/planner/`: migration source-of-truth (scope, parity, backlog, milestones).
- `dev/artifacts/`: development and agent-oriented artifacts.
- `contrib/`: examples and helpful project contributions (for example service profiles/scripts).

## Technical Docs

- [docs/INDEX.md](./docs/INDEX.md)
- [docs/GUIDE.md](./docs/GUIDE.md)
- [docs/API.md](./docs/API.md)
- [docs/PROTOCOL.md](./docs/PROTOCOL.md)
- [docs/CRYPTOGRAPHY.md](./docs/CRYPTOGRAPHY.md)
- [docs/SECURITY-MODEL.md](./docs/SECURITY-MODEL.md)
- [docs/GLOSSARY.md](./docs/GLOSSARY.md)

## Current Snapshot

Completed milestones:
- `M1` Core cryptographic parity freeze
- `M2` Codec/schema parity
- `M3` Node security parity
- `M4` WS transport hardening (state/reconnect/failover/threshold behavior)
- `M5` Batching/cache/event parity
- `M6` Integration/adversarial coverage
- `M7` Docs/examples parity
- `M8` Release readiness artifacts
- `M9` Runtime surface: daemon + cli + tui + dev relay

## Quick Verification

- Core/node/codec:
  - `cargo test -p bifrost-core -p bifrost-codec -p bifrost-node --offline`
- WS transport:
  - `cargo test -p bifrost-transport-ws --offline`
- Runtime targets:
  - `cargo check -p bifrost-devnet -p bifrost-relay-dev -p bifrostd -p bifrost-cli -p bifrost-tui --offline`
- Runtime smoke:
  - `scripts/devnet.sh smoke`
- Runtime tmux demo:
  - `scripts/devnet-tmux.sh start`
- Runtime TUI e2e (real devnet):
  - `scripts/test-tui-e2e.sh`
- Runtime node e2e (real devnet):
  - `scripts/test-node-e2e.sh`
- Planner baseline verification:
  - `./dev/scripts/planner_runbook.sh verify`

## Resume Checklist

1. Read [docs/INDEX.md](./docs/INDEX.md).
2. Read [dev/artifacts/current-status.md](./dev/artifacts/current-status.md).
3. Read [dev/planner/README.md](./dev/planner/README.md).
4. Continue from [dev/planner/04-backlog.md](./dev/planner/04-backlog.md).

Planner automation:
- Runbook: [dev/planner/RUNBOOK.md](./dev/planner/RUNBOOK.md)
- CLI: `dev/scripts/planner_runbook.sh`
