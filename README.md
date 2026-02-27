# bifrost-rs

Rust workspace for the Bifrost migration.

## Layout

- `crates/bifrost-core`: deterministic protocol and crypto primitives
- `crates/bifrost-codec`: wire codec and RPC envelope serialization
- `crates/bifrost-transport`: runtime-agnostic transport traits
- `crates/bifrost-node`: node orchestration runtime
- `crates/bifrost-transport-ws`: websocket transport backend (in progress)
- `example/`: standalone exploratory examples
- `planner/`: migration plan, parity matrix, milestones, and backlog
- `docs/`: durable context and handoff documentation

## Status

Implemented in this iteration:
- Workspace split and shared dependency management
- Group/session ID determinism in `bifrost-core`
- FROST-based signing integration for active sign path
- FROST nonce state handling integrated into nonce pool
- Typed wire envelope and JSON codec with hex encoding bridges
- Runtime-agnostic transport interfaces
- Node API flow implementations (`connect`, `close`, `echo`, `ping`, `onboard`, `sign`, `ecdh`)
- Inbound handler implementation for `echo`, `ping`, `onboard`, `sign`, and `ecdh`
- Session validation hardening and negative-path tests
- Planner system for migration execution tracking

Still pending:
- Safe batch-signing parity and related nonce lifecycle expansions
- WS transport production hardening (reconnect/failover/health)
- Event/batcher/cache parity with TypeScript class layer
- Expanded adversarial/integration coverage and release readiness tasks

## Start Here

If you are resuming work after a context reset:

1. Read [docs/README.md](./docs/README.md)
2. Read [docs/current-status.md](./docs/current-status.md)
3. Read [planner/README.md](./planner/README.md)
4. Continue from [planner/04-backlog.md](./planner/04-backlog.md)
