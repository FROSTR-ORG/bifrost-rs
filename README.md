# Bifrost RS

Rust implementation of the FROSTR threshold-signing stack, migrated from `bifrost-ts` with behavior parity goals and stricter runtime safety.

## What This Is

`bifrost-rs` provides:
- FROST threshold signing over secp256k1.
- Collaborative ECDH flows.
- Nostr-native peer transport (`REQ`/`EVENT`/`CLOSE`) with encrypted payload handling.
- A production-shaped runtime surface:
  - `bifrostd` daemon (local RPC server)
  - `bifrost-cli` (scriptable client)
  - `bifrost-tui` (operator interface)
  - `bifrost-devtools` + devnet scripts (local integration harness)

## Project Status

Migration backlog status is complete in planner tracking (`53/53 done`).

Current release condition:
- `cargo audit` is vulnerability-clean.
- One accepted transitive warning remains: `RUSTSEC-2023-0089` (`atomic-polyfill`) via Frost dependency chain.
- This is tracked in audit artifacts and re-checked each release cycle.

See:
- [dev/audit/internal-audit-2026-02-27.md](./dev/audit/internal-audit-2026-02-27.md)
- [dev/audit/checklist-v0.1.0.md](./dev/audit/checklist-v0.1.0.md)

## Workspace Layout

- `crates/bifrost-core`: cryptographic/session primitives and nonce safety.
- `crates/frostr-utils`: shared FROSTR keyset/onboarding utility APIs.
- `crates/bifrost-codec`: wire and RPC validation/parsing.
- `crates/bifrost-transport`: transport traits/shared message types.
- `crates/bifrost-node`: orchestration/runtime logic.
- `crates/bifrost-transport-ws`: websocket + Nostr transport backend.
- `crates/bifrost-rpc`: daemon RPC schema/client helpers.
- `crates/bifrostd`: headless daemon over Unix socket JSON RPC.
- `crates/bifrost-cli`: command-oriented RPC client.
- `crates/bifrost-tui`: interactive operator shell.
- `crates/bifrost-devtools`: consolidated dev tooling (`relay` + `keygen`).
- `docs/`: product manual and operational guide.
- `dev/planner/`: migration source of truth.
- `dev/audit/`: audit framework, runbook, and evidence.

## Quickstart (Local Devnet)

Prereqs:
- Rust toolchain installed (`cargo`, `rustfmt`, `clippy`).
- `cargo-audit` available for security gate.

1) Preflight:

```bash
./dev/scripts/toolchain_preflight.sh --require-cargo --require-cargo-audit
```

2) Generate devnet artifacts:

```bash
scripts/devnet.sh gen
```

3) Start relay + daemons:

```bash
scripts/devnet.sh start
scripts/devnet.sh status
```

4) Run CLI commands against Alice:

```bash
cargo run -p bifrost-cli -- --socket /tmp/bifrostd-alice.sock health
cargo run -p bifrost-cli -- --socket /tmp/bifrostd-alice.sock status
cargo run -p bifrost-cli -- --socket /tmp/bifrostd-alice.sock ping <peer_pubkey_hex>
```

5) Open TUI:

```bash
cargo run -p bifrost-tui -- --socket /tmp/bifrostd-alice.sock
```

6) Stop everything:

```bash
scripts/devnet.sh stop
```

## Verification Matrix

Core checks:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --offline --no-deps
cargo check --workspace --offline
cargo test -p bifrost-core -p bifrost-codec -p bifrost-node -p bifrost-transport-ws --offline
cargo test -p bifrost-devtools -p bifrost-rpc --offline
```

Runtime checks:

```bash
scripts/devnet.sh smoke
scripts/test-node-e2e.sh
scripts/test-tui-e2e.sh
```

Audit automation:

```bash
dev/scripts/audit_run.sh
```

## Documentation Map

Start here:
- [docs/INDEX.md](./docs/INDEX.md)
- [docs/GUIDE.md](./docs/GUIDE.md)

Core manuals:
- [docs/API.md](./docs/API.md)
- [docs/PROTOCOL.md](./docs/PROTOCOL.md)
- [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md)
- [docs/CRYPTOGRAPHY.md](./docs/CRYPTOGRAPHY.md)
- [docs/SECURITY-MODEL.md](./docs/SECURITY-MODEL.md)
- [docs/CONFIGURATION.md](./docs/CONFIGURATION.md)
- [docs/OPERATIONS.md](./docs/OPERATIONS.md)
- [docs/TROUBLESHOOTING.md](./docs/TROUBLESHOOTING.md)
- [docs/GLOSSARY.md](./docs/GLOSSARY.md)

Governance/process:
- [CONTRIBUTING.md](./CONTRIBUTING.md)
- [TESTING.md](./TESTING.md)
- [RELEASES.md](./RELEASES.md)
- [SECURITY.md](./SECURITY.md)
- [CHANGELOG.md](./CHANGELOG.md)

## TS Parity Tracking

- Parity matrix: [dev/planner/02-parity-matrix.md](./dev/planner/02-parity-matrix.md)
- Gap report: [dev/artifacts/gap-report-ts-vs-rs.md](./dev/artifacts/gap-report-ts-vs-rs.md)
- TS to RS migration notes: [dev/artifacts/migration-guide-ts-to-rs.md](./dev/artifacts/migration-guide-ts-to-rs.md)

## Security Notes

- Local RPC surface (`bifrostd`) supports token auth (`auth.token`) and optional unauthenticated read mode controls.
- Enforce restrictive socket permissions in any shared environment.
- Treat `dev/data` credentials as ephemeral test material only.

## License

MIT.
