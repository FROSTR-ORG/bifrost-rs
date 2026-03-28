# Contributing to bifrost-rs

Thanks for contributing. This project migrates `bifrost-ts` to Rust with strict parity and stronger safety.

## Prerequisites

- Rust toolchain (stable)
- `cargo` available
- Unix-like environment for runtime scripts

## Setup

```bash
git clone <repo-url>
cd bifrost-rs
cargo check --workspace --offline
```

## Workflow

1. Pick a task from active project artifacts (`dev/plans/`, `dev/checklists/`, or a tracked issue).
2. Implement code and tests in a focused branch.
3. Run verification gates from `TESTING.md`.
4. Update docs and artifacts affected by the change.
5. Include concrete test evidence in the PR description.

## Coding Rules

- prioritize cryptographic correctness and nonce safety
- do not silently change protocol behavior
- add tests for every behavioral change, especially negative-path tests
- keep public API and crate-boundary documentation synchronized with the root docs

## Pull Requests

- keep PRs focused and reviewable
- include:
  - problem statement
  - changes made
  - test evidence (commands and result)
  - docs and artifacts touched

## Documentation Requirements

If behavior changes:

1. Update `README.md` if architecture, API, runtime contracts, utility formats, config, or troubleshooting guidance changed.
2. Update `TESTING.md` for verification changes.
3. Update `RELEASE.md` for release-gate changes.
4. Update `SECURITY.md` when threat model or disclosure guidance changes.
5. Do not duplicate general FROSTR protocol, cryptography, or glossary topics in this repo-local manual set.
6. Update release and audit artifacts (`RELEASE.md`, `dev/artifacts/current-status.md`, `dev/audit/*`) when relevant.

## Architecture And Ownership Notes

### Crate responsibilities

- `bifrost-core`: cryptographic/session primitives and nonce safety
- `bifrost-codec`: strict bridge/wire/package validation
- `bifrost-signer`: signer state machine, readiness, replay, and policy logic
- `bifrost-router`: queueing, dedupe, request lifecycle, and outbound routing
- `bifrost-bridge-tokio`: native async bridge runtime
- `bifrost-bridge-wasm`: browser-facing runtime bridge and package exports
- `bifrost-app`: reusable host/listen/control layer
- `frostr-utils`: keyset lifecycle, package, onboarding, and backup helpers

### Hosted runtime model

- `runtime_status()` is the canonical host read model
- `readiness()` is the capability view
- `drain_runtime_events()` is incremental only
- hosted clients should not infer readiness from snapshots or nonce inventory

### Security model

Repository-scoped threats and controls:
- malformed payloads: strict codec bounds and parsing
- spoofing and binding failures: signer-side sender/member checks
- replay and stale requests: replay cache and TTL checks
- nonce misuse: core and signer guardrails
- relay metadata leakage: encrypted opaque content payloads

Keep filesystem permissions, relay lists, and dev key material handling conservative in local workflows.
