# Bifrost RS Manual

`docs/` is the repo-specific technical manual for developing and maintaining `bifrost-rs`.

## Fast Paths

- Runtime/library maintainer: read `../README.md` -> `ARCHITECTURE.md` -> `API.md`
- Host/runtime integrator: read `../README.md` -> `API.md` -> `CONFIGURATION.md`
- Security/release owner: read `SECURITY-MODEL.md` -> `OPERATIONS.md`

## Manual Contents

1. `API.md`
- Rust crate-level API map and runtime command inventory.

2. `ARCHITECTURE.md`
- Crate responsibilities, hosted runtime boundaries, and internal request flow.

3. `CONFIGURATION.md`
- Runtime config semantics owned by the host layer.

4. `OPERATIONS.md`
- Runtime-core operations, health signals, and verification guidance.

5. `TROUBLESHOOTING.md`
- Failure modes, structured diagnostics, and recovery commands.

6. `SECURITY-MODEL.md`
- Threat model, control matrix, and residual repo-scoped risks.

7. `frostr-utils/INDEX.md`
- Shared utility manual for keyset lifecycle, browser package formats, encrypted backups, and WASM package exports.

## Out of scope for `docs/`

The following are intentionally outside this manual:
- Host-specific operator manuals in consuming repositories
- General FROSTR protocol, cryptography, glossary, and system-wide architecture topics
- Governance/process policy: `CONTRIBUTING.md`, `TESTING.md`, `RELEASE.md`, `SECURITY.md`, `CHANGELOG.md`
- Migration planning artifacts: project planning and execution state files outside this manual
- Execution artifacts and audits: execution/evidence directories outside this manual
