# Bifrost RS Manual

`docs/` is the canonical product manual for operating, integrating, and maintaining `bifrost-rs`.

## Fast Paths

- New operator: read `../../igloo-shell/docs/GUIDE.md` -> `../../igloo-shell/docs/OPERATIONS.md` -> `TROUBLESHOOTING.md`
- Integrator/client author: read `GUIDE.md` -> `API.md` -> `PROTOCOL.md` -> `CONFIGURATION.md`
- Security/release owner: read `SECURITY-MODEL.md` -> `CRYPTOGRAPHY.md` -> `OPERATIONS.md`
- Cross-repo architecture/protocol reader: read [../../../docs/INDEX.md](../../../docs/INDEX.md) -> [../../../docs/ARCHITECTURE.md](../../../docs/ARCHITECTURE.md) -> [../../../docs/PROTOCOL.md](../../../docs/PROTOCOL.md)

## Manual Contents

1. `GUIDE.md`
- Runtime/library orientation for the current signer core.

2. `OPERATIONS.md`
- Runtime-core operations, health signals, and cross-links into shell-owned runbooks.

3. `CONFIGURATION.md`
- Runtime config semantics owned by the host layer.

4. `TROUBLESHOOTING.md`
- Failure modes, structured diagnostics, and recovery commands.

5. `API.md`
- Rust crate-level API map and runtime command inventory.

6. `frostr-utils/INDEX.md`
- Shared utility manual for keyset lifecycle, browser package formats, encrypted backups, and WASM package exports.

7. `PROTOCOL.md`
- Peer envelope formats and validation boundaries.

8. `ARCHITECTURE.md`
- Crate responsibilities, critical boundaries, and request data flow.

9. `CRYPTOGRAPHY.md`
- Signing/ECDH lifecycle and nonce safety model.

10. `SECURITY-MODEL.md`
- Threat model, control matrix, and residual risks.

11. `GLOSSARY.md`
- Shared terminology.

## Out of scope for `docs/`

The following are intentionally outside this manual:
- Shell/operator manuals: `../../igloo-shell/docs/`
- Governance/process policy: `CONTRIBUTING.md`, `TESTING.md`, `RELEASE.md`, `SECURITY.md`, `CHANGELOG.md`
- Migration planning artifacts: project planning and execution state files outside this manual
- Execution artifacts and audits: execution/evidence directories outside this manual
- Cross-repo ADRs and guidance docs under `../../../docs/adrs/` and `../../../docs/policies/`
