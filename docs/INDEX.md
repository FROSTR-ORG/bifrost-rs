# Bifrost RS Manual

`docs/` is the canonical product manual for operating, integrating, and maintaining `bifrost-rs`.

## Fast Paths

- New operator: read `GUIDE.md` -> `OPERATIONS.md` -> `TROUBLESHOOTING.md`
- Integrator/client author: read `GUIDE.md` -> `API.md` -> `PROTOCOL.md` -> `CONFIGURATION.md`
- Security/release owner: read `SECURITY-MODEL.md` -> `CRYPTOGRAPHY.md` -> `OPERATIONS.md`

## Manual Contents

1. `GUIDE.md`
- End-to-end local bootstrap and first successful operations.

2. `OPERATIONS.md`
- Day-2 runbook: start/stop/status, health checks, e2e scripts, audit runs.

3. `CONFIGURATION.md`
- Runtime config schema and practical defaults.

4. `TROUBLESHOOTING.md`
- Failure modes, diagnostics, and recovery commands.

5. `API.md`
- Rust crate-level API map and runtime command inventory.

6. `frostr-utils/INDEX.md`
- Shared utility manual for keyset lifecycle and onboarding package helpers.

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
- Governance/process policy: `CONTRIBUTING.md`, `TESTING.md`, `RELEASE.md`, `SECURITY.md`, `CHANGELOG.md`
- Migration planning artifacts: project planning and execution state files outside this manual
- Execution artifacts and audits: execution/evidence directories outside this manual
