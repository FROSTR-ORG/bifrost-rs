# Security Policy

## Reporting a Vulnerability

Do not open a public issue for security vulnerabilities.

Report privately with:

1. A clear description of impact
2. Reproduction steps
3. Affected components/crates
4. Suggested mitigation (if known)

If private reporting infrastructure is unavailable, coordinate directly with maintainers and avoid public disclosure until patched.

## Scope

Security-sensitive areas include:

- `bifrost-core` cryptographic flows and nonce lifecycle
- `bifrost-codec` validation and parsing boundaries
- `bifrost-signer` authorization/binding/replay controls
- `bifrost-bridge` relay orchestration and queueing controls
- `bifrost-app` state persistence and runtime configuration safety

## Disclosure Policy

- Acknowledge report receipt as quickly as practical.
- Validate and triage severity.
- Ship fix with regression tests.
- Publish advisory notes after a patch is available.

## Security Documentation

- Threat model: `docs/SECURITY-MODEL.md`
- Cryptography details: `docs/CRYPTOGRAPHY.md`
- Release security checks: `RELEASE.md`
