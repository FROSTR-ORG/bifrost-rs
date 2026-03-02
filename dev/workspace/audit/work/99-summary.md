# Audit Run Summary — 2026-02-27

## Category Outcomes

| category | status | top findings |
|---|---|---|
| architecture | pass | evidence matrix green |
| completeness | pass | planner and matrix gates green |
| separation/boundaries | pass | governance/doc boundaries intact |
| security | conditional_pass | accepted-risk: `RUSTSEC-2023-0089` (`atomic-polyfill`, transitive) |
| technical debt | conditional_pass | accepted-risk tracking remains open |
| code smell | pass | cold-start e2e hardening in place |
| readability | pass | command/doc readability acceptable |
| documentation | pass | governance + audit docs aligned |
| testing quality | pass | fmt/clippy/check/tests/e2e all green |
| reliability/operability | pass | e2e + planner verify green |
| release/supply-chain | conditional_pass | no vulnerabilities; one accepted-risk warning |

## Aggregate Status

- Overall: `go_with_conditions`
- Blocking conditions:
1. None.

## Conditions

1. Maintain explicit accepted-risk review for `RUSTSEC-2023-0089` (`atomic-polyfill`) each release cycle.

## Evidence References

- `evidence/automation-status.txt`
- `evidence/toolchain-preflight.log`
- `evidence/cargo-fmt-check.log`
- `evidence/cargo-clippy-workspace-offline.log`
- `evidence/cargo-check-workspace-offline.log`
- `evidence/cargo-test-core-codec-node-ws-offline.log`
- `evidence/cargo-test-relay-rpc-offline.log`
- `evidence/test-node-e2e.log`
- `evidence/test-tui-e2e.log`
- `evidence/planner-summary.log`
- `evidence/planner-verify.log`
- `evidence/cargo-audit.log`
- `evidence/cargo-audit-report.txt`

## Signoff

- Engineering:
- Security:
- Release:
