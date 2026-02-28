# Internal Audit Report (2026-02-27)

## Summary

- Audit status: `go_with_conditions`
- Build/test/runtime gates: passing.
- Security gate: high-severity vulnerability `RUSTSEC-2026-0007` remediated.
- Warning triage status: `paste` and `lru` advisories removed by dependency updates; `atomic-polyfill` retained as accepted-risk pending upstream updates.
- Reliability hardening status: node/tui e2e cold-start handling improved (prebuild + configurable readiness wait + log diagnostics).

## Evidence

1. `dev/scripts/toolchain_preflight.sh --require-cargo --require-cargo-audit`  
Result: pass

2. `cargo fmt --all -- --check`  
Result: pass

3. `cargo clippy --workspace --all-targets --offline --no-deps`  
Result: pass

4. `cargo check --workspace --offline`  
Result: pass

5. `cargo test -p bifrost-core -p bifrost-codec -p bifrost-node -p bifrost-transport-ws --offline`  
Result: pass

6. `cargo test -p bifrost-devtools -p bifrost-rpc --offline`  
Result: pass

7. `scripts/test-node-e2e.sh`  
Result: pass (hardened cold-start handling)

8. `scripts/test-tui-e2e.sh`  
Result: pass (hardened cold-start handling)

9. `dev/scripts/planner_runbook.sh summary`  
Result: pass

10. `dev/scripts/planner_runbook.sh verify`  
Result: pass

11. `cargo audit`  
Result: pass (no vulnerabilities); one warning advisory remains (`atomic-polyfill`)

## Findings

1. Vulnerability remediation complete (closed)
- `RUSTSEC-2026-0007` resolved by upgrading `bytes` from `1.11.0` to `1.11.1` in lockfile.
- Impact: former high-severity release blocker removed.

2. Warning-advisory reduction complete (partial close)
- `paste` and `lru` advisories removed by upgrading `ratatui` to `0.30.0` and lockfile dependencies.
- Impact: advisory surface reduced from 3 warnings to 1 warning.

3. Accepted-risk retained for transitive advisory (medium)
- `RUSTSEC-2023-0089` (`atomic-polyfill`) remains transitive via Frost dependency chain.
- Upstream release check (crates.io, 2026-02-27):
  - `frost-secp256k1-tr-unofficial`: latest `2.2.0` (published 2025-02-23)
  - `frost-core-unofficial`: latest `2.2.0` (published 2025-02-23)
  - `atomic-polyfill`: latest `1.0.3` (published 2023-07-11)
  - Dependency path in lockfile: `frost-secp256k1-tr-unofficial -> frost-core-unofficial -> postcard -> heapless -> atomic-polyfill`
- Impact: medium residual maintenance/security risk; tracked under `M11-007` with periodic review.

4. Cold-start reliability hardening complete (closed)
- Node/TUI e2e scripts now prebuild runtime binaries and use configurable socket wait timeout/interval with daemon log tails on timeout.
- Impact: first-run startup flake risk reduced and diagnostics improved.

## Recommended Follow-Ups

1. Re-check `cargo audit` each release cycle and close accepted-risk once upstream dependency chain removes `atomic-polyfill`.
2. Keep dependency updates and lockfile refreshes in regular maintenance cadence.
