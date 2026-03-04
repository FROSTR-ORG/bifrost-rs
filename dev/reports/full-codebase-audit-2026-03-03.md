# Full Codebase Audit (Security, Robustness, Cross-Platform, Technical Debt)

Date: 2026-03-03  
Scope: `crates/*`, runtime scripts, and current bridge/signer/app architecture.

## Executive Summary

- No production `unsafe`, `todo!`, or `unimplemented!` usage was found.
- No active legacy daemon/RPC runtime code remains in `crates/` (hard-cut is mostly clean).
- Main remaining risks are runtime hardening and configuration fail-fast behavior.

## Findings (ordered by severity)

## 1) Unbounded command ingress allows memory-pressure DoS

Severity: `high`  
Category: Security / Robustness

Evidence:
- `crates/bifrost-bridge/src/lib.rs:129`
- `crates/bifrost-bridge/src/lib.rs:183`
- `crates/bifrost-bridge/src/lib.rs:267`

Details:
- `Bridge` uses `mpsc::UnboundedSender<BridgeCommand>` and `mpsc::unbounded_channel`.
- Internal `command_queue_capacity` is bounded, but that protection only applies after commands are pulled from the unbounded channel.
- A fast local producer can flood memory before the loop drains.

Recommended remediation:
- Replace unbounded command ingress with bounded `mpsc::channel(capacity)`.
- Use `try_send` for immediate overload signaling and preserve current overflow policy behavior.
- Emit structured overload telemetry (`queue=command`, dropped/rejected counts).

## 2) Request freshness check lacks future-skew bound

Severity: `high`  
Category: Security

Evidence:
- `crates/bifrost-signer/src/lib.rs:1321`
- `crates/bifrost-signer/src/lib.rs:1323`

Details:
- `record_request` rejects stale request IDs but does not reject IDs with timestamps far in the future.
- This allows acceptance of future-dated request IDs beyond expected clock skew windows.

Recommended remediation:
- Add `max_future_skew_secs` to config and reject `issued_at > now + max_future_skew_secs`.
- Include clear error codes for stale vs future-skew rejection.

## 3) State deserialization has no explicit size cap

Severity: `high`  
Category: Security / Robustness

Evidence:
- `crates/bifrost-app/src/runtime.rs:296`
- `crates/bifrost-app/src/runtime.rs:301`

Details:
- Encrypted state is read fully from disk and deserialized with `bincode::deserialize` without bounding input size.
- A corrupted or oversized file can cause high memory usage or deserialization stress.

Recommended remediation:
- Enforce a max ciphertext/plaintext size before decrypt/deserialize.
- Switch to a bounded deserializer and reject oversized payloads early.
- Add negative tests for oversized state blobs.

## 4) Inbound overflow `Fail` policy silently drops events

Severity: `medium`  
Category: Robustness / Operability

Evidence:
- `crates/bifrost-bridge/src/lib.rs:712`
- `crates/bifrost-bridge/src/lib.rs:713`

Details:
- With `inbound_overflow_policy = Fail`, full queue behavior is a no-op (event dropped silently).
- No error path, metric, or caller-facing signal is produced.

Recommended remediation:
- Track and emit overflow counters/logs for inbound drops.
- Optionally push a signer-visible synthetic failure event for locally initiated operations affected by drops.

## 5) Silent fallback on filter build is a compatibility shim

Severity: `medium`  
Category: Technical Debt / Robustness

Evidence:
- `crates/bifrost-signer/src/lib.rs:391`
- `crates/bifrost-signer/src/lib.rs:393`

Details:
- `subscription_filters()` uses `serde_json::from_value(...).unwrap_or_default()`.
- Invalid filter construction results in empty filter list and silent degradation.

Recommended remediation:
- Return `Result<Vec<Filter>>` and fail startup on filter-build errors.
- Remove silent fallback behavior.

## 6) Group package invariants are under-validated

Severity: `medium`  
Category: Security / Robustness

Evidence:
- `crates/bifrost-codec/src/wire.rs:171`
- `crates/bifrost-signer/src/lib.rs:313`

Details:
- Group decode checks count bounds, but does not enforce unique member indices/pubkeys or threshold sanity (`threshold <= members.len()`).
- Signer only checks non-empty members and non-zero threshold.

Recommended remediation:
- Enforce canonical invariants at decode/load time:
- unique `member.idx`
- unique `member.pubkey`
- `1 <= threshold <= members.len()`

## 7) Dev relay tag filter matching is semantically incorrect

Severity: `medium`  
Category: Test Infrastructure Robustness

Evidence:
- `crates/bifrost-dev/src/bin/devtools/relay.rs:397`
- `crates/bifrost-dev/src/bin/devtools/relay.rs:415`

Details:
- `match_tags()` does not fail when a requested filter key is absent in event tags.
- This can produce false-positive matches in local relay tests and mask protocol issues.

Recommended remediation:
- For each filter key, require at least one matching tag key in event tags.
- Add regression tests for absent-tag-key behavior.

## 8) Runtime scripts are POSIX-specific (cross-platform gap)

Severity: `medium`  
Category: Cross-Platform Compatibility

Evidence:
- `scripts/devnet.sh:1`
- `scripts/test-node-e2e.sh:1`
- `scripts/test-tui-e2e.sh:14`
- `scripts/test-tui-e2e.sh:33`

Details:
- Tooling depends on Bash, `timeout`, and `script(1)`.
- This excludes native Windows execution and complicates CI portability.

Recommended remediation:
- Add Rust-based or cross-platform task-runner alternatives for e2e orchestration.
- Keep shell scripts as optional wrappers, not the only path.

## 9) Config normalization and duplicated defaults are debt-prone shims

Severity: `low`  
Category: Technical Debt / Maintainability

Evidence:
- `crates/bifrost-bridge/src/lib.rs:453`
- `crates/bifrost-app/src/runtime.rs:122`
- `crates/bifrost-app/src/runtime.rs:149`

Details:
- `normalize_config` silently mutates invalid values (zero -> one).
- Defaults are duplicated across `BridgeConfig`, app config defaults, and docs.

Recommended remediation:
- Validate and reject invalid config rather than mutating it.
- Centralize defaults into one canonical source used by app + docs generation.

## 10) `op_id` correlation is stored but not operationally used

Severity: `low`  
Category: Technical Debt

Evidence:
- `crates/bifrost-bridge/src/lib.rs:118`
- `crates/bifrost-bridge/src/lib.rs:795`

Details:
- `op_id` is captured in waiter state but discarded (`let _ = waiter.op_id;`).
- Correlation intent exists but is not surfaced in errors/logging/metrics.

Recommended remediation:
- Include `op_id` in tracing fields and error payloads.
- Use it to correlate command ingress, queue transitions, and completion/failure.

## Cleanliness Check (No-Legacy / No-Shim Goal)

- Legacy daemon/RPC runtime code paths are not present in active crates.
- Remaining shim-like behavior still exists and should be removed:
- silent filter fallback (`subscription_filters`)
- silent config coercion (`normalize_config`)

## Priority Remediation Order

1. Bound command ingress channel and make overload explicit.  
2. Add future-skew bound to request ID validation.  
3. Add state blob size limits + bounded deserialize path.  
4. Remove silent fallbacks (`subscription_filters`, inbound overflow no-op).  
5. Enforce strict group invariants at decode/load boundaries.  
6. Fix dev relay tag matching and add regression tests.  
7. Build cross-platform e2e runner path.  
