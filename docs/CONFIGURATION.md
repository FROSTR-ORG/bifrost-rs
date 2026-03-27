# Configuration Reference

This manual covers the runtime configuration shape consumed by `bifrost_app::host` and the hosted signer runtime.

Host-specific config generation flows, runnable examples, and operator UX are intentionally out of scope for this manual.

## Runtime Config Semantics

The current host config model still includes:
- `group_path`
- `share_path`
- `state_path`
- `relays`
- `peers`
- `options`

These values are consumed by the shared host layer exported from `bifrost_app::host`.

## Important Runtime Options

`options` controls the signer/runtime behavior surfaced by consuming hosts such as native shells and browser hosts.

Relevant fields include:
- `sign_timeout_secs`
- `ecdh_timeout_secs`
- `ping_timeout_secs`
- `onboard_timeout_secs`
- `request_ttl_secs`
- `max_future_skew_secs`
- `request_cache_limit`
- `ecdh_cache_capacity`
- `ecdh_cache_ttl_secs`
- `sig_cache_capacity`
- `sig_cache_ttl_secs`
- `state_save_interval_secs`
- `event_kind`
- `peer_selection_strategy`
- router queue/backoff/overflow settings

## Validation Notes

- Peer pubkeys must be 32-byte x-only secp256k1 hex
- Member indexes and pubkeys must match the configured group package
- Event kind must match across participating peers
- Relay lists must be non-empty
