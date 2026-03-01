# Dependency Audit -- bifrost-rs v0.1.0

This document is a comprehensive audit of all direct (first-party declared) dependencies across the bifrost-rs workspace. The scope covers the eleven workspace crates plus the `contrib/example` binary. Transitive dependencies are noted only where they carry known advisories or elevated risk. Versions listed are the resolved versions from `Cargo.lock` as of 2026-02-28.

Dependencies are grouped by functional category. The **Risk** column reflects a composite judgment of maintenance status, attack surface, and replaceability within this project.

---

## Cryptography

| Name | Version | Used By | Purpose | Maintenance | Risk | Notes |
|------|---------|---------|---------|-------------|------|-------|
| `frost-secp256k1-tr-unofficial` | 2.2.0 | bifrost-core, frostr-utils, bifrost-node (dev) | FROST threshold signing (secp256k1 Taproot variant) | low-activity | **HIGH** | Unofficial fork of the ZF FROST crate family. Transitive dep chain `frost-core-unofficial` -> `postcard` -> `heapless` -> `atomic-polyfill` triggers **RUSTSEC-2023-0089** (unsound `AtomicU64` on platforms without native 64-bit atomics). Core cryptographic dependency; cannot be replaced without a full protocol-level migration. Monitor upstream `frost-secp256k1-tr` for an official Taproot variant. |
| `k256` | 0.13.4 | bifrost-core, bifrost-node, bifrost-transport-ws, bifrost-devtools | secp256k1 elliptic curve arithmetic and ECDH | active | Low | Part of the RustCrypto ecosystem. Well-audited, widely used. |
| `sha2` | 0.10.9 | bifrost-core, bifrost-transport-ws, bifrost-devtools | SHA-256 hashing | active | Low | RustCrypto standard. |
| `hmac` | 0.12.1 | bifrost-core, bifrost-transport-ws | HMAC-based message authentication | active | Low | RustCrypto standard. |
| `chacha20` | 0.9.1 | bifrost-transport-ws | ChaCha20 stream cipher for NIP-44 encryption | active | Low | RustCrypto. Used for Nostr encrypted message transport. |
| `rand_core` | 0.6.4 | bifrost-core, bifrost-node, frostr-utils, bifrost-transport-ws, bifrost-devtools (dev) | Cryptographic RNG traits and `OsRng` | active | Low | Foundation crate for all RustCrypto randomness. |
| `zeroize` | 1.8.2 | bifrost-core, frostr-utils | Secure memory zeroing for secret key material | active | Low | Critical for key hygiene. `derive` feature enables `#[derive(Zeroize)]`. |

## Serialization

| Name | Version | Used By | Purpose | Maintenance | Risk | Notes |
|------|---------|---------|---------|-------------|------|-------|
| `serde` | 1.0.228 | bifrost-core, bifrost-codec, bifrost-transport, bifrost-node, bifrost-transport-ws, bifrost-rpc, bifrostd, bifrost-devtools, frostr-utils | Serialization/deserialization framework | active | Low | Ubiquitous Rust ecosystem crate. `derive` feature enabled. |
| `serde_json` | 1.0.149 | bifrost-codec, bifrost-transport, bifrost-node, bifrost-transport-ws, bifrost-rpc, bifrostd, bifrost-cli, bifrost-tui, bifrost-devtools, frostr-utils | JSON serialization | active | Low | Standard JSON crate. |
| `hex` | 0.4.3 | bifrost-core, bifrost-codec, bifrost-node, bifrost-transport-ws, bifrostd, bifrost-tui, bifrost-devtools, frostr-utils | Hex encoding/decoding | active | Low | Simple, stable utility. |
| `bech32` | 0.11.1 | frostr-utils | Bech32/Bech32m encoding for onboarding packages | active | Low | Nostr key encoding standard (NIP-19). |
| `base64` | 0.22.1 | bifrost-transport-ws | Base64 encoding for WebSocket payloads | active | Low | Standard encoding crate. |

## Networking

| Name | Version | Used By | Purpose | Maintenance | Risk | Notes |
|------|---------|---------|---------|-------------|------|-------|
| `tokio-tungstenite` | 0.24.0 | bifrost-transport-ws, bifrost-devtools | Async WebSocket client/server | active | Medium | `rustls-tls-webpki-roots` feature pulls in a significant TLS dependency tree (rustls, webpki, ring). Evaluate whether native-tls would reduce supply chain surface. |

## Async Runtime

| Name | Version | Used By | Purpose | Maintenance | Risk | Notes |
|------|---------|---------|---------|-------------|------|-------|
| `tokio` | 1.49.0 | bifrost-node, bifrost-transport-ws, bifrost-rpc, bifrostd, bifrost-cli, bifrost-tui, bifrost-devtools | Async runtime (executor, timers, I/O, sync primitives) | active | Low | Industry-standard async runtime. Feature sets vary by crate: `rt-multi-thread` for binaries, minimal `rt`+`sync`+`time` for libraries. |
| `futures` | 0.3.31 | bifrost-transport, bifrost-node, bifrost-transport-ws (dev) | Future combinators and stream utilities | active | Low | Core async ecosystem crate. |
| `futures-util` | 0.3.31 | bifrost-transport-ws, bifrost-devtools | Stream/sink extension traits | active | Low | Subset of `futures`. Used for `StreamExt`/`SinkExt` on WebSocket streams. |

## Error Handling

| Name | Version | Used By | Purpose | Maintenance | Risk | Notes |
|------|---------|---------|---------|-------------|------|-------|
| `thiserror` | 2.0.18 | bifrost-core, bifrost-codec, bifrost-transport, bifrost-node, bifrost-transport-ws, frostr-utils | Derive macro for `std::error::Error` | active | Low | Workspace uses v2; `frost-core-unofficial` transitively pulls in `thiserror` 1.x as well (dual version in lockfile). |
| `anyhow` | 1.0.102 | bifrost-rpc, bifrostd, bifrost-cli, bifrost-tui, bifrost-devtools | Ergonomic error handling for applications | active | Low | Used in binary/application crates only, not in library crates. |

## CLI / TUI

| Name | Version | Used By | Purpose | Maintenance | Risk | Notes |
|------|---------|---------|---------|-------------|------|-------|
| `ratatui` | 0.30.0 | bifrost-tui | Terminal UI rendering framework | active | Low | Community successor to `tui-rs`. Actively maintained with regular releases. |
| `crossterm` | 0.29.0 | bifrost-tui | Cross-platform terminal manipulation backend | active | Low | Backend for `ratatui`. Matches ratatui-derived transitive dependency chain. |

## Observability

| Name | Version | Used By | Purpose | Maintenance | Risk | Notes |
|------|---------|---------|---------|-------------|------|-------|
| `tracing` | 0.1.44 | bifrost-transport-ws, bifrostd, bifrost-devtools | Structured, async-aware logging and diagnostics | active | Low | Tokio ecosystem standard. Only the facade crate is a direct dependency; subscriber configuration is left to the binary crates. |

## Testing / Dev-only

| Name | Version | Used By | Purpose | Maintenance | Risk | Notes |
|------|---------|---------|---------|-------------|------|-------|
| `rand` | 0.8.5 | frostr-utils (dev) | Full-featured RNG for test fixtures | active | Low | Dev-dependency only. Not compiled into release builds. |

---

## Summary of Findings

### High-Risk Dependencies

1. **`frost-secp256k1-tr-unofficial` 2.2.0** -- This is the single highest-risk dependency in the project. It is an unofficial fork with no guaranteed maintenance commitment, and its transitive dependency chain includes `atomic-polyfill` (RUSTSEC-2023-0089). The advisory concerns unsound behavior on platforms without native 64-bit atomics; while x86-64 Linux targets are unaffected in practice, the advisory remains open and un-patched in this dependency tree. This crate is irreplaceable without a protocol migration -- there is no official `frost-secp256k1-tr` crate from the ZCash Foundation as of this writing.

### Medium-Risk Dependencies

2. **`tokio-tungstenite` 0.24.0** -- The `rustls-tls-webpki-roots` feature flag pulls in a large transitive tree (rustls, ring, webpki-roots). This is standard practice for async WebSocket clients, but the TLS stack represents meaningful attack surface. Consider pinning `rustls` versions and monitoring advisories.

### Future Considerations

- **Dual `thiserror` versions** (1.x transitive from frost, 2.x direct) increase compile times slightly. This resolves automatically if/when the frost fork updates its dependency.
