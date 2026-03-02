# Project Overview

## Goal

Migrate `bifrost-ts` into a Rust workspace (`bifrost-rs`) while preserving protocol behavior and improving safety and reliability.

## Repository Layout

- `crates/bifrost-core`: protocol primitives and cryptographic composition.
- `crates/bifrost-codec`: wire/RPC encoding and type bridges.
- `crates/bifrost-transport`: runtime-agnostic transport interfaces.
- `crates/bifrost-node`: orchestration layer for peer operations.
- `crates/bifrost-transport-ws`: websocket transport backend (in progress).
- `dev/planner/`: migration tracking artifacts and execution plan.
- `docs/`: product manual and technical knowledgebase.
- `contrib/`: examples and other helpful project contributions.

## Design Intent

- Keep crypto logic inside `bifrost-core`.
- Keep transport abstract behind traits.
- Keep node logic focused on protocol orchestration and policy enforcement.
- Keep wire format isolated in codec crate.

## Compatibility Policy

- Target: behavioral parity with TypeScript.
- Allow: Rust-idiomatic internals and stronger validation/safety checks.
- Any intentional deviation must be documented in planner parity/interface docs.
