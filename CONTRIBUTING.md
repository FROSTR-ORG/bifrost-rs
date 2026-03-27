# Contributing to bifrost-rs

Thanks for contributing. This project migrates `bifrost-ts` to Rust with strict parity and stronger safety.

## Prerequisites

- Rust toolchain (stable)
- `cargo` available
- Unix-like environment for runtime scripts

## Setup

```bash
git clone <repo-url>
cd bifrost-rs
cargo check --workspace --offline
```

## Workflow

1. Pick a task from active project artifacts (`dev/plans/`, `dev/checklists/`, or a tracked issue).
2. Implement code + tests in a focused branch.
3. Run verification gates from `TESTING.md`.
4. Update docs/artifacts affected by the change.
5. Include concrete test evidence in the PR description.

## Coding Rules

- Prioritize cryptographic correctness and nonce safety.
- Do not silently change protocol behavior.
- Add tests for every behavioral change, especially negative-path tests.
- Keep public API changes synchronized with `docs/API.md`.

## Pull Requests

- Keep PRs focused and reviewable.
- Include:
  - problem statement
  - changes made
  - test evidence (commands + result)
  - docs/artifacts touched

## Documentation Requirements

If behavior changes:

1. Update root `README.md` if user-facing behavior changed.
2. Update repo-specific technical docs in `docs/` when crate behavior, runtime contracts, or utility formats change.
3. Do not duplicate general FROSTR protocol, cryptography, or glossary topics in this repo-local manual set.
3. Update release/audit artifacts (`RELEASE.md`, `dev/artifacts/current-status.md`, `dev/audit/*`) when relevant.
