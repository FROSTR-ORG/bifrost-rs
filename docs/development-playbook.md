# Development Playbook

## Environment

- Rust workspace rooted at this repository.
- Primary crates: `bifrost-core`, `bifrost-codec`, `bifrost-transport`, `bifrost-node`, `bifrost-transport-ws`.

## Common Commands

- Format:
- `cargo fmt`
- Focused check:
- `cargo check -p bifrost-core -p bifrost-node --offline`
- Focused test:
- `cargo test -p bifrost-core -p bifrost-node --offline`
- Full workspace check (when deps available):
- `cargo check --workspace`

## Git Hygiene

- Root `.gitignore` is configured to ignore `target/` and common local artifacts.
- Confirm ignored artifacts:
- `git status --ignored`
- `??` means untracked (candidate source files).
- `!!` means ignored (expected build/temp files).

## Testing Discipline

- Any behavior change requires test coverage in corresponding crate.
- Security-sensitive paths need negative tests (tamper/malformed/replay).
- Keep tests local to crate unless cross-crate integration is required.

## Documentation Discipline

When behavior or public APIs change:

1. Update relevant docs in `/docs`.
2. Update planner files (`02`, `04`, `05`, `06`, `07` as needed).
3. Ensure README still reflects reality.
