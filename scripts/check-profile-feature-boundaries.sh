#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cargo test --manifest-path "${ROOT_DIR}/Cargo.toml" -p bifrost-profile --no-default-features --offline
cargo test --manifest-path "${ROOT_DIR}/Cargo.toml" -p bifrost-profile-wasm --offline

echo "ok: bifrost-profile feature boundaries are intact"
