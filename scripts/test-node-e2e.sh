#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLCHAIN_PREFLIGHT="${ROOT_DIR}/dev/scripts/toolchain_preflight.sh"

"${TOOLCHAIN_PREFLIGHT}" --require-cargo >/dev/null

cargo run -p bifrost-dev --bin bifrost-devtools --offline -- e2e-node \
  --out-dir "${ROOT_DIR}/dev/data" \
  --relay "ws://127.0.0.1:8194"
