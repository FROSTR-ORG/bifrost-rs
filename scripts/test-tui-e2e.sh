#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEVNET_SCRIPT="${ROOT_DIR}/scripts/devnet.sh"
TOOLCHAIN_PREFLIGHT="${ROOT_DIR}/dev/scripts/toolchain_preflight.sh"
CONFIG="${ROOT_DIR}/dev/data/bifrost-alice.json"
OUT_DIR="${ROOT_DIR}/dev/data/logs"
OUT_FILE="${OUT_DIR}/tui-e2e-output.txt"

mkdir -p "${OUT_DIR}"
"${TOOLCHAIN_PREFLIGHT}" --require-cargo >/dev/null

if ! command -v script >/dev/null 2>&1; then
  echo "script(1) is required for TUI e2e" >&2
  exit 1
fi

cleanup() {
  "${DEVNET_SCRIPT}" stop || true
}
trap cleanup EXIT INT TERM

"${DEVNET_SCRIPT}" gen
"${DEVNET_SCRIPT}" stop >/dev/null 2>&1 || true

cargo build -p bifrost-dev -p bifrost-app --offline >/dev/null

"${DEVNET_SCRIPT}" start-responders
sleep 2

set +e
timeout 5 script -q -c "cd '${ROOT_DIR}' && cargo run -p bifrost-dev --bin bifrost-tui --offline -- --config='${CONFIG}'" /dev/null >"${OUT_FILE}" 2>&1
rc=$?
set -e

if [[ "${rc}" -ne 124 ]]; then
  echo "tui did not remain running under timeout (rc=${rc})" >&2
  tail -n 120 "${OUT_FILE}" >&2 || true
  exit 1
fi

echo "tui e2e passed"
