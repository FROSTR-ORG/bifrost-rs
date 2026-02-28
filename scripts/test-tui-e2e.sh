#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEVNET_SCRIPT="${ROOT_DIR}/scripts/devnet.sh"
TOOLCHAIN_PREFLIGHT="${ROOT_DIR}/dev/scripts/toolchain_preflight.sh"
CONFIG="${ROOT_DIR}/dev/data/daemon-alice.json"
OUT_DIR="${ROOT_DIR}/dev/data/logs"
OUT_FILE="${OUT_DIR}/tui-e2e-script-output.txt"
CMD_FILE="${OUT_DIR}/tui-e2e-commands.txt"
SOCKET="/tmp/bifrostd-alice.sock"
SOCKET_WAIT_TIMEOUT_SECS="${SOCKET_WAIT_TIMEOUT_SECS:-60}"
SOCKET_WAIT_INTERVAL_SECS="${SOCKET_WAIT_INTERVAL_SECS:-0.2}"

mkdir -p "${OUT_DIR}"
"${TOOLCHAIN_PREFLIGHT}" --require-cargo >/dev/null

extract_first_peer() {
  awk -F'"' '
    /"peers"[[:space:]]*:/ { in_peers=1; next }
    in_peers && /"pubkey"[[:space:]]*:/ { print $4; exit }
  ' "${CONFIG}"
}

assert_output_contains() {
  local needle="$1"
  if ! rg -F "${needle}" "${OUT_FILE}" >/dev/null 2>&1; then
    echo "assertion failed: missing '${needle}' in ${OUT_FILE}" >&2
    echo "--- output tail ---" >&2
    tail -n 120 "${OUT_FILE}" >&2 || true
    exit 1
  fi
}

assert_any_contains() {
  local first="$1"
  local second="$2"
  if rg -F "${first}" "${OUT_FILE}" >/dev/null 2>&1; then
    return 0
  fi
  if rg -F "${second}" "${OUT_FILE}" >/dev/null 2>&1; then
    return 0
  fi
  echo "assertion failed: missing both '${first}' and '${second}' in ${OUT_FILE}" >&2
  echo "--- output tail ---" >&2
  tail -n 120 "${OUT_FILE}" >&2 || true
  exit 1
}

wait_for_socket() {
  local socket="$1"
  local timeout_secs="${2:-${SOCKET_WAIT_TIMEOUT_SECS}}"
  local interval_secs="${3:-${SOCKET_WAIT_INTERVAL_SECS}}"
  local attempts
  attempts="$(awk "BEGIN { printf \"%d\", (${timeout_secs} / ${interval_secs}) }")"
  if [[ "${attempts}" -lt 1 ]]; then
    attempts=1
  fi
  while (( attempts > 0 )); do
    if [[ -S "${socket}" ]]; then
      return 0
    fi
    sleep "${interval_secs}"
    attempts=$((attempts - 1))
  done
  echo "timed out waiting for socket: ${socket} (timeout=${timeout_secs}s interval=${interval_secs}s)" >&2
  if [[ -f "${OUT_DIR}/bifrostd-alice.log" ]]; then
    echo "--- tail: ${OUT_DIR}/bifrostd-alice.log ---" >&2
    tail -n 80 "${OUT_DIR}/bifrostd-alice.log" >&2 || true
  fi
  if [[ -f "${OUT_DIR}/relay.log" ]]; then
    echo "--- tail: ${OUT_DIR}/relay.log ---" >&2
    tail -n 80 "${OUT_DIR}/relay.log" >&2 || true
  fi
  exit 1
}

cleanup() {
  "${DEVNET_SCRIPT}" stop || true
}
trap cleanup EXIT INT TERM

"${DEVNET_SCRIPT}" gen
"${DEVNET_SCRIPT}" stop >/dev/null 2>&1 || true

cargo build -p bifrost-devtools -p bifrostd -p bifrost-tui --offline >/dev/null

"${DEVNET_SCRIPT}" start
wait_for_socket "${SOCKET}"

peer_pk="$(extract_first_peer)"
if [[ -z "${peer_pk}" ]]; then
  echo "failed to extract peer pubkey from ${CONFIG}" >&2
  exit 1
fi

cat > "${CMD_FILE}" <<CMDS
health
status
events 5
use 1
ping bob
echo tui-e2e
onboard bob
sign hello
ecdh bob
CMDS

cargo run -p bifrost-tui --offline -- --socket "${SOCKET}" --script "${CMD_FILE}" > "${OUT_FILE}"

assert_output_contains '"ok": true'
assert_output_contains '"ready":'
assert_output_contains '"events"'
assert_output_contains '"version": 1'
assert_output_contains '"echo": "tui-e2e"'
assert_output_contains '"group"'
assert_output_contains '"signature"'
assert_output_contains '"shared_secret"'

echo "tui e2e passed"
