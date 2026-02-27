#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEVNET_SCRIPT="${ROOT_DIR}/scripts/devnet.sh"
CONFIG="${ROOT_DIR}/dev/data/daemon-alice.json"
OUT_DIR="${ROOT_DIR}/dev/data/logs"
OUT_FILE="${OUT_DIR}/tui-e2e-script-output.txt"
CMD_FILE="${OUT_DIR}/tui-e2e-commands.txt"
SOCKET="/tmp/bifrostd-alice.sock"

mkdir -p "${OUT_DIR}"

extract_first_peer() {
  awk -F'"' '
    /"peers"[[:space:]]*:/ { in_peers=1; next }
    in_peers && /"[0-9a-fA-F]+"/ { print $2; exit }
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
  local attempts=120
  while (( attempts > 0 )); do
    if [[ -S "${socket}" ]]; then
      return 0
    fi
    sleep 0.1
    attempts=$((attempts - 1))
  done
  echo "timed out waiting for socket: ${socket}" >&2
  exit 1
}

cleanup() {
  "${DEVNET_SCRIPT}" stop || true
}
trap cleanup EXIT INT TERM

"${DEVNET_SCRIPT}" gen
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
ping ${peer_pk}
echo ${peer_pk} tui-e2e
onboard ${peer_pk}
sign aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ecdh ${peer_pk}
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
