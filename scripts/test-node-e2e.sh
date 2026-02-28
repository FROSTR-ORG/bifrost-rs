#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEVNET_SCRIPT="${ROOT_DIR}/scripts/devnet.sh"
TOOLCHAIN_PREFLIGHT="${ROOT_DIR}/dev/scripts/toolchain_preflight.sh"
DEVNET_DIR="${ROOT_DIR}/dev/data"
ALICE_SOCKET="/tmp/bifrostd-alice.sock"
ALICE_CFG="${DEVNET_DIR}/daemon-alice.json"
OUT_DIR="${DEVNET_DIR}/logs"
OUT_FILE="${OUT_DIR}/node-e2e-output.txt"
SOCKET_WAIT_TIMEOUT_SECS="${SOCKET_WAIT_TIMEOUT_SECS:-60}"
SOCKET_WAIT_INTERVAL_SECS="${SOCKET_WAIT_INTERVAL_SECS:-0.2}"

mkdir -p "${OUT_DIR}"
: >"${OUT_FILE}"
"${TOOLCHAIN_PREFLIGHT}" --require-cargo >/dev/null

log() {
  echo "[node-e2e] $*"
}

run_cli() {
  local label="$1"
  shift

  {
    echo "\n### ${label}"
    echo "$ cargo run -p bifrost-cli --offline -- --socket ${ALICE_SOCKET} $*"
  } >>"${OUT_FILE}"

  cargo run -p bifrost-cli --offline -- --socket "${ALICE_SOCKET}" "$@" >>"${OUT_FILE}" 2>&1 || true
}

assert_file_exists() {
  local f="$1"
  if [[ ! -f "${f}" ]]; then
    echo "missing expected file: ${f}" >&2
    exit 1
  fi
}

assert_output_contains() {
  local needle="$1"
  if ! rg -F "${needle}" "${OUT_FILE}" >/dev/null 2>&1; then
    echo "assertion failed: missing '${needle}' in ${OUT_FILE}" >&2
    tail -n 160 "${OUT_FILE}" >&2 || true
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
  tail -n 160 "${OUT_FILE}" >&2 || true
  exit 1
}

extract_first_peer() {
  awk -F'"' '
    /"peers"[[:space:]]*:/ { in_peers=1; next }
    in_peers && /"pubkey"[[:space:]]*:/ { print $4; exit }
  ' "${ALICE_CFG}"
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

log "generating keyset + share distribution"
"${DEVNET_SCRIPT}" gen
"${DEVNET_SCRIPT}" stop >/dev/null 2>&1 || true

log "warming runtime binaries (cold-start stabilization)"
cargo build -p bifrost-devtools -p bifrostd -p bifrost-cli --offline >/dev/null

# Distribution/material checks
assert_file_exists "${DEVNET_DIR}/group.json"
assert_file_exists "${DEVNET_DIR}/share-alice.json"
assert_file_exists "${DEVNET_DIR}/share-bob.json"
assert_file_exists "${DEVNET_DIR}/share-carol.json"
assert_file_exists "${DEVNET_DIR}/daemon-alice.json"
assert_file_exists "${DEVNET_DIR}/daemon-bob.json"
assert_file_exists "${DEVNET_DIR}/daemon-carol.json"

peer_pk="$(extract_first_peer)"
if [[ -z "${peer_pk}" ]]; then
  echo "failed to extract peer pubkey from ${ALICE_CFG}" >&2
  exit 1
fi

log "starting devnet daemons"
"${DEVNET_SCRIPT}" start
wait_for_socket "${ALICE_SOCKET}"

log "running bifrost-node e2e RPC flow through bifrostd"
run_cli "health" health
run_cli "status" status
run_cli "events" events 8
run_cli "ping" ping "${peer_pk}"
run_cli "echo" echo "${peer_pk}" "node-e2e"
run_cli "onboard" onboard "${peer_pk}"
run_cli "sign" sign aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
run_cli "ecdh" ecdh "${peer_pk}"

# Baseline assertions
assert_output_contains '"ok": true'
assert_output_contains '"ready":'
assert_output_contains '"events"'

# Method assertions (healthy devnet must succeed)
assert_output_contains '"version": 1'
assert_output_contains '"echo": "node-e2e"'
assert_output_contains '"group"'
assert_output_contains '"signature"'
assert_output_contains '"shared_secret"'

log "node e2e passed"
echo "node e2e passed"
