#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLCHAIN_PREFLIGHT="${ROOT_DIR}/dev/scripts/toolchain_preflight.sh"
DEVNET_DIR="${ROOT_DIR}/dev/data"
STATE_DIR="${DEVNET_DIR}/.state"
LOG_DIR="${DEVNET_DIR}/logs"
PID_FILE="${STATE_DIR}/pids.env"
RELAY_PORT="${RELAY_PORT:-8194}"
RELAY_URL="ws://127.0.0.1:${RELAY_PORT}"

mkdir -p "${STATE_DIR}" "${LOG_DIR}"

require_runtime_tools() {
  "${TOOLCHAIN_PREFLIGHT}" --require-cargo >/dev/null
}

usage() {
  cat <<USAGE
Usage: scripts/devnet.sh <command>

Commands:
  gen       Generate group/share/runtime config files in dev/data/
  start     Start relay + 3 signer listeners (alice/bob/carol)
  start-responders  Start relay + responder listeners only (bob/carol)
  stop      Stop relay + listeners
  status    Show process status
  smoke     Run a local smoke flow (gen + responder start + command checks + stop)
USAGE
}

extract_first_peer() {
  local config_path="$1"
  awk -F'"' '
    /"peers"[[:space:]]*:/ { peers=1; next }
    peers && /"pubkey"[[:space:]]*:/ { print $4 }
    peers && /\]/ { exit }
  ' "${config_path}" | sort | head -n 1
}

run_gen() {
  require_runtime_tools
  rm -f "${DEVNET_DIR}"/state-*.json "${DEVNET_DIR}"/state-*.lock
  cargo run -p bifrost-dev --bin bifrost-devtools --offline -- keygen \
    --out-dir "${DEVNET_DIR}" \
    --threshold 2 \
    --count 3 \
    --relay "${RELAY_URL}"
}

start_relay() {
  local existing
  existing="$(pgrep -f "bifrost-devtools.*relay.*${RELAY_PORT}" | head -n 1 || true)"
  if [[ -n "${existing}" ]]; then
    RELAY_PID="${existing}"
    echo "relay already running on ${RELAY_PORT}"
    return
  fi
  cargo run -p bifrost-dev --bin bifrost-devtools --offline -- relay "${RELAY_PORT}" \
    >"${LOG_DIR}/relay.log" 2>&1 &
  RELAY_PID=$!
  echo "started relay pid=${RELAY_PID}"
}

start_listener() {
  local name="$1"
  local cfg="${DEVNET_DIR}/bifrost-${name}.json"
  cargo run -p bifrost-app --bin bifrost --offline -- --config "${cfg}" listen \
    >"${LOG_DIR}/bifrost-${name}.log" 2>&1 &
  local pid=$!
  echo "started bifrost-${name} pid=${pid}"
  echo "BIFROST_${name^^}_PID=${pid}" >>"${PID_FILE}"
}

run_start() {
  require_runtime_tools
  : >"${PID_FILE}"
  start_relay
  echo "RELAY_PID=${RELAY_PID}" >>"${PID_FILE}"

  sleep 1
  start_listener "alice"
  start_listener "bob"
  start_listener "carol"

  sleep 1
  echo "devnet started"
}

run_start_responders() {
  require_runtime_tools
  : >"${PID_FILE}"
  start_relay
  echo "RELAY_PID=${RELAY_PID}" >>"${PID_FILE}"

  sleep 1
  start_listener "bob"
  start_listener "carol"

  sleep 1
  echo "devnet responders started"
}

run_stop() {
  if [[ ! -f "${PID_FILE}" ]]; then
    echo "no pid file"
    return
  fi

  # shellcheck disable=SC1090
  source "${PID_FILE}"

  for var in RELAY_PID BIFROST_ALICE_PID BIFROST_BOB_PID BIFROST_CAROL_PID; do
    pid="${!var:-}"
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" || true
      wait "${pid}" 2>/dev/null || true
      echo "stopped ${var} (${pid})"
    fi
  done

  rm -f "${PID_FILE}"
}

run_status() {
  if [[ -f "${PID_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${PID_FILE}"
  fi

  for pair in \
    "relay:${RELAY_PID:-}" \
    "bifrost-alice:${BIFROST_ALICE_PID:-}" \
    "bifrost-bob:${BIFROST_BOB_PID:-}" \
    "bifrost-carol:${BIFROST_CAROL_PID:-}"; do
    name="${pair%%:*}"
    pid="${pair#*:}"
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      echo "${name}: running (${pid})"
    else
      echo "${name}: stopped"
    fi
  done
}

run_smoke() {
  require_runtime_tools
  run_gen
  run_start_responders

  local config="${DEVNET_DIR}/bifrost-alice.json"
  local peer
  peer="$(extract_first_peer "${config}")"
  if [[ -z "${peer}" ]]; then
    echo "failed to extract peer pubkey from ${config}" >&2
    run_stop
    exit 1
  fi

  run_cmd_with_retry() {
    local attempts="$1"
    local delay_secs="$2"
    shift 2
    local cmd=("$@")
    local try
    for ((try = 1; try <= attempts; try++)); do
      if "${cmd[@]}"; then
        return 0
      fi
      if [[ "${try}" -lt "${attempts}" ]]; then
        sleep "${delay_secs}"
      fi
    done
    return 1
  }

  cargo run -p bifrost-app --bin bifrost --offline -- --config "${config}" status
  cargo run -p bifrost-app --bin bifrost --offline -- --config "${config}" policies
  run_cmd_with_retry 5 1 \
    cargo run -p bifrost-app --bin bifrost --offline -- --config "${config}" ping "${peer}"
  run_cmd_with_retry 5 1 \
    cargo run -p bifrost-app --bin bifrost --offline -- --config "${config}" onboard "${peer}"
  cargo run -p bifrost-app --bin bifrost --offline -- --config "${config}" sign aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

  run_stop
  echo "smoke complete"
}

cmd="${1:-}"
case "${cmd}" in
  gen) run_gen ;;
  start) run_start ;;
  start-responders) run_start_responders ;;
  stop) run_stop ;;
  status) run_status ;;
  smoke) run_smoke ;;
  *) usage; exit 1 ;;
esac
