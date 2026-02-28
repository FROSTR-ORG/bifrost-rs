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
  gen       Generate group/share/daemon config files in dev/data/
  start     Start relay + 3 daemons (alice/bob/carol)
  stop      Stop relay + daemons
  status    Show process status
  smoke     Run a local smoke flow (gen + start + CLI checks + stop)
USAGE
}

run_gen() {
  require_runtime_tools
  cargo run -p bifrost-devtools --offline -- keygen \
    --out-dir "${DEVNET_DIR}" \
    --threshold 2 \
    --count 3 \
    --relay "${RELAY_URL}" \
    --socket-dir /tmp
}

start_relay() {
  local existing
  existing="$(pgrep -f "bifrost-devtools.*relay.*${RELAY_PORT}" | head -n 1 || true)"
  if [[ -n "${existing}" ]]; then
    RELAY_PID="${existing}"
    echo "relay already running on ${RELAY_PORT}"
    return
  fi
  cargo run -p bifrost-devtools --offline -- relay "${RELAY_PORT}" \
    >"${LOG_DIR}/relay.log" 2>&1 &
  RELAY_PID=$!
  echo "started relay pid=${RELAY_PID}"
}

start_daemon() {
  local name="$1"
  local cfg="${DEVNET_DIR}/daemon-${name}.json"
  cargo run -p bifrostd --offline -- --config "${cfg}" \
    >"${LOG_DIR}/bifrostd-${name}.log" 2>&1 &
  local pid=$!
  echo "started bifrostd-${name} pid=${pid}"
  echo "BIFROSTD_${name^^}_PID=${pid}" >>"${PID_FILE}"
}

run_start() {
  require_runtime_tools
  : >"${PID_FILE}"
  start_relay
  echo "RELAY_PID=${RELAY_PID}" >>"${PID_FILE}"

  sleep 1
  start_daemon "alice"
  start_daemon "bob"
  start_daemon "carol"

  sleep 1
  echo "devnet started"
}

run_stop() {
  if [[ ! -f "${PID_FILE}" ]]; then
    echo "no pid file"
    return
  fi

  # shellcheck disable=SC1090
  source "${PID_FILE}"

  for var in RELAY_PID BIFROSTD_ALICE_PID BIFROSTD_BOB_PID BIFROSTD_CAROL_PID; do
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
    "bifrostd-alice:${BIFROSTD_ALICE_PID:-}" \
    "bifrostd-bob:${BIFROSTD_BOB_PID:-}" \
    "bifrostd-carol:${BIFROSTD_CAROL_PID:-}"; do
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
  run_start

  local socket="/tmp/bifrostd-alice.sock"
  cargo run -p bifrost-cli --offline -- --socket "${socket}" health
  cargo run -p bifrost-cli --offline -- --socket "${socket}" status
  cargo run -p bifrost-cli --offline -- --socket "${socket}" events 5

  run_stop
  echo "smoke complete"
}

cmd="${1:-}"
case "${cmd}" in
  gen) run_gen ;;
  start) run_start ;;
  stop) run_stop ;;
  status) run_status ;;
  smoke) run_smoke ;;
  *) usage; exit 1 ;;
esac
