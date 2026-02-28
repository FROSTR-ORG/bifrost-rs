#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLCHAIN_PREFLIGHT="${ROOT_DIR}/dev/scripts/toolchain_preflight.sh"
DEVNET_DIR="${ROOT_DIR}/dev/data"
STATE_DIR="${DEVNET_DIR}/.state"
LOG_DIR="${DEVNET_DIR}/logs"
PID_FILE="${STATE_DIR}/cluster-pids.env"

CLUSTER_COUNT="${CLUSTER_COUNT:-5}"
THRESHOLD="${THRESHOLD:-3}"
RELAY_PORT="${RELAY_PORT:-8194}"
RELAY_URL="ws://127.0.0.1:${RELAY_PORT}"
SOCKET_DIR="${SOCKET_DIR:-/tmp}"

MEMBER_NAMES=(alice bob carol dave erin frank grace heidi)

mkdir -p "${STATE_DIR}" "${LOG_DIR}"

usage() {
  cat <<USAGE
Usage: scripts/devnet-cluster.sh <command>

Commands:
  gen       Generate group/share/daemon configs for CLUSTER_COUNT members
  start     Start relay + CLUSTER_COUNT daemons
  stop      Stop relay + daemons from prior start
  status    Show relay/daemon process status
  smoke     Run gen+start and basic CLI checks against first daemon, then stop

Environment:
  CLUSTER_COUNT   default: 5 (max 8)
  THRESHOLD       default: 3
  RELAY_PORT      default: 8194
  SOCKET_DIR      default: /tmp
USAGE
}

require_runtime_tools() {
  "${TOOLCHAIN_PREFLIGHT}" --require-cargo >/dev/null
}

selected_names() {
  local count="$1"
  if (( count < 2 )); then
    echo "CLUSTER_COUNT must be >= 2" >&2
    exit 1
  fi
  if (( count > ${#MEMBER_NAMES[@]} )); then
    echo "CLUSTER_COUNT exceeds max ${#MEMBER_NAMES[@]}" >&2
    exit 1
  fi
  for ((i = 0; i < count; i++)); do
    echo "${MEMBER_NAMES[$i]}"
  done
}

run_gen() {
  require_runtime_tools
  cargo run -p bifrost-devtools --offline -- keygen \
    --out-dir "${DEVNET_DIR}" \
    --threshold "${THRESHOLD}" \
    --count "${CLUSTER_COUNT}" \
    --relay "${RELAY_URL}" \
    --socket-dir "${SOCKET_DIR}"
}

start_relay() {
  local existing
  existing="$(pgrep -f "bifrost-devtools.*relay.*${RELAY_PORT}" | head -n 1 || true)"
  if [[ -n "${existing}" ]]; then
    RELAY_PID="${existing}"
    echo "relay already running on ${RELAY_PORT}"
    return
  fi
  cargo run -p bifrost-devtools --offline -- relay "${RELAY_PORT}" >"${LOG_DIR}/relay.log" 2>&1 &
  RELAY_PID=$!
  echo "started relay pid=${RELAY_PID}"
}

start_daemon() {
  local name="$1"
  local cfg="${DEVNET_DIR}/daemon-${name}.json"
  cargo run -p bifrostd --offline -- --config "${cfg}" >"${LOG_DIR}/bifrostd-${name}.log" 2>&1 &
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
  while IFS= read -r name; do
    start_daemon "${name}"
  done < <(selected_names "${CLUSTER_COUNT}")

  sleep 1
  echo "cluster started (${CLUSTER_COUNT} nodes)"
}

run_stop() {
  if [[ ! -f "${PID_FILE}" ]]; then
    echo "no cluster pid file"
    return
  fi

  # shellcheck disable=SC1090
  source "${PID_FILE}"

  if [[ -n "${RELAY_PID:-}" ]] && kill -0 "${RELAY_PID}" 2>/dev/null; then
    kill "${RELAY_PID}" || true
    wait "${RELAY_PID}" 2>/dev/null || true
    echo "stopped relay (${RELAY_PID})"
  fi

  while IFS= read -r name; do
    local var="BIFROSTD_${name^^}_PID"
    local pid="${!var:-}"
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" || true
      wait "${pid}" 2>/dev/null || true
      echo "stopped bifrostd-${name} (${pid})"
    fi
  done < <(selected_names "${CLUSTER_COUNT}")

  rm -f "${PID_FILE}"
}

run_status() {
  if [[ -f "${PID_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${PID_FILE}"
  fi

  if [[ -n "${RELAY_PID:-}" ]] && kill -0 "${RELAY_PID}" 2>/dev/null; then
    echo "relay: running (${RELAY_PID})"
  else
    echo "relay: stopped"
  fi

  while IFS= read -r name; do
    local var="BIFROSTD_${name^^}_PID"
    local pid="${!var:-}"
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      echo "bifrostd-${name}: running (${pid})"
    else
      echo "bifrostd-${name}: stopped"
    fi
  done < <(selected_names "${CLUSTER_COUNT}")
}

run_smoke() {
  require_runtime_tools
  run_gen
  run_start

  local first_name
  first_name="$(selected_names "${CLUSTER_COUNT}" | head -n 1)"
  local socket="${SOCKET_DIR}/bifrostd-${first_name}.sock"
  cargo run -p bifrost-cli --offline -- --socket "${socket}" health
  cargo run -p bifrost-cli --offline -- --socket "${socket}" status
  cargo run -p bifrost-cli --offline -- --socket "${socket}" events 5

  run_stop
  echo "cluster smoke complete"
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
