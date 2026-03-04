#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SESSION_NAME="bifrost-rs-demo"
DEVNET_SCRIPT="${ROOT_DIR}/scripts/devnet.sh"
LOG_DIR="${ROOT_DIR}/dev/data/logs"
CONFIG_DIR="${ROOT_DIR}/dev/data"

usage() {
  cat <<USAGE
Usage: scripts/devnet-tmux.sh <command> [--no-attach]

Commands:
  start [--no-attach]   Generate/start devnet and open tmux layout
  stop                  Stop tmux session and devnet processes
  status                Show tmux + devnet status
USAGE
}

ensure_tmux() {
  if ! command -v tmux >/dev/null 2>&1; then
    echo "tmux is required" >&2
    exit 1
  fi
}

create_layout() {
  local no_attach="$1"

  tmux new-session -d -s "${SESSION_NAME}" -n demo \
    "cd '${ROOT_DIR}' && bash"
  tmux split-window -h -t "${SESSION_NAME}:demo.0"
  tmux split-window -v -t "${SESSION_NAME}:demo.0"
  tmux split-window -v -t "${SESSION_NAME}:demo.1"
  tmux select-layout -t "${SESSION_NAME}:demo" tiled

  tmux send-keys -t "${SESSION_NAME}:demo.0" \
    "cd '${ROOT_DIR}' && clear && echo 'Relay log (Ctrl+b d to detach)' && exec tail -n +1 -f '${LOG_DIR}/relay.log'" C-m
  tmux send-keys -t "${SESSION_NAME}:demo.1" \
    "cd '${ROOT_DIR}' && clear && exec cargo run -p bifrost-app --bin bifrost --offline -- --config '${CONFIG_DIR}/bifrost-alice.json' listen" C-m
  tmux send-keys -t "${SESSION_NAME}:demo.2" \
    "cd '${ROOT_DIR}' && clear && exec cargo run -p bifrost-app --bin bifrost --offline -- --config '${CONFIG_DIR}/bifrost-bob.json' listen" C-m
  tmux send-keys -t "${SESSION_NAME}:demo.3" \
    "cd '${ROOT_DIR}' && clear && exec cargo run -p bifrost-app --bin bifrost --offline -- --config '${CONFIG_DIR}/bifrost-carol.json' listen" C-m

  tmux select-pane -t "${SESSION_NAME}:demo.1"

  if [[ "${no_attach}" == "1" ]]; then
    echo "tmux session created: ${SESSION_NAME}"
    echo "attach with: tmux attach -t ${SESSION_NAME}"
  else
    tmux attach-session -t "${SESSION_NAME}" || true
  fi
}

start_cmd() {
  local no_attach="0"
  if [[ "${1:-}" == "--no-attach" ]]; then
    no_attach="1"
  fi

  ensure_tmux

  if tmux has-session -t "${SESSION_NAME}" 2>/dev/null; then
    tmux kill-session -t "${SESSION_NAME}" || true
  fi

  "${DEVNET_SCRIPT}" gen
  "${DEVNET_SCRIPT}" start

  cleanup() {
    "${DEVNET_SCRIPT}" stop || true
    if tmux has-session -t "${SESSION_NAME}" 2>/dev/null; then
      tmux kill-session -t "${SESSION_NAME}" || true
    fi
  }

  if [[ "${no_attach}" == "1" ]]; then
    create_layout "1"
    return
  fi

  trap cleanup EXIT INT TERM
  create_layout "0"
}

stop_cmd() {
  ensure_tmux
  if tmux has-session -t "${SESSION_NAME}" 2>/dev/null; then
    tmux kill-session -t "${SESSION_NAME}" || true
  fi
  "${DEVNET_SCRIPT}" stop || true
}

status_cmd() {
  ensure_tmux
  if tmux has-session -t "${SESSION_NAME}" 2>/dev/null; then
    echo "tmux: running (${SESSION_NAME})"
  else
    echo "tmux: stopped"
  fi
  "${DEVNET_SCRIPT}" status
}

cmd="${1:-}"
case "${cmd}" in
  start)
    shift
    start_cmd "${1:-}"
    ;;
  stop)
    stop_cmd
    ;;
  status)
    status_cmd
    ;;
  *)
    usage
    exit 1
    ;;
esac
