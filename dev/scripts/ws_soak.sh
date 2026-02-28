#!/usr/bin/env bash
set -euo pipefail

ITERATIONS=25
OUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --iterations)
      ITERATIONS="${2:?missing value for --iterations}"
      shift 2
      ;;
    --out)
      OUT="${2:?missing value for --out}"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if ! [[ "$ITERATIONS" =~ ^[0-9]+$ ]] || [[ "$ITERATIONS" -lt 1 ]]; then
  echo "--iterations must be a positive integer" >&2
  exit 1
fi

if [[ -z "$OUT" ]]; then
  OUT="dev/audit/work/evidence/ws-soak-$(date +%F-%H%M%S).txt"
fi

mkdir -p "$(dirname "$OUT")"

run() {
  echo "$ $*"
  "$@"
}

run_with_retry() {
  local retries="$1"
  shift
  local attempt=1
  while true; do
    echo "$ $* (attempt $attempt/$retries)"
    if "$@"; then
      return 0
    fi
    if [[ "$attempt" -ge "$retries" ]]; then
      return 1
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
}

{
  echo "ws soak started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "iterations: $ITERATIONS"

  run dev/scripts/toolchain_preflight.sh --require-cargo

  for i in $(seq 1 "$ITERATIONS"); do
    echo "--- ws failover forced-fault iteration $i/$ITERATIONS ---"
    run cargo test -p bifrost-transport-ws --offline connect_failover_forced_fault_records_relay_health
  done

  echo "--- ws nip44 deterministic regression ---"
  run cargo test -p bifrost-transport-ws --offline nip44_deterministic_matrix_and_mutation_rejects

  echo "--- runtime smoke regression ---"
  run scripts/devnet.sh smoke

  echo "ws soak completed: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} 2>&1 | tee "$OUT"
