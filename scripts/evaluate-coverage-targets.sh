#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/coverage-targets.env"

SUMMARY_FILE="${1:-}"

if [[ -z "${SUMMARY_FILE}" ]]; then
  SUMMARY_FILE="$(mktemp)"
  cargo llvm-cov report --summary-only > "${SUMMARY_FILE}"
  trap 'rm -f "${SUMMARY_FILE}"' EXIT
fi

if [[ ! -f "${SUMMARY_FILE}" ]]; then
  echo "coverage summary file not found: ${SUMMARY_FILE}" >&2
  exit 1
fi

TOTAL_LINE="$(awk '$1 == "TOTAL" { print $0 }' "${SUMMARY_FILE}")"
if [[ -z "${TOTAL_LINE}" ]]; then
  echo "TOTAL row not found in coverage summary" >&2
  exit 1
fi

REGIONS_PERCENT="$(awk '$1 == "TOTAL" { gsub(/%/, "", $4); print $4 }' "${SUMMARY_FILE}")"
LINES_PERCENT="$(awk '$1 == "TOTAL" { gsub(/%/, "", $10); print $10 }' "${SUMMARY_FILE}")"

check_target() {
  local actual="$1"
  local target="$2"
  awk -v actual="${actual}" -v target="${target}" 'BEGIN { exit !(actual + 0 >= target + 0) }'
}

REGIONS_STATUS="not_met"
LINES_STATUS="not_met"

if check_target "${REGIONS_PERCENT}" "${TARGET_REGIONS_PERCENT}"; then
  REGIONS_STATUS="met"
fi

if check_target "${LINES_PERCENT}" "${TARGET_LINES_PERCENT}"; then
  LINES_STATUS="met"
fi

cat <<EOF
coverage_baseline_regions_percent=${BASELINE_REGIONS_PERCENT}
coverage_baseline_lines_percent=${BASELINE_LINES_PERCENT}
coverage_target_regions_percent=${TARGET_REGIONS_PERCENT}
coverage_target_lines_percent=${TARGET_LINES_PERCENT}
coverage_actual_regions_percent=${REGIONS_PERCENT}
coverage_actual_lines_percent=${LINES_PERCENT}
coverage_regions_status=${REGIONS_STATUS}
coverage_lines_status=${LINES_STATUS}
EOF
