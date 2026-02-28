#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOLCHAIN_PREFLIGHT="${ROOT_DIR}/dev/scripts/toolchain_preflight.sh"
TEMPLATES_DIR="${ROOT_DIR}/dev/audit/templates"
WORK_DIR="${ROOT_DIR}/dev/audit/work"
EVIDENCE_DIR="${WORK_DIR}/evidence"
STATUS_FILE="${EVIDENCE_DIR}/automation-status.txt"

usage() {
  cat <<'EOF'
Usage: dev/scripts/audit_run.sh [--scaffold-only]

Runs the canonical audit workflow:
  1) rebuilds dev/audit/work from templates
  2) runs required command matrix
  3) stores deterministic evidence logs under dev/audit/work/evidence

Options:
  --scaffold-only   Only scaffold work files; skip command execution.
EOF
}

scaffold_only=0
if [[ "${1:-}" == "--scaffold-only" ]]; then
  scaffold_only=1
elif [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
elif [[ $# -gt 0 ]]; then
  echo "unknown option: $1" >&2
  usage >&2
  exit 1
fi

scaffold_work_dir() {
  rm -rf "${WORK_DIR}"
  mkdir -p "${WORK_DIR}" "${EVIDENCE_DIR}"

  cp "${TEMPLATES_DIR}/00-index.template.md" "${WORK_DIR}/00-index.md"
  cp "${TEMPLATES_DIR}/01-architecture.template.md" "${WORK_DIR}/01-architecture.md"
  cp "${TEMPLATES_DIR}/02-completeness.template.md" "${WORK_DIR}/02-completeness.md"
  cp "${TEMPLATES_DIR}/03-separation-boundaries.template.md" "${WORK_DIR}/03-separation-boundaries.md"
  cp "${TEMPLATES_DIR}/04-security.template.md" "${WORK_DIR}/04-security.md"
  cp "${TEMPLATES_DIR}/05-technical-debt.template.md" "${WORK_DIR}/05-technical-debt.md"
  cp "${TEMPLATES_DIR}/06-code-smell.template.md" "${WORK_DIR}/06-code-smell.md"
  cp "${TEMPLATES_DIR}/07-readability.template.md" "${WORK_DIR}/07-readability.md"
  cp "${TEMPLATES_DIR}/08-documentation.template.md" "${WORK_DIR}/08-documentation.md"
  cp "${TEMPLATES_DIR}/09-testing-quality.template.md" "${WORK_DIR}/09-testing-quality.md"
  cp "${TEMPLATES_DIR}/10-reliability-operability.template.md" "${WORK_DIR}/10-reliability-operability.md"
  cp "${TEMPLATES_DIR}/11-release-supply-chain.template.md" "${WORK_DIR}/11-release-supply-chain.md"
  cp "${TEMPLATES_DIR}/12-agent-assignments.template.md" "${WORK_DIR}/12-agent-assignments.md"
  cp "${TEMPLATES_DIR}/13-shared-notes.template.md" "${WORK_DIR}/13-shared-notes.md"
  cp "${TEMPLATES_DIR}/14-findings-log.template.md" "${WORK_DIR}/14-findings-log.md"
  cp "${TEMPLATES_DIR}/15-remediation-queue.template.md" "${WORK_DIR}/15-remediation-queue.md"
  cp "${TEMPLATES_DIR}/99-summary.template.md" "${WORK_DIR}/99-summary.md"
}

run_matrix() {
  "${TOOLCHAIN_PREFLIGHT}" --require-cargo --require-cargo-audit > "${EVIDENCE_DIR}/toolchain-preflight.log" 2>&1
  echo "preflight_exit:$?" > "${STATUS_FILE}"

  (
    cd "${ROOT_DIR}"
    set +e
    cargo fmt --all -- --check > "${EVIDENCE_DIR}/cargo-fmt-check.log" 2>&1
    echo "fmt_exit:$?" >> "${STATUS_FILE}"

    cargo clippy --workspace --all-targets --offline --no-deps > "${EVIDENCE_DIR}/cargo-clippy-workspace-offline.log" 2>&1
    echo "clippy_exit:$?" >> "${STATUS_FILE}"

    cargo check --workspace --offline > "${EVIDENCE_DIR}/cargo-check-workspace-offline.log" 2>&1
    echo "cargo_check_exit:$?" >> "${STATUS_FILE}"

    cargo test -p bifrost-core -p bifrost-codec -p bifrost-node -p bifrost-transport-ws --offline > "${EVIDENCE_DIR}/cargo-test-core-codec-node-ws-offline.log" 2>&1
    echo "cargo_test_core_exit:$?" >> "${STATUS_FILE}"

    cargo test -p bifrost-devtools -p bifrost-rpc --offline > "${EVIDENCE_DIR}/cargo-test-relay-rpc-offline.log" 2>&1
    echo "cargo_test_relay_exit:$?" >> "${STATUS_FILE}"

    scripts/test-node-e2e.sh > "${EVIDENCE_DIR}/test-node-e2e.log" 2>&1
    echo "node_e2e_exit:$?" >> "${STATUS_FILE}"

    scripts/test-tui-e2e.sh > "${EVIDENCE_DIR}/test-tui-e2e.log" 2>&1
    echo "tui_e2e_exit:$?" >> "${STATUS_FILE}"

    dev/scripts/planner_runbook.sh summary > "${EVIDENCE_DIR}/planner-summary.log" 2>&1
    echo "planner_summary_exit:$?" >> "${STATUS_FILE}"

    dev/scripts/planner_runbook.sh verify > "${EVIDENCE_DIR}/planner-verify.log" 2>&1
    echo "planner_verify_exit:$?" >> "${STATUS_FILE}"

    cargo audit > "${EVIDENCE_DIR}/cargo-audit.log" 2>&1
    echo "cargo_audit_exit:$?" >> "${STATUS_FILE}"
  )
}

scaffold_work_dir
echo "audit scaffold complete: ${WORK_DIR}"

if [[ "${scaffold_only}" -eq 1 ]]; then
  exit 0
fi

run_matrix
echo "audit command matrix complete: ${STATUS_FILE}"
cat "${STATUS_FILE}"
