#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BACKLOG_FILE="${ROOT_DIR}/dev/planner/04-backlog.md"
MILESTONES_FILE="${ROOT_DIR}/dev/planner/03-milestones.md"
TOOLCHAIN_PREFLIGHT="${ROOT_DIR}/dev/scripts/toolchain_preflight.sh"

usage() {
  cat <<'EOF'
Usage: dev/scripts/planner_runbook.sh <command> [args]

Commands:
  summary
      Show planner task counts by status and milestone.

  next
      Show next executable tasks (in_progress first, then todo with satisfied deps).

  list
      Print all planner tasks in backlog order.

  set-status <TASK_ID> <todo|in_progress|blocked|done>
      Update backlog status for a task.

  verify
      Run current baseline verification commands used by planner execution.

  milestone
      Print milestone status lines from dev/planner/03-milestones.md.
EOF
}

require_backlog() {
  if [[ ! -f "${BACKLOG_FILE}" ]]; then
    echo "missing backlog file: ${BACKLOG_FILE}" >&2
    exit 1
  fi
}

# Output records:
# TASK_ID|MILESTONE|STATUS|DEPENDS_ON|OWNER|DESCRIPTION|EVIDENCE
extract_tasks() {
  awk -F'|' '
    function clean(s) {
      gsub(/^[ \t]+|[ \t]+$/, "", s)
      gsub(/`/, "", s)
      return s
    }
    $0 ~ /^\| `M[0-9]+-[0-9][0-9][0-9]`/ {
      id=clean($2)
      milestone=clean($3)
      desc=clean($4)
      owner=clean($5)
      status=clean($6)
      dep=clean($7)
      evidence=clean($8)
      print id "|" milestone "|" status "|" dep "|" owner "|" desc "|" evidence
    }
  ' "${BACKLOG_FILE}"
}

summary() {
  require_backlog
  local total
  total="$(extract_tasks | wc -l | tr -d ' ')"
  echo "Planner task summary"
  echo "  total: ${total}"
  echo
  echo "By status:"
  extract_tasks | awk -F'|' '
    { c[$3]++ }
    END {
      printf "  todo: %d\n", c["todo"]+0
      printf "  in_progress: %d\n", c["in_progress"]+0
      printf "  blocked: %d\n", c["blocked"]+0
      printf "  done: %d\n", c["done"]+0
    }
  '
  echo
  echo "By milestone:"
  extract_tasks | awk -F'|' '
    { c[$2]++ }
    END {
      for (m in c) {
        printf "  %s: %d\n", m, c[m]
      }
    }
  ' | sort
}

list_tasks() {
  require_backlog
  printf "%-8s %-4s %-12s %-12s %s\n" "TASK_ID" "MS" "STATUS" "DEPENDS_ON" "DESCRIPTION"
  extract_tasks | while IFS='|' read -r id ms st dep owner desc evidence; do
    printf "%-8s %-4s %-12s %-12s %s\n" "${id}" "${ms}" "${st}" "${dep}" "${desc}"
  done
}

next_tasks() {
  require_backlog
  mapfile -t done_ids < <(extract_tasks | awk -F'|' '$3=="done"{print $1}')

  is_done() {
    local needle="$1"
    local d
    for d in "${done_ids[@]}"; do
      [[ "${d}" == "${needle}" ]] && return 0
    done
    return 1
  }

  dep_satisfied() {
    local dep_raw="$1"
    dep_raw="${dep_raw// /}"
    if [[ "${dep_raw}" == "none" || -z "${dep_raw}" ]]; then
      return 0
    fi
    if [[ "${dep_raw}" =~ ^M[0-9]+-[0-9]{3}$ ]]; then
      is_done "${dep_raw}"
      return $?
    fi
    if [[ "${dep_raw}" == *","* ]]; then
      IFS=',' read -r -a deps <<< "${dep_raw}"
      local d
      for d in "${deps[@]}"; do
        if [[ "${d}" =~ ^M[0-9]+-[0-9]{3}$ ]]; then
          is_done "${d}" || return 1
        else
          return 1
        fi
      done
      return 0
    fi
    return 1
  }

  echo "Next executable tasks"
  echo
  echo "In progress:"
  local any_in_progress=0
  while IFS='|' read -r id ms st dep owner desc evidence; do
    if [[ "${st}" == "in_progress" ]]; then
      any_in_progress=1
      printf "  - %s (%s): %s\n" "${id}" "${ms}" "${desc}"
    fi
  done < <(extract_tasks)
  if [[ "${any_in_progress}" -eq 0 ]]; then
    echo "  (none)"
  fi

  echo
  echo "Ready (todo + deps satisfied):"
  local any_ready=0
  while IFS='|' read -r id ms st dep owner desc evidence; do
    if [[ "${st}" == "todo" ]] && dep_satisfied "${dep}"; then
      any_ready=1
      printf "  - %s (%s): %s [depends_on=%s]\n" "${id}" "${ms}" "${desc}" "${dep}"
    fi
  done < <(extract_tasks)
  if [[ "${any_ready}" -eq 0 ]]; then
    echo "  (none)"
  fi
}

set_status() {
  require_backlog
  local task_id="${1:-}"
  local new_status="${2:-}"
  if [[ -z "${task_id}" || -z "${new_status}" ]]; then
    echo "set-status requires TASK_ID and STATUS" >&2
    exit 1
  fi
  case "${new_status}" in
    todo|in_progress|blocked|done) ;;
    *)
      echo "invalid status: ${new_status}" >&2
      exit 1
      ;;
  esac

  awk -v task="${task_id}" -v st="${new_status}" -F'|' '
    BEGIN { updated=0; OFS="|" }
    function clean(s) {
      gsub(/^[ \t]+|[ \t]+$/, "", s)
      gsub(/`/, "", s)
      return s
    }
    {
      if ($0 ~ /^\| `M[0-9]+-[0-9][0-9][0-9]`/) {
        id=clean($2)
        if (id == task) {
          $6 = " " st " "
          updated=1
        }
      }
      print $0
    }
    END {
      if (updated == 0) {
        exit 42
      }
    }
  ' "${BACKLOG_FILE}" > "${BACKLOG_FILE}.tmp" || {
    rc=$?
    rm -f "${BACKLOG_FILE}.tmp"
    if [[ ${rc} -eq 42 ]]; then
      echo "task not found: ${task_id}" >&2
    fi
    exit 1
  }
  mv "${BACKLOG_FILE}.tmp" "${BACKLOG_FILE}"
  echo "updated ${task_id} -> ${new_status}"
}

verify() {
  "${TOOLCHAIN_PREFLIGHT}" --require-cargo
  echo "Running baseline verification..."
  (cd "${ROOT_DIR}" && cargo fmt --all -- --check)
  (cd "${ROOT_DIR}" && cargo clippy --workspace --all-targets --offline --no-deps)
  (cd "${ROOT_DIR}" && cargo check -p bifrost-codec -p bifrost-core -p bifrost-node --offline)
  (cd "${ROOT_DIR}" && cargo test -p bifrost-codec -p bifrost-core -p bifrost-node --offline)
  (cd "${ROOT_DIR}" && cargo check -p bifrost-devtools -p bifrostd -p bifrost-cli -p bifrost-tui --offline)
  (cd "${ROOT_DIR}" && cargo test -p bifrost-devtools -p bifrost-rpc --offline)
  echo "Verification complete."
}

milestone() {
  if [[ ! -f "${MILESTONES_FILE}" ]]; then
    echo "missing milestones file: ${MILESTONES_FILE}" >&2
    exit 1
  fi
  awk '
    $0 ~ /^## M[0-9]+:/ { print; next }
    $0 ~ /^- Status:/ { print }
  ' "${MILESTONES_FILE}"
}

cmd="${1:-}"
case "${cmd}" in
  summary) summary ;;
  next) next_tasks ;;
  list) list_tasks ;;
  set-status) shift; set_status "${1:-}" "${2:-}" ;;
  verify) verify ;;
  milestone) milestone ;;
  *) usage; exit 1 ;;
esac
