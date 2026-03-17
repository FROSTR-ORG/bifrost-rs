#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

require_cargo=1
require_audit=0

usage() {
  cat <<'EOF'
Usage: dev/scripts/toolchain_preflight.sh [options]

Options:
  --require-cargo         Require cargo/rustc to be available (default).
  --require-cargo-audit   Require `cargo audit` subcommand availability.
  -h, --help              Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --require-cargo)
      require_cargo=1
      shift
      ;;
    --require-cargo-audit)
      require_audit=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

fail() {
  echo "toolchain preflight failed: $*" >&2
  exit 1
}

if [[ "${require_cargo}" -eq 1 ]]; then
  command -v cargo >/dev/null 2>&1 || fail "missing cargo in PATH. Install Rust toolchain (https://rustup.rs)."
  command -v rustc >/dev/null 2>&1 || fail "missing rustc in PATH. Install Rust toolchain (https://rustup.rs)."
fi

if [[ "${require_audit}" -eq 1 ]]; then
  cargo audit -V >/dev/null 2>&1 || fail "missing cargo-audit. Install with: cargo install cargo-audit --locked"
fi

echo "toolchain preflight ok: cargo=$(cargo --version) rustc=$(rustc --version)"
if [[ "${require_audit}" -eq 1 ]]; then
  echo "toolchain preflight ok: cargo-audit=$(cargo audit -V)"
fi
