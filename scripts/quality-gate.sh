#!/usr/bin/env bash
set -euo pipefail

QUICK=0
for arg in "$@"; do
  case "$arg" in
    --quick)
      QUICK=1
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      echo "Usage: $0 [--quick]" >&2
      exit 2
      ;;
  esac
done

run() {
  echo
  echo "==> $*"
  "$@"
}

echo "Running PMACS VPN quality gate..."

run cargo fmt --check
run cargo check
run cargo clippy --all-targets -- -D warnings
run cargo test --lib

if [[ "$QUICK" -eq 0 ]]; then
  run cargo test
fi

HOST_UNAME="$(uname -s 2>/dev/null || echo unknown)"
case "$HOST_UNAME" in
  Darwin)
    run cargo check --target aarch64-apple-darwin
    run cargo check --target x86_64-apple-darwin
    ;;
  Linux)
    run cargo check --target x86_64-unknown-linux-gnu
    ;;
  *)
    echo
    echo "Skipping host-specific target checks on $HOST_UNAME"
    ;;
esac

if [[ "${PMACS_ENABLE_WINDOWS_CROSS_CHECKS:-0}" == "1" ]]; then
  run cargo check --target x86_64-pc-windows-msvc
  run cargo check --target x86_64-pc-windows-gnu
else
  echo
  echo "Skipping Windows cross-target checks."
  echo "Set PMACS_ENABLE_WINDOWS_CROSS_CHECKS=1 to enable."
fi

echo
echo "Quality gate passed."
