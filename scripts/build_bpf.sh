#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLANG_BIN="${CLANG_BIN:-clang}"
OUT_PATH="${1:-$ROOT_DIR/kernel/binder_monitor.bpf.o}"

"$CLANG_BIN" \
  -target bpf \
  -D__TARGET_ARCH_arm64 \
  -O2 -g -Wall -Werror \
  -I"$ROOT_DIR" \
  -I/usr/include/x86_64-linux-gnu \
  -c "$ROOT_DIR/kernel/binder_monitor.bpf.c" \
  -o "$OUT_PATH"

echo "Built $OUT_PATH"
