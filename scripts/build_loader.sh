#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NDK_HOME="${ANDROID_NDK_HOME:-/home/hayawardh/android-sdk/ndk/android-ndk-r29}"
LIBBPF_PREFIX="${LIBBPF_PREFIX:-/home/hayawardh/android-prebuilt/aosp-bpfdeps-arm64}"
BUILD_DIR="${1:-$ROOT_DIR/loader/out/android-arm64}"

cmake -S "$ROOT_DIR/loader" -B "$BUILD_DIR" \
  -DCMAKE_TOOLCHAIN_FILE="$NDK_HOME/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=31 \
  -DLIBBPF_PREFIX="$LIBBPF_PREFIX"

cmake --build "$BUILD_DIR"

echo "Built $BUILD_DIR/binder_monitor_loader"
