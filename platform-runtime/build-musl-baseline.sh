#!/bin/bash
set -euo pipefail
cd /output/bun-source
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0=safe.directory
export GIT_CONFIG_VALUE_0=/output/bun-source
export BUN_BUILD_CACHE_DIR=/output/source-cache
export LINUX_MUSL_SYSROOT=/output/sysroot
export BUN_TOOLCHAIN_LLVM=/usr/lib/llvm-current
export RUSTUP_TOOLCHAIN=nightly-2026-09-15
export CARGO_BUILD_JOBS=2
export TAR_OPTIONS=--no-same-owner
bun --version
"$BUN_TOOLCHAIN_LLVM/bin/clang" --version
"$BUN_TOOLCHAIN_LLVM/bin/llvm-nm" --version
"$BUN_TOOLCHAIN_LLVM/bin/ld.lld" --version
rustc -vV
"$BUN_TOOLCHAIN_LLVM/bin/clang" --target="$MUSL_TARGET" --sysroot="$LINUX_MUSL_SYSROOT" \
  -fsyntax-only -x c - <<'C'
#include <stdio.h>
#include <pthread.h>
int main(void) { return 0; }
C
bun scripts/build.ts --profile=release --os=linux --arch="$BUN_TARGET_ARCH" --abi=musl \
  --build-dir=/output/bun-source/build/recovery -j4
