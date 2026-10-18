#!/bin/bash
set -euo pipefail
cd /output/bun-source
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0=safe.directory
export GIT_CONFIG_VALUE_0=/output/bun-source
export BUN_BUILD_CACHE_DIR=/output/source-cache
export LINUX_MUSL_SYSROOT="$RECOVERY_MUSL_SYSROOT"
export BUN_TOOLCHAIN_LLVM=/usr/lib/llvm-current
export RUSTUP_TOOLCHAIN=nightly-2026-09-15
export CARGO_BUILD_JOBS=2
export TAR_OPTIONS=--no-same-owner
export PCRE2_SYS_STATIC=0
export PKG_CONFIG_ALL_STATIC=1
export PKG_CONFIG_ALLOW_CROSS=1
export PKG_CONFIG_PATH=/output/bun-source/recovery-native/pcre2-install/lib/pkgconfig
export PKG_CONFIG_LIBDIR="$PKG_CONFIG_PATH"
export GIT_CEILING_DIRECTORIES=/output/bun-source/recovery-native
unset PKG_CONFIG_SYSROOT_DIR
bun --version
"$BUN_TOOLCHAIN_LLVM/bin/clang" --version
rustc -vV
test "$(pkg-config --modversion libpcre2-8)" = 10.45
pkg-config --static --cflags --libs libpcre2-8
args=(--profile=release --os=linux --arch="$BUN_TARGET_ARCH" --abi=musl --build-dir=/output/bun-source/build/recovery)
bun scripts/build.ts "${args[@]}" --target=rust-plan -j2
python3 /repo/bun-runtime/verify_rust_plan.py build/recovery/rust-target/plan.json /output/diagnostics/single-rust-graph.json
bun scripts/build.ts "${args[@]}" -j4
