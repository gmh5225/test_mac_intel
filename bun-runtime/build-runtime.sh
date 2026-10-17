#!/bin/bash
set -euo pipefail
cd /output/bun-source
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0=safe.directory
export GIT_CONFIG_VALUE_0=/output/bun-source
export BUN_BUILD_CACHE_DIR=/output/source-cache
export CARGO_BUILD_JOBS=2
export NINJA_STATUS='[%f/%t %e] '
# Public archive owners are unrelated to this disposable compiler UID.
# Keep extracted bytes/modes while avoiding root-only archive chown calls.
export TAR_OPTIONS=--no-same-owner
export LINUX_GLIBC_SYSROOT=/output/sysroot
test -d "$LINUX_GLIBC_SYSROOT/usr/include/c++/13"
command -v bun
bun --version
python3 --version
# A fresh build directory cannot reuse the image's Bun core object files.
# Public WebKit and other dependency artifacts remain subject to Bun's own
# pinned dependency graph; this is not a JavaScriptCore source-build claim.
# Compile PCRE2 with the same portable C sysroot before Cargo plans pcre2-sys.
native=/output/bun-source/recovery-native
mkdir "$native/pcre2-build"
cd "$native/pcre2-build"
CC="/usr/lib/llvm-current/bin/clang --sysroot=$LINUX_GLIBC_SYSROOT" \
  AR=/usr/lib/llvm-current/bin/llvm-ar RANLIB=/usr/lib/llvm-current/bin/llvm-ranlib \
  "$native/pcre2-source/configure" --prefix="$native/pcre2-install" \
  --disable-shared --enable-static --enable-jit --disable-pcre2-16 --disable-pcre2-32
make -j2
make check
make install
cd /output/bun-source
# Permit pkg-config to select the exact external source build. The sys crate's
# STATIC=1 means "ignore pkg-config and compile bundled PCRE2", not static link.
export PCRE2_SYS_STATIC=0
export PKG_CONFIG_ALL_STATIC=1
export PKG_CONFIG_PATH="$native/pcre2-install/lib/pkgconfig"
test "$(pkg-config --modversion libpcre2-8)" = 10.45
pkg-config --static --cflags --libs libpcre2-8
export GIT_CEILING_DIRECTORIES=/output/bun-source/recovery-native
# Both native bootstrap plans independently resolved this exact retained lock.
# Normal preparation and the complete build now remain locked from the start.
cp Cargo.lock /output/diagnostics/resolved-Cargo.lock
bun scripts/build.ts --profile=release --build-dir=/output/bun-source/build/recovery --target rust-plan -j2
python3 /recipes/verify_rust_plan.py build/recovery/rust-target/plan.json /output/diagnostics/single-rust-graph.json
bun scripts/build.ts --profile=release --build-dir=/output/bun-source/build/recovery -j4
