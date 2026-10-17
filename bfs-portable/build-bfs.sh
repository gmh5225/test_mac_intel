#!/bin/bash
set -euo pipefail
: "${RECOVERY_ARCH?}"
case "$RECOVERY_ARCH" in
  x64) triple=x86_64-linux-gnu; sysroot=/opt/linux-sysroot-glibc ;;
  arm64) triple=aarch64-linux-gnu; sysroot=/opt/linux-sysroot-glibc-arm64 ;;
  *) exit 64 ;;
esac
compiler=/usr/lib/llvm-23/bin/clang
test -x "$compiler"
"$compiler" --version
cmake --version
export HOME=/tmpfs/bun/home
export GIT_CEILING_DIRECTORIES=/tmpfs/bun
cmake -S /tmpfs/bun/embedded/oniguruma -B /tmpfs/bun/build/release/deps/oniguruma \
  -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DBUILD_TEST=ON \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_C_COMPILER="$compiler" \
  -DCMAKE_C_COMPILER_TARGET="$triple" -DCMAKE_SYSROOT="$sysroot"
cmake --build /tmpfs/bun/build/release/deps/oniguruma --parallel 2
ctest --test-dir /tmpfs/bun/build/release/deps/oniguruma --output-on-failure
cd /tmpfs/bun/embedded/bfs
export CC="$compiler --target=$triple --sysroot=$sysroot"
export CPPFLAGS='-Dposix_getdents=__bfs_poison_posix_getdents_musl_1_2_5 -Dgetdents64=__bfs_poison_getdents64_glibc_2_30 -Dposix_spawn_file_actions_addfchdir_np=__bfs_poison_addfchdir_np_glibc_2_29 -I/tmpfs/bun/embedded/oniguruma/src'
export LDFLAGS='-L/tmpfs/bun/build/release/deps/oniguruma -no-pie'
# The observed original flags link the privately built Oniguruma and contain
# no standalone Bfs LTO flag. Its pkg-config file is not installed in this tree.
export LDLIBS=-lonig
export LTO=0
export VERSION=4.1.1
export PKG_CONFIG_LIBDIR=/tmpfs/bun/no-host-pkgconfig
unset CFLAGS CXXFLAGS
./configure --enable-release --with-oniguruma --without-libselinux --without-libacl
make -j2 V=1
make -j2 check
./bin/bfs --version
