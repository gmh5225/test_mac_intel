#!/bin/bash
set -euo pipefail
: "${RECOVERY_ARCH?}"
case "$RECOVERY_ARCH" in
  arm64) triple=arm64-apple-macosx; cpu=arm64 ;;
  x64) triple=x86_64-apple-macosx; cpu=x86_64 ;;
  *) exit 64 ;;
esac
llvm=/usr/lib/llvm-23/bin
sdk=/opt/macos-sdk/MacOSX26.5.sdk
test -f "$sdk/usr/include/sys/syscall.h"
"$llvm/clang" --version
cmake --version
export HOME=/tmpfs/bun/home
export GIT_CEILING_DIRECTORIES=/tmpfs/bun
export PKG_CONFIG_LIBDIR=/tmpfs/bun/no-host-pkgconfig
unset CFLAGS CXXFLAGS CPPFLAGS LDFLAGS LDLIBS
cmake -S /tmpfs/bun/embedded/oniguruma -B /tmpfs/bun/build/release/deps/oniguruma \
  -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DBUILD_TEST=ON \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_SYSTEM_NAME=Darwin \
  -DCMAKE_SYSTEM_PROCESSOR="$cpu" -DCMAKE_OSX_ARCHITECTURES="$cpu" \
  -DCMAKE_OSX_SYSROOT="$sdk" -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0 \
  -DCMAKE_C_COMPILER="$llvm/clang" -DCMAKE_C_COMPILER_TARGET="$triple" \
  -DCMAKE_AR="$llvm/llvm-ar" -DCMAKE_RANLIB="$llvm/llvm-ranlib" \
  "-DCMAKE_C_FLAGS=-mlinker-version=705 --ld-path=$llvm/ld64.lld"
cmake --build /tmpfs/bun/build/release/deps/oniguruma --parallel 2
cd /tmpfs/bun/embedded/bfs
export CC="$llvm/clang --target=$triple -isysroot $sdk -mmacosx-version-min=13.0 -mlinker-version=705 --ld-path=$llvm/ld64.lld"
export CPPFLAGS='-Dfdclosedir=__bfs_poison_fdclosedir_macos_26_4 -I/tmpfs/bun/embedded/oniguruma/src'
export LDFLAGS='-L/tmpfs/bun/build/release/deps/oniguruma'
export LDLIBS=-lonig
export LTO=0 VERSION=4.1.1 OS=Darwin
build_flags=(
  "XCPPFLAGS=-Isrc -Igen -include src/prelude.h -DNDEBUG -MD -MP -Wundef-prefix=BFS_ $CPPFLAGS"
  "XLDFLAGS=$LDFLAGS"
  # This measured flag value also feeds upstream's gen/ldlibs.i. Keep its
  # trailing space as a real configure/compiler input, without editing output.
  "XLDLIBS=-lonig "
)
./configure --enable-release --with-oniguruma --without-libselinux --without-libacl --without-liburing --without-libcap "${build_flags[@]}"
make -j2 V=1 all tests "${build_flags[@]}"
python3 /recipes/export_bfs_cross.py
