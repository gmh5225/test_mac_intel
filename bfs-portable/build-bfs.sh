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
id
getent passwd "$(id -u)"
getent group "$(id -g)"
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
# These are real inputs to the compiler/linker and to Bfs's generated metadata.
# Keep component flags separate from Bun's outer compatibility link below.
build_flags=(
  "XCPPFLAGS=-Isrc -Igen -include src/prelude.h -DNDEBUG -MD -MP -Wundef-prefix=BFS_ $CPPFLAGS"
  "XLDFLAGS=-Wl,-z,now $LDFLAGS"
  "XLDLIBS=-lonig -lrt"
)
./configure --enable-release --with-oniguruma --without-libselinux --without-libacl "${build_flags[@]}"
make -j2 V=1 "${build_flags[@]}"
./bin/bfs --version
./bin/bfs --version > /tmpfs/bun/standalone/component-version.stdout
cxx=/usr/lib/llvm-23/bin/clang++
"$cxx" --target="$triple" --sysroot="$sysroot" -std=c++20 -O2 -ffunction-sections -fdata-sections -c \
  /tmpfs/bun/standalone/compat.cpp -o /tmpfs/bun/standalone/compat.o
outer_flags=(-Wl,--wrap=fcntl64 -Wl,--wrap=statx -Wl,--gc-sections -static-libstdc++ -static-libgcc -pthread -ldl)
objects=(obj/src/*.o)
"$cxx" --target="$triple" --sysroot="$sysroot" -Wl,-z,now -no-pie \
  "${objects[@]}" /tmpfs/bun/standalone/compat.o \
  -L/tmpfs/bun/build/release/deps/oniguruma -lonig -lrt \
  "${outer_flags[@]}" -Wl,-Map=/tmpfs/bun/standalone/bfs-link.map -o /tmpfs/bun/standalone/bfs
/tmpfs/bun/standalone/bfs --version > /tmpfs/bun/standalone/outer-version.stdout
cmp /tmpfs/bun/standalone/component-version.stdout /tmpfs/bun/standalone/outer-version.stdout
for variant in native fallback; do
  extra=()
  if [ "$variant" = fallback ]; then extra=(-DRECOVERY_FORCE_OLD_FCNTL=1); fi
  "$compiler" --target="$triple" --sysroot="$sysroot" -std=c11 -O2 "${extra[@]}" \
    -c /recipes/compat-probe.c -o /tmpfs/bun/standalone/probe.o
  "$cxx" --target="$triple" --sysroot="$sysroot" /tmpfs/bun/standalone/probe.o \
    /tmpfs/bun/standalone/compat.o "${outer_flags[@]}" -Wl,--wrap=dlsym \
    -o /tmpfs/bun/standalone/compat-probe
  /tmpfs/bun/standalone/compat-probe
done
cp /tmpfs/bun/standalone/bfs ./bin/bfs
make -j2 check "${build_flags[@]}"
