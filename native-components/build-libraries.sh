#!/bin/bash
set -euo pipefail
: "${RECOVERY_NATIVE_TARGET?}"
export RUSTUP_TOOLCHAIN=nightly-2026-09-15
export CARGO_HOME=/build/cargo-home
export CARGO_TARGET_DIR=/build/target
export CARGO_BUILD_JOBS=2
export BUN_RUNTIME_TRANSPILER_CACHE_PATH=0
export GIT_CEILING_DIRECTORIES=/build
unset RIPGREP_BUILD_GIT_HASH
rustc --version --verbose
cargo --version --verbose
cc --version
export PCRE2_SYS_STATIC=0
export PKG_CONFIG_PATH=/build/install/lib/pkgconfig
export PKG_CONFIG_ALL_STATIC=1
mkdir /build/pcre2-build
cd /build/pcre2-build
/build/pcre2/configure --prefix=/build/install --disable-shared --enable-static --enable-jit --disable-pcre2-16 --disable-pcre2-32
make -j2
make check
make install
test "$(pkg-config --modversion libpcre2-8)" = 10.45
cd /build/ripgrep
export RUSTFLAGS='-C panic=abort'
if [ "$RECOVERY_NATIVE_TARGET" = x86_64-unknown-linux-gnu ]; then
  RUSTFLAGS+=' -C target-feature=+ssse3,-avx2'
fi
cargo build --release --lib --features pcre2 --locked --offline --target "$RECOVERY_NATIVE_TARGET"
mkdir /build/rust-libs
cp "/build/target/$RECOVERY_NATIVE_TARGET/release/deps/"*.rlib /build/rust-libs/
cc -O2 -Wall -Wextra -Werror -Dmain=neverd_recovered_seccomp_main -I/build/seccomp-source -c /build/seccomp-source/apply-seccomp.c -o /build/seccomp-source/apply-seccomp.o
link_args=('-C' 'link-arg=-Wl,--start-group')
for archive in /build/rust-libs/*.rlib; do
  link_args+=('-C' "link-arg=$archive")
done
link_args+=('-C' 'link-arg=/build/seccomp-source/apply-seccomp.o' '-C' 'link-arg=-Wl,--end-group')
rustc --edition=2024 -C panic=abort -C opt-level=2 --target "$RECOVERY_NATIVE_TARGET" /recipes/role-probe.rs -o /build/native-role-probe "${link_args[@]}"
nm /build/native-role-probe | grep -E 'neverd_recovered_(rg|seccomp)_main$'
