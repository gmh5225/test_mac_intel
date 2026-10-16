#!/bin/sh
set -eu
export CARGO_HOME=/build/cargo-home
export CARGO_TARGET_DIR=/build/target
export CARGO_BUILD_JOBS=2
export RUSTFLAGS='-C target-feature=+ssse3,-avx2'
# pcre2-sys 0.2.9 treats 1 as "compile its older vendored source".
# Use pkg-config to select our pinned 10.45 static library instead.
export PCRE2_SYS_STATIC=0
export PKG_CONFIG_PATH=/build/install/lib/pkgconfig
export PKG_CONFIG_ALL_STATIC=1
mkdir /build/pcre2-build
cd /build/pcre2-build
/source/pcre2/configure --prefix=/build/install --disable-shared --enable-static --enable-jit --disable-pcre2-16 --disable-pcre2-32
make -j2
make check
make install
cd /build/ripgrep
cargo build --release --features pcre2 --locked --offline
cp /build/target/release/rg /build/rg
ldd /build/rg
/build/rg --version
