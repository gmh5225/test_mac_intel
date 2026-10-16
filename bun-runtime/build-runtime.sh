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
bun scripts/build.ts --profile=release --build-dir=/output/bun-source/build/recovery -j2
