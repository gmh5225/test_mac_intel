#!/bin/bash
set -euo pipefail
cd /output/bun-source
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0=safe.directory
export GIT_CONFIG_VALUE_0=/output/bun-source
export RECOVERY_RG_PAYLOAD=/payloads/rg
export RECOVERY_SECCOMP_PAYLOAD=/payloads/apply-seccomp
export BUN_BUILD_CACHE_DIR=/output/source-cache
export CARGO_BUILD_JOBS=2
export NINJA_STATUS='[%f/%t %e] '
command -v bun
bun --version
python3 --version
# A fresh build directory cannot reuse the image's Bun core object files.
# Public WebKit and other dependency artifacts remain subject to Bun's own
# pinned dependency graph; this is not a JavaScriptCore source-build claim.
bun scripts/build.ts --profile=release --build-dir=/output/source-build -j2
