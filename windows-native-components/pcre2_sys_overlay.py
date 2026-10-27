"""Link-only override for the unchanged locked pcre2-sys 0.2.10 FFI crate."""
from pathlib import Path
import difflib
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'runtime-helpers'))
from build import unpack, sha
from build_native import SYS_BUILD

CRATE_SHA256 = '18b9073c1a2549bd409bf4a32c94d903bb1a09bf845bc306ae148897fa0760a4'
BUILD_RS_SHA256 = 'baf224f96d7c9aeae4156157c66d90e5777d83ead74a41f251a38fdfa7057086'


def stage(crate, destination, evidence):
    assert sha(crate) == CRATE_SHA256
    unpack(crate, destination, 'pcre2-sys-0.2.10/')
    path = destination / 'build.rs'; assert sha(path) == BUILD_RS_SHA256
    before = path.read_text(encoding='utf-8'); path.write_text(SYS_BUILD)
    patch = evidence / 'pcre2-sys-link.patch'
    patch.write_text(''.join(difflib.unified_diff(before.splitlines(True), SYS_BUILD.splitlines(True),
        fromfile='pcre2-sys-0.2.10/build.rs', tofile='pcre2-sys-overlay/build.rs')))
    return dict(crate_version='0.2.10', crate_sha256=CRATE_SHA256, original_build_rs_sha256=BUILD_RS_SHA256,
        overlay_build_rs_sha256=sha(path), patch_sha256=sha(patch),
        Rust_FFI_sources_unchanged=True, scope='Build linkage only to admitted source PCRE2 10.45; all locked package versions and dependency edges retained.')
