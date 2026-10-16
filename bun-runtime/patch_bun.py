"""Add the reconstructed dispatcher at one hash-pinned public Bun boundary."""
from pathlib import Path
import argparse
import difflib
import hashlib
import json
import shutil

ROOT = Path(__file__).resolve().parent
ENTRY_SHA256 = "fe9a6db0e6c4fdc3b960de384a8ce26d3c5892566c6189be9ca5c30bba2b3b43"
BUILD_SHA256 = "6363ec4e9de333e9569f763e1f49c0010122872c6bd53709c87cdde0e0aef021"
OLD = "    unsafe { bun_core::init_argv(argc, argv) };\n"
NEW = OLD + '''
    // Recovered Linux multicall boundary, before threads and cached env reads.
    #[cfg(target_os = "linux")]
    if let Some(status) = unsafe { recovered_multicall::dispatch(argc, argv) } {
        return status;
    }
'''


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def patch(source, evidence, native_package=None):
    entry = source / "src/runtime/bin_entry/mod.rs"
    assert sha(entry) == ENTRY_SHA256, "unqualified Bun process entry"
    build = source / "scripts/build/bun.ts"
    assert sha(build) == BUILD_SHA256, "unqualified Bun native build graph"
    assert native_package is not None, "qualified direct native libraries are required"
    native_package = Path(native_package)
    native_files = [native_package / name for name in ["apply-seccomp.c", "unix-block-bpf.h", "librecovered_rg.a"]]
    assert all(path.is_file() and not path.is_symlink() for path in native_files)
    native_root = source / "recovery-native"
    assert not native_root.exists()
    assert not evidence.exists()
    assert all(not (entry.parent / name).exists() for name in ["role_contract.rs", "recovered_multicall.rs"])
    before = entry.read_text()
    assert before.count(OLD) == 1 and before.count("mod c_abi_exports;\n") == 1
    after = before.replace(OLD, NEW).replace("mod c_abi_exports;\n",
        'mod c_abi_exports;\n#[cfg(target_os = "linux")]\nmod recovered_multicall;\n')
    build_before = build.read_text()
    c_anchor = "  const cSources = [...sources.c];\n"
    link_anchor = "  const linkObjects = [...cxxObjects, ...cObjects, ...depLink.eager, ...rustObjects, ...windowsRes];\n"
    assert build_before.count(c_anchor) == build_before.count(link_anchor) == 1
    build_after = build_before.replace(c_anchor, c_anchor + '''  if (cfg.linux) cSources.push(resolve(cfg.cwd, "recovery-native/seccomp-entry.c"));
''').replace(link_anchor, '''  const recoveryLibraries = cfg.linux ? [resolve(cfg.cwd, "recovery-native/librecovered_rg.a")] : [];
  const linkObjects = [...cxxObjects, ...cObjects, ...depLink.eager, ...rustObjects, ...recoveryLibraries, ...windowsRes];
''')
    entry.write_text(after)
    build.write_text(build_after)
    native_root.mkdir()
    for name in ["apply-seccomp.c", "unix-block-bpf.h", "librecovered_rg.a"]:
        shutil.copyfile(native_package / name, native_root / name)
    (native_root / "seccomp-entry.c").write_text('#define main neverd_recovered_seccomp_main\n#include "apply-seccomp.c"\n')
    copied = []
    for name in ["role_contract.rs", "recovered_multicall.rs"]:
        destination = entry.parent / name
        assert not destination.exists()
        shutil.copyfile(ROOT / name, destination)
        copied.append({"file": str(destination.relative_to(source)), "sha256": sha(destination)})
    evidence.mkdir()
    diff = "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
        fromfile="public-bun/src/runtime/bin_entry/mod.rs", tofile="recovered-bun/src/runtime/bin_entry/mod.rs"))
    (evidence / "entry.patch").write_text(diff)
    build_diff = "".join(difflib.unified_diff(build_before.splitlines(True), build_after.splitlines(True),
        fromfile="public-bun/scripts/build/bun.ts", tofile="recovered-bun/scripts/build/bun.ts"))
    (evidence / "build.patch").write_text(build_diff)
    receipt = {"status": "patched_not_built", "entry_sha256_before": ENTRY_SHA256, "entry_sha256_after": sha(entry),
               "patch_sha256": sha(evidence / "entry.patch"), "new_sources": copied,
               "original_prefix_reused": False, "original_erased_types_claimed": False,
               "build_sha256_before": BUILD_SHA256, "build_sha256_after": sha(build),
               "build_patch_sha256": sha(evidence / "build.patch"),
               "native_inputs": [{"file": p.relative_to(native_root).as_posix(), "sha256": sha(p)}
                                 for p in sorted(native_root.rglob("*")) if p.is_file()],
               "scope": "Direct Linux Rust/C library integration before VM initialization. No payload file writes. Ugrep/Bfs and original private revision remain open."}
    (evidence / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--native-libraries", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(patch(args.source.resolve(), args.evidence.resolve(), args.native_libraries.resolve())))
