"""Add the reconstructed dispatcher at one hash-pinned public Bun boundary."""
from pathlib import Path
import argparse
import difflib
import hashlib
import json
import shutil
from stage_native_sources import stage

ROOT = Path(__file__).resolve().parent
ENTRY_SHA256 = "fe9a6db0e6c4fdc3b960de384a8ce26d3c5892566c6189be9ca5c30bba2b3b43"
BUILD_SHA256 = "6363ec4e9de333e9569f763e1f49c0010122872c6bd53709c87cdde0e0aef021"
CARGO_SHA256 = "495f3ec9e82d180b395d9b9af3cc4a3522c98bac387d3b0c8f2af647712e7c60"
RUNTIME_CARGO_SHA256 = "6dd4d57202c8153c7c1e58057802b46e21f20ba2da5363884de7769ed476086d"
RUST_BUILD_SHA256 = "60be0343740db96380bca663c4d06875945ef59aeba97e8ea03e4e01b91ddb68"
GLOBS_SHA256 = "21f9a8a7073b3a780b65ed402ef172766ecfdf5c8ec0ba2274c0b54d41b0eec7"
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
    additional = [("Cargo.toml", CARGO_SHA256), ("src/runtime/Cargo.toml", RUNTIME_CARGO_SHA256),
                  ("scripts/build/rust.ts", RUST_BUILD_SHA256), ("scripts/glob-sources.ts", GLOBS_SHA256)]
    for rel, digest in additional:
        assert sha(source / rel) == digest, "unqualified Bun Rust graph input: " + rel
    native_files = [native_package / name for name in ["apply-seccomp.c", "unix-block-bpf.h", "recovery_lib.rs"]]
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
''')
    root_cargo = source / "Cargo.toml"; root_before = root_cargo.read_text()
    assert root_before.count('\nexclude = ["vendor"]\n') == 1 and "[patch.crates-io]" not in root_before
    root_after = root_before.replace('\nexclude = ["vendor"]\n', '\nexclude = ["vendor", "recovery-native"]\n')
    root_after += '\n[patch.crates-io]\npcre2 = { path = "recovery-native/pcre2-overlay" }\n'
    runtime_cargo = source / "src/runtime/Cargo.toml"; runtime_before = runtime_cargo.read_text()
    runtime_after = runtime_before + '''
[target.'cfg(target_os = "linux")'.dependencies]
recovered_ripgrep = { package = "ripgrep", path = "../../recovery-native/ripgrep", features = ["pcre2"] }
'''
    rust_build = source / "scripts/build/rust.ts"; rust_before = rust_build.read_text()
    locked = '    "--locked",\n  ];\n'
    assert rust_before.count(locked) == 1
    rust_after = rust_before.replace(locked, '''    ...(process.env.RECOVERY_BOOTSTRAP_RUST_LOCK === "1" ? [] : ["--locked"]),
  ];
''')
    globs = source / "scripts/glob-sources.ts"; globs_before = globs.read_text()
    anchor = '      "src/**/Cargo.toml",\n'; assert globs_before.count(anchor) == 1
    globs_after = globs_before.replace(anchor, anchor + '      "recovery-native/**/*.rs",\n      "recovery-native/**/Cargo.toml",\n')
    stage(native_package, native_root)
    entry.write_text(after); build.write_text(build_after)
    root_cargo.write_text(root_after); runtime_cargo.write_text(runtime_after)
    rust_build.write_text(rust_after); globs.write_text(globs_after)
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
    graph_patches = []
    for label, rel, old, new in [
        ("cargo", "Cargo.toml", root_before, root_after),
        ("runtime-cargo", "src/runtime/Cargo.toml", runtime_before, runtime_after),
        ("rust-plan", "scripts/build/rust.ts", rust_before, rust_after),
        ("source-globs", "scripts/glob-sources.ts", globs_before, globs_after)]:
        patch_file = evidence / (label + ".patch")
        patch_file.write_text("".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), fromfile="public-bun/" + rel, tofile="recovered-bun/" + rel)))
        graph_patches.append({"file": rel, "before_sha256": hashlib.sha256(old.encode()).hexdigest(), "after_sha256": sha(source / rel), "patch_sha256": sha(patch_file)})
    receipt = {"status": "patched_not_built", "entry_sha256_before": ENTRY_SHA256, "entry_sha256_after": sha(entry),
               "patch_sha256": sha(evidence / "entry.patch"), "new_sources": copied,
               "original_prefix_reused": False, "original_erased_types_claimed": False,
               "build_sha256_before": BUILD_SHA256, "build_sha256_after": sha(build),
               "build_patch_sha256": sha(evidence / "build.patch"), "rust_graph_patches": graph_patches,
               "compiled_native_archive_used": False,
               "native_inputs": [{"file": p.relative_to(native_root).as_posix(), "sha256": sha(p)}
                                 for p in sorted(native_root.rglob("*")) if p.is_file()],
               "scope": "One source-built Rust graph including std and rg, plus C seccomp, before VM initialization. No payload file writes or prebuilt Rust archive. Ugrep/Bfs and the private revision remain open."}
    (evidence / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--native-libraries", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(patch(args.source.resolve(), args.evidence.resolve(), args.native_libraries.resolve())))
