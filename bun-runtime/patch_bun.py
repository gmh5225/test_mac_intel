"""Add the reconstructed dispatcher at one hash-pinned public Bun boundary."""
from pathlib import Path
import argparse
import difflib
import hashlib
import json
import shutil
from stage_native_sources import stage
from allocator_exports import patch_script as patch_allocator_exports, versions as allocator_versions

ROOT = Path(__file__).resolve().parent
ENTRY_SHA256 = "fe9a6db0e6c4fdc3b960de384a8ce26d3c5892566c6189be9ca5c30bba2b3b43"
BUILD_SHA256 = "6363ec4e9de333e9569f763e1f49c0010122872c6bd53709c87cdde0e0aef021"
CARGO_SHA256 = "495f3ec9e82d180b395d9b9af3cc4a3522c98bac387d3b0c8f2af647712e7c60"
RUNTIME_CARGO_SHA256 = "6dd4d57202c8153c7c1e58057802b46e21f20ba2da5363884de7769ed476086d"
RUST_BUILD_SHA256 = "60be0343740db96380bca663c4d06875945ef59aeba97e8ea03e4e01b91ddb68"
GLOBS_SHA256 = "21f9a8a7073b3a780b65ed402ef172766ecfdf5c8ec0ba2274c0b54d41b0eec7"
BASE_LOCK_SHA256 = "10c44ac0a3662b7ee64b0d925b2d8728e8e3031485066e404b5b31379a342b3e"
RESOLVED_LOCK_SHA256 = "1bc3c6d8c1975d2693c16ca22cf84f9ea12d66ca2565916c292d27030919c723"
FLAGS_SHA256 = "131cb0fbe11ae8249bace7d39486c30cd800f1e4e3903093c74c12f2b6e3395c"
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


def patch(source, evidence, native_package=None, bfs_package=None, ugrep_package=None):
    entry = source / "src/runtime/bin_entry/mod.rs"
    assert sha(entry) == ENTRY_SHA256, "unqualified Bun process entry"
    build = source / "scripts/build/bun.ts"
    assert sha(build) == BUILD_SHA256, "unqualified Bun native build graph"
    assert native_package is not None, "qualified direct native libraries are required"
    native_package = Path(native_package)
    additional = [("Cargo.toml", CARGO_SHA256), ("src/runtime/Cargo.toml", RUNTIME_CARGO_SHA256),
                  ("scripts/build/rust.ts", RUST_BUILD_SHA256), ("scripts/glob-sources.ts", GLOBS_SHA256),
                  ("Cargo.lock", BASE_LOCK_SHA256),
                  ("src/linker.lds", "a365da6e5ee059e4debb1a605bd9433e1cd334ea26f0c142a968757c7d657345"),
                  ("src/runtime/dns_jsc/options_jsc.rs", "960c957481b0e97a688ed947ccf480dd13b0dd94285fbd45894ace7dae54fc47"),
                  ("src/runtime/node/node_fs.rs", "09039025d7da37aceec165fd5177caea7e721da3e8c97dc675d4b1035e7bd0dd")]
    for rel, digest in additional:
        assert sha(source / rel) == digest, "unqualified Bun Rust graph input: " + rel
    arch = json.loads((native_package / "receipt.json").read_bytes())["arch"]
    linker_before = (source / "src/linker.lds").read_text()
    linker_after = patch_allocator_exports(linker_before, arch)
    allocator_patch = ("allocator-exports", "src/linker.lds", linker_before, linker_after)
    bfs_inputs = None
    if bfs_package is not None:
        from bfs_libraries import qualify as qualify_bfs
        bfs_package = Path(bfs_package)
        component = json.loads((bfs_package / "receipt.json").read_bytes())
        bfs_inputs = qualify_bfs(component["arch"], bfs_package, component["compiler_image"])
        assert sha(source / "scripts/build/flags.ts") == FLAGS_SHA256, "unqualified Bun Bfs linker flags"
    ugrep_inputs = None
    if ugrep_package is not None:
        assert bfs_inputs is not None, "The full Ugrep profile requires the qualified Bfs libraries"
        from ugrep_libraries import qualify as qualify_ugrep
        ugrep_package = Path(ugrep_package)
        component = json.loads((ugrep_package / "receipt.json").read_bytes())
        assert component["arch"] == arch
        ugrep_inputs = qualify_ugrep(arch, ugrep_package, component["compiler_image"])
    assert sha(ROOT / "resolved-Cargo.lock") == RESOLVED_LOCK_SHA256
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
    extra_patches = []
    multicall_code = None
    if bfs_inputs is not None:
        build_after = build_after.replace(link_anchor, link_anchor + '''  if (cfg.linux) linkObjects.push(
    resolve(cfg.cwd, "recovery-native/bfs-libraries/librecovered_bfs.a"),
    resolve(cfg.cwd, "recovery-native/bfs-libraries/libonig.a"),
  );
''')
        flags = source / "scripts/build/flags.ts"; flags_before = flags.read_text()
        flag_anchor = '  // ─── Linux ───\n  {\n    flag: c => [`--target=${c.crossTarget!}`, `--sysroot=${c.sysroot!}`],\n'
        assert flags_before.count(flag_anchor) == 1
        flags_after = flags_before.replace(flag_anchor, '''  // ─── Linux ───
  {
    flag: "-lrt",
    when: c => c.linux && c.abi === "gnu",
    desc: "Source-built Bfs POSIX timers (also required by the measured original)",
  },
  {
    flag: c => [`--target=${c.crossTarget!}`, `--sysroot=${c.sysroot!}`],
''')
        if ugrep_inputs is not None:
            from ugrep_libraries import ARCHIVES as ugrep_archives
            libraries = ''.join('    resolve(cfg.cwd, "recovery-native/ugrep-libraries/'+name+'"),\n' for name in ugrep_archives)
            build_after = build_after.replace(link_anchor, link_anchor+'  if (cfg.linux) linkObjects.push(\n'+libraries+'  );\n')
            # Ugrep catches real C++ regex exceptions. Its source objects and
            # libstdc++ need unwind metadata through the final release strip.
            eh_anchor = '    flag: "-Wl,--no-eh-frame-hdr",\n'
            strip_anchor = '    flag: ["-R", ".eh_frame", "-R", ".eh_frame_hdr", "-R", ".gcc_except_table"],\n'
            assert flags_after.count(eh_anchor) == flags_after.count(strip_anchor) == 1
            flags_after = flags_after.replace(eh_anchor, '    flag: "-Wl,--eh-frame-hdr", // Required by source-built Ugrep exceptions.\n')
            flags_after = flags_after.replace(strip_anchor, '    flag: [], // Preserve source-built Ugrep unwind/exception sections.\n')
        extra_patches.append(("c-native-link-flags" if ugrep_inputs is not None else "bfs-link-flags", "scripts/build/flags.ts", flags_before, flags_after))
        multicall_code = (ROOT / "recovered_multicall.rs").read_text()
        declaration = '    fn neverd_recovered_seccomp_main(argc: c_int, argv: *const *const c_char) -> c_int;\n'
        unsupported = '        role @ (Role::Ugrep | Role::Bfs) => {\n'
        assert multicall_code.count(declaration) == multicall_code.count(unsupported) == 1
        multicall_code = multicall_code.replace(declaration, declaration + '    fn neverd_recovered_bfs_main(argc: c_int, argv: *const *const c_char) -> c_int;\n')
        multicall_code = multicall_code.replace(unsupported, '        Role::Bfs => Some(unsafe { neverd_recovered_bfs_main(argc, argv) }),\n        role @ Role::Ugrep => {\n')
        if ugrep_inputs is not None:
            unsupported_ugrep = '''        role @ Role::Ugrep => {
            eprintln!("recovered native dispatch: {role:?} implementation is not integrated");
            Some(126)
        }
'''
            assert multicall_code.count(unsupported_ugrep) == 1
            multicall_code = multicall_code.replace(declaration, declaration+'    fn neverd_recovered_ugrep_main(argc: c_int, argv: *const *const c_char) -> c_int;\n')
            multicall_code = multicall_code.replace(unsupported_ugrep, '        Role::Ugrep => Some(unsafe { neverd_recovered_ugrep_main(argc, argv) }),\n')
    root_cargo = source / "Cargo.toml"; root_before = root_cargo.read_text()
    assert root_before.count('\nexclude = ["vendor"]\n') == 1 and "[patch.crates-io]" not in root_before
    root_after = root_before.replace('\nexclude = ["vendor"]\n', '\nexclude = ["vendor", "recovery-native"]\n')
    root_after += '\n[patch.crates-io]\npcre2 = { path = "recovery-native/pcre2-overlay" }\n'
    runtime_cargo = source / "src/runtime/Cargo.toml"; runtime_before = runtime_cargo.read_text()
    runtime_after = runtime_before + '''
[target.'cfg(target_os = "linux")'.dependencies]
recovered_ripgrep = { package = "ripgrep", path = "../../recovery-native/ripgrep", features = ["pcre2"] }
'''
    globs = source / "scripts/glob-sources.ts"; globs_before = globs.read_text()
    anchor = '      "src/**/Cargo.toml",\n'; assert globs_before.count(anchor) == 1
    globs_after = globs_before.replace(anchor, anchor + '      "recovery-native/**/*.rs",\n      "recovery-native/**/Cargo.toml",\n')
    # The added serde_json trait implementations expose previously ambiguous
    # `as _` comparisons. Use the actual i32 family/u16 SystemError field types;
    # hash-gated line identities avoid changing the separate i32 syscall errors.
    type_patches = []
    for label, rel, numbers, old, new in [
        ("dns-type", "src/runtime/dns_jsc/options_jsc.rs", [226, 227], " as _ =>", " as i32 =>"),
        ("fs-type", "src/runtime/node/node_fs.rs", [1598, 2015, 8236, 8364], "E::EEXIST as _", "E::EEXIST as u16")]:
        before_type = (source / rel).read_text(); lines = before_type.splitlines(True)
        for number in numbers:
            assert lines[number - 1].count(old) == 1
            lines[number - 1] = lines[number - 1].replace(old, new)
        type_patches.append((label, rel, before_type, "".join(lines)))
    lock_before = (source / "Cargo.lock").read_text()
    lock_after = (ROOT / "resolved-Cargo.lock").read_text()
    stage(native_package, native_root)
    if bfs_inputs is not None:
        library_root = native_root / "bfs-libraries"; library_root.mkdir()
        for name in ["librecovered_bfs.a", "libonig.a"]:
            shutil.copyfile(bfs_package / "native-library" / name, library_root / name)
    if ugrep_inputs is not None:
        library_root = native_root / "ugrep-libraries"; library_root.mkdir()
        for name in ugrep_archives:
            shutil.copyfile(ugrep_package / "native-library" / name, library_root / name)
    entry.write_text(after); build.write_text(build_after)
    root_cargo.write_text(root_after); runtime_cargo.write_text(runtime_after)
    globs.write_text(globs_after); (source / "Cargo.lock").write_text(lock_after)
    for _, rel, _, after_type in [*type_patches, allocator_patch]: (source / rel).write_text(after_type)
    for _, rel, _, after_extra in extra_patches: (source / rel).write_text(after_extra)
    copied = []
    for name in ["role_contract.rs", "recovered_multicall.rs"]:
        destination = entry.parent / name
        assert not destination.exists()
        shutil.copyfile(ROOT / name, destination)
        if name == "recovered_multicall.rs" and multicall_code is not None:
            destination.write_text(multicall_code)
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
        ("source-globs", "scripts/glob-sources.ts", globs_before, globs_after),
        ("cargo-lock", "Cargo.lock", lock_before, lock_after), *type_patches, allocator_patch]:
        patch_file = evidence / (label + ".patch")
        patch_file.write_text("".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), fromfile="public-bun/" + rel, tofile="recovered-bun/" + rel)))
        graph_patches.append({"file": rel, "before_sha256": hashlib.sha256(old.encode()).hexdigest(), "after_sha256": sha(source / rel), "patch_sha256": sha(patch_file)})
    receipt = {"status": "patched_not_built", "entry_sha256_before": ENTRY_SHA256, "entry_sha256_after": sha(entry),
               "patch_sha256": sha(evidence / "entry.patch"), "new_sources": copied,
               "original_prefix_reused": False, "original_erased_types_claimed": False,
               "build_sha256_before": BUILD_SHA256, "build_sha256_after": sha(build),
               "build_patch_sha256": sha(evidence / "build.patch"), "rust_graph_patches": graph_patches,
               "resolved_cargo_lock_sha256": RESOLVED_LOCK_SHA256,
               "upstream_rust_planner_sha256": sha(source / "scripts/build/rust.ts"),
               "allocator_symbol_versions": allocator_versions(arch),
               "compiled_native_archive_used": False,
               "native_inputs": [{"file": p.relative_to(native_root).as_posix(), "sha256": sha(p)}
                                 for p in sorted(native_root.rglob("*")) if p.is_file()],
               "scope": "One source-built Rust graph including std and rg, plus C seccomp, before VM initialization. No payload file writes or prebuilt Rust archive. Ugrep/Bfs and the private revision remain open."}
    if bfs_inputs is not None:
        extra_receipts = []
        for label, rel, old, new in extra_patches:
            path = evidence / (label + ".patch")
            path.write_text("".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), fromfile="public-bun/"+rel, tofile="recovered-bun/"+rel)))
            extra_receipts.append(dict(file=rel,before_sha256=hashlib.sha256(old.encode()).hexdigest(),after_sha256=sha(source/rel),patch_sha256=sha(path)))
        receipt.update(compiled_native_archive_used=True, compiled_rust_archive_used=False,
            bfs_library_provenance=bfs_inputs, c_library_patches=extra_receipts,
            scope="One source-built Rust graph plus pinned source-built Bfs/Oniguruma C libraries and C seccomp before VM initialization. Ugrep and the private Bun revision remain open.")
    if ugrep_inputs is not None:
        receipt.update(ugrep_library_provenance=ugrep_inputs,ugrep_exception_metadata_preserved=True,
            scope="One source-built Rust graph plus qualified Ugrep/Bfs libraries and unchanged C seccomp before VM initialization. Real Ugrep C++ exception tables are retained. The private Bun revision remains open.")
    (evidence / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--native-libraries", type=Path, required=True)
    parser.add_argument("--bfs-libraries", type=Path)
    parser.add_argument("--ugrep-libraries", type=Path)
    args = parser.parse_args()
    print(json.dumps(patch(args.source.resolve(), args.evidence.resolve(), args.native_libraries.resolve(),
        args.bfs_libraries.resolve() if args.bfs_libraries else None,
        args.ugrep_libraries.resolve() if args.ugrep_libraries else None)))
