"""Hash-gated musl source integration with the shared single Rust/std graph."""
from pathlib import Path
import difflib
import hashlib
import json
import shutil
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'bun-runtime'))
from rust_source_graph import plan
from stage_native_sources import stage
from native_libraries import sha
from musl_allocator import patch_script
from embedded_rg_allocator import plan as plan_rg_allocator
from musl_rust_lock import qualified_text as musl_lock, LOCK_SHA256

HASHES = {
    'src/runtime/bin_entry/mod.rs': 'fe9a6db0e6c4fdc3b960de384a8ce26d3c5892566c6189be9ca5c30bba2b3b43',
    'scripts/build/bun.ts': '6363ec4e9de333e9569f763e1f49c0010122872c6bd53709c87cdde0e0aef021',
    'scripts/build/flags.ts': '131cb0fbe11ae8249bace7d39486c30cd800f1e4e3903093c74c12f2b6e3395c',
    'scripts/build/binary-expectations.ts': 'edd04de7530d876804fceef7c47511ce06811236ad568f6bd786e32ffaf1dec2',
    'src/linker.lds': 'a365da6e5ee059e4debb1a605bd9433e1cd334ea26f0c142a968757c7d657345',
    'Cargo.toml': '495f3ec9e82d180b395d9b9af3cc4a3522c98bac387d3b0c8f2af647712e7c60',
    'Cargo.lock': '10c44ac0a3662b7ee64b0d925b2d8728e8e3031485066e404b5b31379a342b3e',
    'src/runtime/Cargo.toml': '6dd4d57202c8153c7c1e58057802b46e21f20ba2da5363884de7769ed476086d',
    'scripts/build/rust.ts': '60be0343740db96380bca663c4d06875945ef59aeba97e8ea03e4e01b91ddb68',
    'scripts/glob-sources.ts': '21f9a8a7073b3a780b65ed402ef172766ecfdf5c8ec0ba2274c0b54d41b0eec7',
    'src/runtime/dns_jsc/options_jsc.rs': '960c957481b0e97a688ed947ccf480dd13b0dd94285fbd45894ace7dae54fc47',
    'src/runtime/node/node_fs.rs': '09039025d7da37aceec165fd5177caea7e721da3e8c97dc675d4b1035e7bd0dd',
}
ARCHIVES = {
    'bfs': ['librecovered_bfs.a', 'libonig.a'],
    'ugrep': ['librecovered_ugrep.a', 'libreflex.a', 'libviiz.a', 'libpcre2-8.a', 'libz.a', 'libbz2.a', 'libzstd.a', 'libbrotlidec.a', 'libbrotlicommon.a'],
}


def replace(text, before, after):
    assert text.count(before) == 1, before
    return text.replace(before, after)


def patch(source, evidence, native_sources, components):
    assert not evidence.exists() and not (source / 'recovery-native').exists()
    for name, digest in HASHES.items(): assert sha(source / name) == digest, 'Unqualified musl source boundary: ' + name
    changes = plan(source, 'linux')
    changes = [(label, name, before, musl_lock() if label == 'cargo-lock' else after) for label, name, before, after in changes]
    old_dependency = 'recovered_ripgrep = { package = "ripgrep", path = "../../recovery-native/ripgrep", features = ["pcre2"] }'
    changes = [(label, name, before, replace(after, old_dependency, old_dependency.replace('features =', 'default-features = false, features =')) if label == 'runtime-cargo' else after) for label, name, before, after in changes]
    entry = source / 'src/runtime/bin_entry/mod.rs'; before = entry.read_text()
    anchor = '    unsafe { bun_core::init_argv(argc, argv) };\n'
    after = replace(before, anchor, anchor + '''
    // Recovered Linux multicall boundary, before VM threads and cached env reads.
    #[cfg(target_os = "linux")]
    if let Some(status) = unsafe { recovered_multicall::dispatch(argc, argv) } {
        return status;
    }
''')
    after = replace(after, 'mod c_abi_exports;\n', 'mod c_abi_exports;\n#[cfg(target_os = "linux")]\nmod recovered_multicall;\n')
    changes.append(('entry', 'src/runtime/bin_entry/mod.rs', before, after))
    build = source / 'scripts/build/bun.ts'; before = build.read_text()
    anchor = '  const cSources = [...sources.c];\n'
    after = replace(before, anchor, anchor + '  if (cfg.linux && cfg.abi === "musl") cSources.push(resolve(cfg.cwd, "recovery-native/seccomp-entry.c"));\n')
    anchor = '  const linkObjects = [...cxxObjects, ...cObjects, ...depLink.eager, ...rustObjects, ...windowsRes];\n'
    libs = ''.join('    resolve(cfg.cwd, "recovery-native/' + role + '-libraries/' + name + '"),\n' for role in ['ugrep', 'bfs'] for name in ARCHIVES[role])
    after = replace(after, anchor, anchor + '  if (cfg.linux && cfg.abi === "musl") linkObjects.push(\n' + libs + '  );\n')
    changes.append(('native-C-graphs', 'scripts/build/bun.ts', before, after))
    flags = source / 'scripts/build/flags.ts'; before = flags.read_text()
    after = replace(before, '''    flag: ["-lstdc++", "-lgcc"],
    when: c => c.linux && c.abi === "musl",
    desc: "Dynamic C++ runtime on musl (static unavailable)",
''', '''    flag: ["-static-libstdc++", "-static-libgcc", "-lrt"],
    when: c => c.linux && c.abi === "musl",
    desc: "Measured musl libc-only dependency graph with admitted static C++ support",
''')
    changes.append(('static-Cxx-runtime', 'scripts/build/flags.ts', before, after))
    expectations = source / 'scripts/build/binary-expectations.ts'; before = expectations.read_text()
    old = '        neededLibs = [`libc.musl-${cfg.x64 ? "x86_64" : "aarch64"}.so.1`, "libstdc++.so.6"];\n'
    after = replace(before, old, '        neededLibs = [`libc.musl-${cfg.x64 ? "x86_64" : "aarch64"}.so.1`];\n')
    after = replace(after, '''        // libstdc++/libgcc stay dynamic on musl on purpose: an N-API addon
        // built on Alpine links libstdc++.so.6, and it and bun must share one
        // C++ runtime when it loads (node does the same). glibc links it
        // statically. musl has no symbol versioning.
''', '''        // The measured recovery profile has only musl libc in DT_NEEDED.
        // Its C++/GCC support libraries come from the admitted static SDK.
        // This does not qualify arbitrary external N-API addon ABI behavior.
''')
    # The admitted Alpine SDK's static C++ runtime replaces the public dynamic
    # C++ runtime. Allow the real known runtime and Ugrep source initializers;
    # keep the verifier active instead of widening it to arbitrary globals.
    anchor = '  return initializers;\n'
    extra = ['_GLOBAL__sub_I_' + name for name in ['eh_alloc.cc', 'cxx11_locale_inst.cc', 'cxx11_wlocale_inst.cc', 'ios_errcat.cc', 'locale_inst.cc', 'system_error.cc', 'wlocale_inst.cc', 'bitmap_allocator.cc', 'future.cc', 'memory_resource.cc', 'parallel_settings.cc', 'ugrep.cpp', 'output.cpp', 'query.cpp', 'stats.cpp', 'posix.cpp', 'unicode.cpp']]
    extra += ['_GLOBAL__sub_I.00090_globals_io.cc', '_GLOBAL__sub_I.00098_tzdb.cc']
    after = replace(after, anchor, '  if (musl) initializers.push(' + ', '.join(json.dumps(n) for n in extra) + ');\n' + '  if (musl && cfg.x64) initializers.push("_GLOBAL__sub_I_simd.cpp");\n' + anchor)
    changes.append(('musl-native-binary-contract', 'scripts/build/binary-expectations.ts', before, after))
    linker = source / 'src/linker.lds'; before = linker.read_text()
    changes.append(('musl-allocator-exports', 'src/linker.lds', before, patch_script(before)))
    native = source / 'recovery-native'; stage(native_sources, native, target_os='linux')
    changes.extend(plan_rg_allocator(native / 'ripgrep'))
    for role, names in ARCHIVES.items():
        destination = native / (role + '-libraries'); destination.mkdir()
        for name in names: shutil.copyfile(components / 'native-libraries' / role / name, destination / name)
    install = native / 'pcre2-install'; (install / 'lib/pkgconfig').mkdir(parents=True)
    pc_input = components / 'native-libraries/rg-pcre2'
    shutil.copytree(pc_input / 'include', install / 'include'); shutil.copyfile(pc_input / 'libpcre2-8.a', install / 'lib/libpcre2-8.a')
    # Paths are compiler-container paths; no producer runner directory is used.
    prefix = '/output/bun-source/recovery-native/pcre2-install'
    (install / 'lib/pkgconfig/libpcre2-8.pc').write_text('prefix=' + prefix + '\nlibdir=${prefix}/lib\nincludedir=${prefix}/include\n\nName: libpcre2-8\nDescription: Admitted native musl PCRE2 source graph\nVersion: 10.45\nLibs: -L${libdir} -lpcre2-8\nCflags: -I${includedir}\n')
    multicall = (ROOT.parent / 'bun-runtime/recovered_multicall.rs').read_text()
    anchor = '    fn neverd_recovered_seccomp_main(argc: c_int, argv: *const *const c_char) -> c_int;\n'
    multicall = replace(multicall, anchor, anchor + ''.join('    fn neverd_recovered_' + role + '_main(argc: c_int, argv: *const *const c_char) -> c_int;\n' for role in ['ugrep', 'bfs']))
    unsupported = '''        role @ (Role::Ugrep | Role::Bfs) => {
            eprintln!("recovered native dispatch: {role:?} implementation is not integrated");
            Some(126)
        }
'''
    multicall = replace(multicall, unsupported, ''.join('        Role::' + variant + ' => Some(unsafe { neverd_recovered_' + role + '_main(argc, argv) }),\n' for role, variant in [('ugrep', 'Ugrep'), ('bfs', 'Bfs')]))
    (entry.parent / 'recovered_multicall.rs').write_text(multicall)
    shutil.copyfile(ROOT.parent / 'bun-runtime/role_contract.rs', entry.parent / 'role_contract.rs')
    evidence.mkdir(); patches = []
    for label, name, before, after in changes:
        assert before != after; path = source / name; path.write_text(after); output = evidence / (label + '.patch')
        output.write_text(''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile='public-bun/' + name, tofile='recovered-bun/' + name)))
        patches.append(dict(file=name, before_sha256=hashlib.sha256(before.encode()).hexdigest(), after_sha256=sha(path), patch_sha256=sha(output)))
    receipt = dict(status='musl_source_native_roles_patched_not_built', patches=patches, compiled_rust_archive_used=False,
        native_source_manifest_sha256=sha(native_sources / 'MANIFEST.json'), component_manifest_sha256=sha(components / 'MANIFEST.json'),
        GNU_allocator_symbol_versions_used=False, original_prefix_reused=False, erased_types_restored=False,
        embedded_rg_allocator_owner='Bun process mimalloc', upstream_rg_standalone_main_unchanged=True,
        locked_musl_graph_sha256=LOCK_SHA256, shared_GNU_and_macos_lock_unchanged=True,
        upstream_rg_standalone_default_jemalloc_feature_preserved=True, original_allocator_performance_reproduced=False, goal_complete=False)
    (evidence / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt
