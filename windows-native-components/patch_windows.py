"""Hash-gated Windows entry, one Rust/std source graph and admitted C graph."""
from pathlib import Path
import difflib
import hashlib
import json
import shutil
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'bun-runtime'))
from rust_source_graph import plan as plan_rust_graph
from stage_native_sources import stage as stage_sources
from pcre2_sys_overlay import stage as stage_sys
from component_libraries import ARCHIVES, qualify_library
from coff_admission import sha

HASHES = {
    'src/runtime/bin_entry/mod.rs': 'fe9a6db0e6c4fdc3b960de384a8ce26d3c5892566c6189be9ca5c30bba2b3b43',
    'scripts/build/bun.ts': '6363ec4e9de333e9569f763e1f49c0010122872c6bd53709c87cdde0e0aef021',
    'Cargo.toml': '495f3ec9e82d180b395d9b9af3cc4a3522c98bac387d3b0c8f2af647712e7c60',
    'src/runtime/Cargo.toml': '6dd4d57202c8153c7c1e58057802b46e21f20ba2da5363884de7769ed476086d',
    'scripts/glob-sources.ts': '21f9a8a7073b3a780b65ed402ef172766ecfdf5c8ec0ba2274c0b54d41b0eec7',
    'Cargo.lock': '10c44ac0a3662b7ee64b0d925b2d8728e8e3031485066e404b5b31379a342b3e',
    'src/runtime/dns_jsc/options_jsc.rs': '960c957481b0e97a688ed947ccf480dd13b0dd94285fbd45894ace7dae54fc47',
    'src/runtime/node/node_fs.rs': '09039025d7da37aceec165fd5177caea7e721da3e8c97dc675d4b1035e7bd0dd',
}


def replace(text, before, after):
    assert text.count(before) == 1, before
    return text.replace(before, after)


def patch(source, evidence, native_sources, ugrep_package, arch):
    assert not evidence.exists() and not (source / 'recovery-native').exists()
    for name, digest in HASHES.items(): assert sha(source / name) == digest, 'Unqualified Windows source: ' + name
    provenance = qualify_library(arch, ugrep_package)
    changes = plan_rust_graph(source, 'windows')
    entry = source / 'src/runtime/bin_entry/mod.rs'; before = entry.read_text(encoding='utf-8')
    anchor = '    unsafe { bun_core::init_argv(argc, argv) };\n'
    after = replace(before, anchor, anchor + '''
    // Recovered Windows boundary, before cached env conversion and threads.
    #[cfg(target_os = "windows")]
    if let Some(status) = unsafe { recovered_multicall::dispatch() } {
        return status;
    }
''')
    after = replace(after, 'mod c_abi_exports;\n', 'mod c_abi_exports;\n#[cfg(target_os = "windows")]\nmod recovered_multicall;\n')
    changes.append(('entry', 'src/runtime/bin_entry/mod.rs', before, after))
    build = source / 'scripts/build/bun.ts'; before = build.read_text(encoding='utf-8')
    anchor = '  const linkObjects = [...cxxObjects, ...cObjects, ...depLink.eager, ...rustObjects, ...windowsRes];\n'
    libraries = ''.join('    resolve(cfg.cwd, "recovery-native/ugrep-libraries/' + name + '"),\n' for name in ARCHIVES)
    after = replace(before, anchor, anchor + '  if (cfg.windows) linkObjects.push(\n' + libraries + '  );\n')
    anchor = '  const ldflags = [...flags.ldflags, ...systemLibs(cfg)];\n'
    after = replace(after, anchor, anchor + '  if (cfg.windows) ldflags.push("advapi32.lib"); // Ugrep config ownership/security queries.\n')
    changes.append(('native-C-link', 'scripts/build/bun.ts', before, after))
    native = source / 'recovery-native'; stage_sources(native_sources, native, target_os='windows')
    libraries = native / 'ugrep-libraries'; libraries.mkdir()
    for name in ARCHIVES: shutil.copyfile(ugrep_package / 'native-library' / name, libraries / name)
    evidence.mkdir()
    sys_overlay = stage_sys(native_sources / 'inputs/pcre2-sys-0.2.10.crate', native / 'pcre2-sys-overlay', evidence)
    sources = [(ROOT / 'recovered_multicall.rs', 'recovered_multicall.rs'), (ROOT / 'role_boundary.rs', 'role_boundary.rs'),
        (ROOT.parent / 'native-role-contracts/windows.rs', 'windows_role_contract.rs')]
    copied = []
    for path, name in sources:
        destination = entry.parent / name; assert not destination.exists(); shutil.copyfile(path, destination)
        copied.append(dict(file=destination.relative_to(source).as_posix(), sha256=sha(destination)))
    patches = []
    for label, name, before, after in changes:
        assert before != after; path = source / name; path.write_text(after, encoding='utf-8'); output = evidence / (label + '.patch')
        output.write_text(''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile='public-bun/' + name, tofile='recovered-bun/' + name)))
        patches.append(dict(file=name, before_sha256=hashlib.sha256(before.encode()).hexdigest(), after_sha256=sha(path), patch_sha256=sha(output)))
    receipt = dict(status='Windows_native_roles_source_patched_not_built', arch=arch, patches=patches, new_sources=copied,
        native_source_manifest_sha256=sha(native_sources / 'MANIFEST.json'), ugrep_provenance=provenance, PCRE2_sys_overlay=sys_overlay,
        one_Rust_std_graph_required=True, compiled_Rust_archive_used=False, compiled_C_source_graph_used=True,
        raw_UTF16_arguments_preserved=True, original_native_prefix_reused=False, private_producer_revision_recovered=False,
        erased_producer_types_restored=False, goal_complete=False)
    (evidence / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt
