"""Hash-gated Darwin entry and source graph for the three real native roles."""
from pathlib import Path
import difflib
import hashlib
import json
import shutil
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'bun-runtime'))
from rust_source_graph import plan as plan_rust_graph
from stage_native_sources import stage
from component_libraries import ARCHIVES, qualify
from macho_contracts import EXCEPTION_IMPORTS

HASHES = {
    'src/runtime/bin_entry/mod.rs': 'fe9a6db0e6c4fdc3b960de384a8ce26d3c5892566c6189be9ca5c30bba2b3b43',
    'scripts/build/bun.ts': '6363ec4e9de333e9569f763e1f49c0010122872c6bd53709c87cdde0e0aef021',
    'Cargo.toml': '495f3ec9e82d180b395d9b9af3cc4a3522c98bac387d3b0c8f2af647712e7c60',
    'src/runtime/Cargo.toml': '6dd4d57202c8153c7c1e58057802b46e21f20ba2da5363884de7769ed476086d',
    'scripts/build/rust.ts': '60be0343740db96380bca663c4d06875945ef59aeba97e8ea03e4e01b91ddb68',
    'scripts/glob-sources.ts': '21f9a8a7073b3a780b65ed402ef172766ecfdf5c8ec0ba2274c0b54d41b0eec7',
    'Cargo.lock': '10c44ac0a3662b7ee64b0d925b2d8728e8e3031485066e404b5b31379a342b3e',
    'src/runtime/dns_jsc/options_jsc.rs': '960c957481b0e97a688ed947ccf480dd13b0dd94285fbd45894ace7dae54fc47',
    'src/runtime/node/node_fs.rs': '09039025d7da37aceec165fd5177caea7e721da3e8c97dc675d4b1035e7bd0dd',
    'scripts/build/flags.ts': '471840ec9df1838a4237805ac456b8a9e4ae069c0d09cf2470b9b5366ea28bbc',
}
UGREP_INITIALIZERS = ['_GLOBAL__sub_I_' + name + '.cpp' for name in ['ugrep', 'output', 'query', 'stats', 'posix', 'unicode']]


def sha(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def replace(text, before, after):
    assert text.count(before) == 1, before
    return text.replace(before, after)


def patch(source, evidence, native_sources, bfs_package, ugrep_package, arch):
    assert not evidence.exists() and not (source / 'recovery-native').exists()
    for name, digest in HASHES.items(): assert sha(source / name) == digest, 'Unqualified Darwin source: ' + name
    provenance = {role: qualify(role, arch, package) for role, package in [('bfs', bfs_package), ('ugrep', ugrep_package)]}
    changes = plan_rust_graph(source, 'macos')
    entry = source / 'src/runtime/bin_entry/mod.rs'; before = entry.read_text()
    anchor = '    unsafe { bun_core::init_argv(argc, argv) };\n'
    after = replace(before, anchor, anchor + '''
    // Recovered macOS multicall boundary, before threads and cached env reads.
    #[cfg(target_os = "macos")]
    if let Some(status) = unsafe { recovered_multicall::dispatch(argc, argv) } {
        return status;
    }
''')
    after = replace(after, 'mod c_abi_exports;\n', 'mod c_abi_exports;\n#[cfg(target_os = "macos")]\nmod recovered_multicall;\n')
    changes.append(('entry', 'src/runtime/bin_entry/mod.rs', before, after))
    build = source / 'scripts/build/bun.ts'; before = build.read_text()
    anchor = '  const linkObjects = [...cxxObjects, ...cObjects, ...depLink.eager, ...rustObjects, ...windowsRes];\n'
    libraries = ''.join('    resolve(cfg.cwd, "recovery-native/' + role + '-libraries/' + name + '"),\n' for role in ['bfs', 'ugrep'] for name in ARCHIVES[role])
    after = replace(before, anchor, anchor + '  if (cfg.darwin) linkObjects.push(\n' + libraries + '  );\n')
    changes.append(('native-link', 'scripts/build/bun.ts', before, after))
    flags = source / 'scripts/build/flags.ts'; before = flags.read_text()
    after = replace(before, '    flag: ["-Wl,-no_compact_unwind", `-Wl,-stack_size,${DARWIN_STACK_SIZE}`, "-fno-keep-static-consts"],\n', '    flag: [`-Wl,-stack_size,${DARWIN_STACK_SIZE}`, "-fno-keep-static-consts"],\n')
    after = replace(after, '    desc: "18MB stack, skip compact unwind",\n', '    desc: "18MB stack; preserve source-built Ugrep exception unwind",\n')
    old = '''    flag: [
      "--remove-section=__TEXT,__eh_frame",
      "--remove-section=__TEXT,__unwind_info",
      "--remove-section=__TEXT,__gcc_except_tab",
    ],
'''
    after = replace(after, old, '    flag: [], // Real Ugrep exceptions need their final unwind/exception sections.\n')
    changes.append(('exception-sections', 'scripts/build/flags.ts', before, after))
    config = source / 'scripts/build/config.ts'; before = config.read_text()
    assert sha(config) in CONFIG_HASHES, 'Unqualified Darwin SDK-selection boundary'
    after = replace(before, '    ({ osxDeploymentTarget, osxSysroot } = detectMacosSdk(ci));\n', '''    if (partial.macosSdk === undefined) {
      ({ osxDeploymentTarget, osxSysroot } = detectMacosSdk(ci));
    } else {
      osxSysroot = resolveMacosSdkPath(partial.macosSdk, cacheDir, cwd);
      osxDeploymentTarget = MIN_OSX_DEPLOYMENT_TARGET;
    }
''')
    changes.append(('explicit-native-sdk', 'scripts/build/config.ts', before, after))
    expectations = source / 'scripts/build/binary-expectations.ts'; before = expectations.read_text()
    assert sha(expectations) == EXPECTATIONS_HASH
    after = replace(before, '  forbiddenImports: string[];\n', '  forbiddenImports: string[];\n  /** Exact source-library EH imports, required as well as allowed on Darwin. */\n  requiredExceptionImports?: string[];\n')
    anchor = '        format,\n        exports: { symbolList: src("symbols.txt"), exact: [], patterns: [] },\n'
    after = replace(after, anchor, '        format,\n        requiredExceptionImports: ' + json.dumps(EXCEPTION_IMPORTS) + ',\n        exports: { symbolList: src("symbols.txt"), exact: [], patterns: [] },\n')
    anchor = '  return initializers;\n'
    after = replace(after, anchor, '  // Six qualified Ugrep/RE-flex source initializers; no wildcard expansion.\n  if (cfg.darwin) initializers.push(' + ', '.join(json.dumps(v) for v in UGREP_INITIALIZERS) + ');\n' + anchor)
    changes.append(('source-library-contract', 'scripts/build/binary-expectations.ts', before, after))
    verifier = source / 'scripts/build/verify-binary.ts'; before = verifier.read_text(); assert sha(verifier) == VERIFIER_HASH
    anchor = '    const pat = globToRegExp(expect.forbiddenImports.map(p => `_${p}`));\n    const bad = imported.filter(s => pat.test(s));\n'
    after = replace(before, anchor, '''    const pat = globToRegExp(expect.forbiddenImports.map(p => `_${p}`));
    const required = (expect.requiredExceptionImports ?? []).map(p => `_${p}`);
    const bad = imported.filter(s => pat.test(s) && !required.includes(s));
    const missing = required.filter(s => !imported.includes(s));
''')
    anchor = '      bad.map(s => `+ ${s} (forbidden import)`),\n'
    # This exact reporting line appears in both ELF and Mach-O checks.
    position = after.index('    const required = (expect.requiredExceptionImports')
    tail = after[position:]; tail = replace(tail, anchor, '      [...bad.map(s => `+ ${s} (forbidden import)`), ...missing.map(s => `- ${s} (required exception import)`)],\n')
    after = after[:position] + tail
    changes.append(('source-library-import-check', 'scripts/build/verify-binary.ts', before, after))
    native = source / 'recovery-native'; stage(native_sources, native, target_os='macos')
    for role, package in [('bfs', bfs_package), ('ugrep', ugrep_package)]:
        folder = native / (role + '-libraries'); folder.mkdir()
        for name in ARCHIVES[role]: shutil.copyfile(package / 'native-library' / name, folder / name)
    copied = []
    for source_path, name in [(ROOT / 'recovered_multicall.rs', 'recovered_multicall.rs'), (ROOT.parent / 'native-role-contracts/darwin.rs', 'darwin_role_contract.rs')]:
        destination = entry.parent / name; assert not destination.exists(); shutil.copyfile(source_path, destination)
        copied.append(dict(file=destination.relative_to(source).as_posix(), sha256=sha(destination)))
    evidence.mkdir(); patches = []
    for label, name, before, after in changes:
        assert before != after; path = source / name; path.write_text(after); output = evidence / (label + '.patch')
        output.write_text(''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile='public-bun/' + name, tofile='recovered-bun/' + name)))
        patches.append(dict(file=name, before_sha256=hashlib.sha256(before.encode()).hexdigest(), after_sha256=sha(path), patch_sha256=sha(output)))
    receipt = dict(status='darwin_native_roles_patched_not_built', arch=arch, patches=patches, new_sources=copied,
        native_source_manifest_sha256=sha(native_sources / 'MANIFEST.json'), component_provenance=provenance,
        one_rust_std_graph_required=True, compiled_rust_archive_used=False, compiled_C_source_libraries_used=True,
        exception_imports=EXCEPTION_IMPORTS, source_initializers=UGREP_INITIALIZERS,
        allocator_GNU_symbol_versions_used=False, original_prefix_reused=False, recovered_erased_types=False,
        private_producer_revision_recovered=False, goal_complete=False)
    (evidence / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt

CONFIG_HASHES = {'aa4dafd7eccbbdee61722a326ce95a3a6dd105badb10af1f8b536ef84934bd7f', '8df541c3f3f3596b5d90f74161d0e946af2097fbe500a00355be3441bb5c046e'}
EXPECTATIONS_HASH = 'edd04de7530d876804fceef7c47511ce06811236ad568f6bd786e32ffaf1dec2'
VERIFIER_HASH = 'addabe198e33429c9ba830b24a03ac3d59e510cccc3c4b59a55f5974fb8931b8'
