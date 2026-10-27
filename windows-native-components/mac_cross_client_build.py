"""Rebuild a private Windows source workspace with an admitted Mac compiler.

The target PE is read as data; no Windows executable runs on Mac.
"""
from pathlib import Path
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
import platform
import shutil
import subprocess

from coff_admission import ROOT, sha
from source_engine import pin as pin_engine
from source_engine import critical_sections
from client_workspace import rows, RECIPE_SHA256, select

MAC = ROOT.parent / 'macos-native-components'
spec = importlib.util.spec_from_file_location('Windows_mac_bounded_process', MAC / 'bounded_process.py')
bounded = importlib.util.module_from_spec(spec); spec.loader.exec_module(bounded)


def build(arch, workspace, engine, compiler, output, logs, *, baseline_control=False):
    assert platform.system() == 'Darwin' and os.getuid() != 0
    host = {'arm64': 'arm64', 'x86_64': 'x64'}[platform.machine()]
    assert subprocess.run(['/usr/sbin/sysctl', '-n', 'sysctl.proc_translated'], capture_output=True).stdout != b'1\n'
    pins = json.loads((MAC / 'source-engine-pins.json').read_bytes())
    assert pins['schema_version'] == 1 and pins['status'] == 'two_full_source_engines_independently_qualified_on_native_macos15_and26'
    assert compiler.is_file() and not compiler.is_symlink() and sha(compiler) == pins['profiles'][host]['binary_sha256']
    engine_proof = pin_engine(arch, engine, baseline_control=baseline_control)
    recipe = ROOT / 'windows-readable-recipes-v1.json.gz'; assert sha(recipe) == RECIPE_SHA256
    data = json.loads(gzip.decompress(recipe.read_bytes()))
    assert data['kind'] == 'hash_pinned_whitespace_insertion_only' and not data['contains_captured_source']
    expected = data['profiles'][arch]
    assert expected['module_count'] == 2586 and expected['source_count'] == 2343 and expected['entry_index'] == 6 and expected['startup_count'] == 7 and expected['flags'] in [8191, 7167]
    assert workspace.is_dir() and not any(p.is_symlink() for p in workspace.rglob('*'))
    output.mkdir(); logs.mkdir(); tools = output / 'tools'; tools.mkdir()
    receipt = dict(status='started', arch=arch, source_engine=engine_proof, Mac_source_compiler=pins['profiles'][host],
        compiler_sha256=sha(compiler), Mac_compiler_pin_sha256=sha(MAC / 'source-engine-pins.json'),
        original_input_supplied=False, original_executed=False, target_PE_executed=False, original_caches_reused=False,
        compiled_client_flags=4479, original_graph_flags=expected['flags'], source_only_workspace=True, clients={}, goal_complete=False)
    def trusted(label, argv):
        with (logs / (label + '.stdout')).open('xb') as out, (logs / (label + '.stderr')).open('xb') as err:
            r = subprocess.run(list(map(str, argv)), stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=120)
        assert r.returncode == 0 and (logs / (label + '.stdout')).stat().st_size <= 2 * 1024 * 1024 and (logs / (label + '.stderr')).stat().st_size <= 262144, label
    for name in ['extract-pinned-graph', 'raw-graph-windows-adapter', 'graph-fidelity-windows-adapter']:
        trusted('compile-' + name, ['xcrun', 'clang++', '-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations', ROOT.parent / 'windows-recovery' / (name + '.cpp'), '-o', tools / name])
    try:
        for layout in ['preserved', 'readable']:
            work = output / layout
            selected, edits = select(arch, workspace, layout, work)
            sources = work / 'sources'; mapping = work / 'mapping.tsv'
            stage = work / 'stage'; stage.mkdir()
            for name in ['runtime', 'input', 'work', 'home', 'tmp']: (stage / name).mkdir()
            runtime = stage / 'runtime/bun'; shutil.copyfile(compiler, runtime); runtime.chmod(0o500)
            target = stage / 'runtime/target-PE'; shutil.copyfile(engine, target); target.chmod(0o400)
            graph = stage / 'input/project'
            trusted(layout + '-stage', [tools / 'raw-graph-windows-adapter', 'stage', mapping, sources, graph])
            assets = sorted(p.name for p in graph.iterdir())
            control = stage / 'runtime/boundary'
            trusted(layout + '-compile-boundary', ['xcrun', 'clang', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', MAC / 'boundary-control.c', '-o', control])
            canary = work / 'outside-sentinel'; canary.write_bytes(b'owned outside build fixture\n')
            readable = graph / 'owned.txt'; readable.write_bytes(b'owned readable fixture\n')
            profile = '(version 1)\n(deny default)\n(allow sysctl-read)\n(allow file-read-metadata)\n'
            profile += '(allow file-read* file-map-executable (literal "/") (literal "/dev/null") (literal "/dev/urandom") (literal "/dev/random") (subpath "/System/Library") (subpath "/usr/lib") (subpath "/System/Volumes/Preboot/Cryptexes/OS"))\n'
            for name in ['runtime', 'input', 'work', 'home', 'tmp']: profile += '(allow file-read* (subpath ' + json.dumps(str(stage / name)) + '))\n'
            for name in ['work', 'home', 'tmp']: profile += '(allow file-write* (subpath ' + json.dumps(str(stage / name)) + '))\n'
            for binary in [runtime, control]: profile += '(allow file-map-executable process-exec (literal ' + json.dumps(str(binary)) + '))\n'
            profile += '(allow process-fork)\n(allow signal (target self))\n(deny network*)\n'
            policy = logs / (layout + '-profile.sb'); policy.write_text(profile)
            env = dict(HOME=str(stage / 'home'), TMPDIR=str(stage / 'tmp'), PATH='/unavailable', LANG='C', LC_ALL='C', BUN_RUNTIME_TRANSPILER_CACHE_PATH='0')
            def isolated(label, argv, *, write=False):
                record, out, err = bounded.run(layout + '-' + label, ['/usr/bin/sandbox-exec', '-f', policy, *argv], stage / 'input', env, logs,
                    wall=180 if write else 60, cpu=120 if write else 30, file_bytes=512 * 1024 * 1024 if write else 0)
                assert record['failure'] is None and not record['kill_errors'] and record['exit_code'] == 0 and not err, layout + '-' + label
                return out
            boundary = json.loads(isolated('boundary', [control, canary, work / 'forbidden-write', readable]))
            assert boundary['readable'] == boundary['shell_exec_denied'] == 1 and len(boundary['network_errno']) == 4
            assert all(n in [1, 13] for n in [boundary['outside_errno'], boundary['write_errno'], *boundary['network_errno']])
            assert not (work / 'forbidden-write').exists() and canary.read_bytes() == b'owned outside build fixture\n'
            owned = json.loads(isolated('owned-compiler', [runtime, '-e', 'console.log(JSON.stringify({arch:process.arch,revision:Bun.revision.slice(0,9),message:"owned Mac Windows source compiler"}))']))
            assert owned == dict(arch=host, revision='c6da4a4d3', message='owned Mac Windows source compiler')
            startup = [row['virtual_name'] for row in expected['rows'][:7]]
            (graph / 'bootstrap.mjs').write_text(''.join('await import(JSON.parse(' + json.dumps(json.dumps(name)) + '));\n' for name in startup))
            # CWD input + nested project yields project/bootstrap.mjs, also
            # used by the native Windows AppContainer compiler. Windows
            # also uses the compile output basename as its internal module name;
            # client.exe must produce the already-qualified root/client entry.
            script = "import{fileURLToPath}from'node:url';const path=s=>fileURLToPath(new URL(s,import.meta.url));await Bun.build({entrypoints:[path('./bootstrap.mjs')],target:'bun',env:'disable',macros:false,minify:false,compile:{target:" + json.dumps('bun-windows-' + arch) + ",outfile:" + json.dumps(str(stage / 'work/client.exe')) + ",executablePath:" + json.dumps(str(target)) + ",assets:" + json.dumps(assets, separators=(',', ':')) + ".map(s=>path('./'+s))}});\n"
            (graph / 'build.isolated.mjs').write_text(script); (graph / 'bunfig.toml').write_text('env=false\n'); (graph / 'tsconfig.json').write_text('{"compilerOptions":{}}\n')
            isolated('compile', [runtime, '--config=' + str(graph / 'bunfig.toml'), '--tsconfig-override=' + str(graph / 'tsconfig.json'), graph / 'build.isolated.mjs'], write=True)
            client = work / 'client-final'
            trusted(layout + '-restore', [tools / 'graph-fidelity-windows-adapter', mapping, stage / 'work/client.exe', client, expected['rows'][6]['virtual_name'], '7', '15', '8'])
            client.chmod(0o500)
            trusted(layout + '-readback', [tools / 'extract-pinned-graph', client, sha(client), work / 'readback'])
            actual = rows(work / 'readback/mapping.tsv')
            assert [[r['virtual_name'], r['loader_id'], r['encoding_id'], r['format_id'], r['side_id'], r['bytes'], r['storage_sha256']] for r in actual] == [row[:5] + row[6:] for row in selected]
            critical = critical_sections(engine, arch); assert critical_sections(client, arch) == critical
            receipt['clients'][layout] = dict(path=str(client), bytes=client.stat().st_size, sha256=sha(client), intentionally_edited_modules=edits,
                all_2586_rows_match_selected_source=True, source_engine_code_and_exception_sections_preserved=critical)
        receipt.update(status='Mac_source_only_Windows_clients_rebuilt_and_readback_exactly', baseline_compiler_control_only=baseline_control, original_provider_source_adapted=False)
        return receipt
    finally: (logs / 'native-client-build.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--arch', choices=['arm64', 'x64'], required=True)
    for name in ['workspace', 'engine', 'compiler', 'output', 'logs']: parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--baseline-compiler-control', action='store_true')
    args = parser.parse_args()
    result = build(args.arch, args.workspace.resolve(), args.engine.resolve(), args.compiler.resolve(), args.output.resolve(), args.logs.resolve(), baseline_control=args.baseline_compiler_control)
    print(json.dumps(dict(status=result['status'], clients={k: dict(sha256=v['sha256'], bytes=v['bytes'], edits=v['intentionally_edited_modules']) for k, v in result['clients'].items()}, target_PE_executed=False)))
