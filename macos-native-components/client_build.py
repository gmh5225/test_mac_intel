"""Rebuild two private Mac clients from published data and an admitted source engine.

Captured input, extracted source and generated clients never enter diagnostics.
The only public formatting data are whitespace insertions and prior hashes.
"""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import os
import platform
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'seccomp-helper'))
from format_recipe import formatted
from bounded_process import run as bounded
from source_engine import qualify as qualify_engine
from component_libraries import sha
from macho_client_layout import inspect as signed_layout

RECIPE_SHA256 = 'c5acb4ce821b00bd7d99f1d08c723c46128319a8f162dced66bcbf71dcf6f61e'


def rows(path):
    result = []
    for i, line in enumerate(path.read_text().splitlines()):
        name, loader, encoding, form, side, file, size, digest = line.split('\t')
        result.append(dict(module_index=i, virtual_name=name, loader_id=int(loader), encoding_id=int(encoding), format_id=int(form), side_id=int(side), file=file, bytes=int(size), storage_sha256=digest))
    return result


def critical_sections(path):
    body = path.read_bytes(); header = struct.unpack_from('<8I', body); assert header[0] == 0xfeedfacf
    offset = 32; result = {}
    for _ in range(header[4]):
        command, size = struct.unpack_from('<II', body, offset); assert size >= 8 and offset + size <= 32 + header[5]
        if command == 0x19:
            count = struct.unpack_from('<I', body, offset + 64)[0]; assert size == 72 + count * 80
            for i in range(count):
                name, segment, address, length, fileoff = struct.unpack_from('<16s16sQQI', body, offset + 72 + i * 80)
                name, segment = name.split(b'\0')[0].decode(), segment.split(b'\0')[0].decode()
                if segment == '__TEXT' and name in ['__text', '__unwind_info', '__gcc_except_tab', '__eh_frame'] and length:
                    assert fileoff + length <= len(body) and name not in result
                    result[name] = dict(bytes=length, sha256=hashlib.sha256(body[fileoff:fileoff + length]).hexdigest())
        offset += size
    assert all(n in result for n in ['__text', '__unwind_info', '__gcc_except_tab'])
    return result


def build(arch, original, engine, output, logs, workspace=None, *, translated_compiler=False):
    native = platform.machine() == {'arm64': 'arm64', 'x64': 'x86_64'}[arch]
    assert platform.system() == 'Darwin' and os.getuid() != 0
    assert native or translated_compiler and arch == 'x64' and platform.machine() == 'arm64'
    assert not translated_compiler or not native, 'The diagnostic flag is only for an ARM host running the public x64 compiler'
    assert subprocess.run(['/usr/sbin/sysctl', '-n', 'sysctl.proc_translated'], capture_output=True).stdout != b'1\n'
    engine_receipt = qualify_engine(arch, engine)
    pin = json.loads((ROOT / 'original-pins.json').read_bytes())[arch]
    if original is not None:
        assert original.is_file() and not original.is_symlink() and original.stat().st_size == pin['bytes'] and sha(original) == pin['sha256']
    else: assert workspace is not None, 'A private source workspace is required without a published original input'
    recipe = ROOT / 'macos-readable-recipes-v1.json.gz'; assert sha(recipe) == RECIPE_SHA256
    recipes = json.loads(gzip.decompress(recipe.read_bytes())); assert recipes['kind'] == 'hash_pinned_whitespace_insertion_only' and not recipes['contains_captured_source']
    expected = recipes['profiles'][arch]; assert expected['module_count'] == 2609 and expected['source_count'] == 2364 and expected['entry_index'] == 6 and expected['startup_count'] == 7
    output.mkdir(); logs.mkdir(exist_ok=True); tools = output / 'tools'; tools.mkdir()
    def command(label, argv, timeout=180):
        with (logs / (label + '.stdout')).open('xb') as stdout, (logs / (label + '.stderr')).open('xb') as stderr:
            result = subprocess.run(list(map(str, argv)), stdout=stdout, stderr=stderr, timeout=timeout)
        assert result.returncode == 0, label + ' failed; inspect bounded diagnostics'
    for name in ['extract-native-graph', 'raw-graph-adapter', 'graph-fidelity-adapter']:
        command('compile-' + name, ['xcrun', 'clang++', '-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations', ROOT / (name + '.cpp'), '-o', tools / name])
    extracted = output / 'extracted'
    if original is not None:
        command('extract-published-graph', [tools / 'extract-native-graph', original, pin['sha256'], extracted])
        actual = rows(extracted / 'mapping.tsv')
    else:
        actual = [dict({k:v for k,v in row.items() if k != 'readable_sha256'},file='m'+str(row['module_index'])) for row in expected['rows']]
    assert [{k:v for k,v in row.items() if k != 'file'} for row in actual] == [{k:v for k,v in row.items() if k != 'readable_sha256'} for row in expected['rows']]
    receipt = dict(status='started', arch=arch, source_engine=engine_receipt, original_sha256=pin['sha256'],
        original_executed_during_build=False, clients_uploaded=False, captured_source_uploaded=False,
        formatting_recipe_sha256=RECIPE_SHA256, all_2609_original_rows_match_prior_NeverD=True,
        original_descriptor_provider_preserved=True, clients={}, goal_complete=False,
        original_input_supplied=original is not None, rebuild_input_mode='published_input_and_optional_workspace' if original is not None else 'private_source_workspace_and_pinned_module_identity_map',
        build_host_cpu=platform.machine(),native_target_CPU=native,translated_public_compiler_used=translated_compiler)
    try:
        for layout in ['preserved', 'readable']:
            work = output / layout; work.mkdir(); source = work / 'sources'; source.mkdir(); selected = []; edits = []
            if workspace is not None:
                supplied = workspace / layout / 'sources'; assert not any(p.is_symlink() for p in supplied.rglob('*'))
                assert {p.name for p in supplied.iterdir()} == {'m' + str(r['module_index']) for r in actual}
            for row in actual:
                name = 'm' + str(row['module_index'])
                if original is not None:
                    raw = (extracted / 'input' / row['file']).read_bytes(); assert hashlib.sha256(raw).hexdigest() == row['storage_sha256']
                    if layout == 'readable' and row['loader_id'] == 1: raw = formatted(raw, recipes['recipes'][row['storage_sha256']])
                if workspace is not None:
                    file = supplied / name; assert file.is_file() and file.stat().st_size <= 512 * 1024 * 1024
                    edited = file.read_bytes()
                    expected_sha = hashlib.sha256(raw).hexdigest() if original is not None else expected['rows'][row['module_index']].get('readable_sha256' if layout == 'readable' and row['loader_id'] == 1 else 'storage_sha256')
                    assert expected_sha is not None
                    if hashlib.sha256(edited).hexdigest() != expected_sha: edits.append(row['module_index'])
                    raw = edited
                (source / name).write_bytes(raw)
                selected.append([row['virtual_name'],row['loader_id'],row['encoding_id'],row['format_id'],row['side_id'],name,len(raw),hashlib.sha256(raw).hexdigest()])
            mapping = work / 'mapping.tsv'; mapping.write_text(''.join('\t'.join(map(str,r)) + '\n' for r in selected))
            stage = work / 'stage'; stage.mkdir()
            for name in ['runtime','project','work','home','tmp']: (stage / name).mkdir()
            runtime = stage / 'runtime/bun'; shutil.copyfile(engine, runtime); runtime.chmod(0o500)
            graph = stage / 'project/graph'
            command(layout + '-stage', [tools / 'raw-graph-adapter', 'stage', mapping, source, graph])
            # Qualify read/write, shell and network refusal with authored inputs
            # before captured source bodies are passed to the compiler.
            control = stage / 'runtime/boundary'
            command(layout + '-compile-boundary', ['xcrun','clang','-std=c11','-O2','-Wall','-Wextra','-Werror',ROOT/'boundary-control.c','-o',control])
            canary = work / 'outside-canary'; canary.write_bytes(b'owned outside build fixture\n')
            readable = stage / 'project/owned-control.txt'; readable.write_bytes(b'owned readable fixture\n')
            literal = lambda p:'(literal ' + json.dumps(str(p)) + ')'
            profile = '(version 1)\n(deny default)\n(allow sysctl-read)\n(allow file-read-metadata)\n'
            profile += '(allow file-read* file-map-executable (literal "/") (literal "/dev/null") (literal "/dev/urandom") (literal "/dev/random") (subpath "/System/Library") (subpath "/usr/lib") (subpath "/System/Volumes/Preboot/Cryptexes/OS"))\n'
            for folder in ['project','runtime','work','home','tmp']: profile += '(allow file-read* (subpath ' + json.dumps(str(stage / folder)) + '))\n'
            for folder in ['work','home','tmp']: profile += '(allow file-write* (subpath ' + json.dumps(str(stage / folder)) + '))\n'
            for binary in [runtime,control]: profile += '(allow file-map-executable process-exec ' + literal(binary) + ')\n'
            profile += '(allow process-fork)\n(allow signal (target self))\n(deny network*)\n'
            if translated_compiler:
                library=Path('/Library/Apple/usr/libexec/oah/libRosettaRuntime');assert library.is_file()
                profile += '(allow file-read* file-map-executable ' + literal(library) + ')\n'
                receipt['translated_compiler_library']=dict(path=str(library),sha256=sha(library))
            profile_path = logs / (layout + '-build-profile.sb'); profile_path.write_text(profile)
            environment = dict(HOME=str(stage / 'home'), TMPDIR=str(stage / 'tmp'), PATH='/unavailable', LANG='C', LC_ALL='C', BUN_RUNTIME_TRANSPILER_CACHE_PATH='0')
            row, stdout, stderr = bounded(layout + '-boundary', ['/usr/bin/sandbox-exec','-f',profile_path,control,canary,work/'forbidden-write',readable],stage/'work',environment,logs,wall=30,cpu=20)
            boundary = json.loads(stdout); assert row['exit_code'] == 0 and row['failure'] is None and not stderr
            assert boundary['readable'] == boundary['shell_exec_denied'] == 1 and len(boundary['network_errno']) == 4
            assert all(v in [1,13] for v in [boundary['outside_errno'],boundary['write_errno'],*boundary['network_errno']])
            assert not (work / 'forbidden-write').exists() and canary.read_bytes() == b'owned outside build fixture\n'
            row,stdout,stderr = bounded(layout+'-owned-compiler', ['/usr/bin/sandbox-exec','-f',profile_path,runtime,'-e','console.log(JSON.stringify({arch:process.arch,message:"owned source compiler"}))'],
                stage/'work',environment,logs,wall=60,cpu=30)
            attempts=[row]
            # Translation can stall before the public compiler produces its
            # first byte. One identical authored-probe retry remains bounded;
            # captured-source compilation is never retried or accepted here.
            if translated_compiler and row['failure']=='wall timeout' and not stdout and not stderr:
                row,stdout,stderr = bounded(layout+'-owned-compiler-retry', ['/usr/bin/sandbox-exec','-f',profile_path,runtime,'-e','console.log(JSON.stringify({arch:process.arch,message:"owned source compiler"}))'],
                    stage/'work',environment,logs,wall=60,cpu=30)
                attempts.append(row)
            receipt.setdefault('owned_compiler_startup',{})[layout]=attempts
            assert row['exit_code']==0 and row['failure'] is None and not stderr
            assert json.loads(stdout)==dict(arch=arch,message='owned source compiler')
            names = sorted(p.name for p in graph.iterdir())
            startup = [r['virtual_name'] for r in actual[:expected['startup_count']]]
            (graph / 'bootstrap.mjs').write_text(''.join('await import(JSON.parse(' + json.dumps(json.dumps(name)) + '));\n' for name in startup))
            scaffold = "import{fileURLToPath}from'node:url';const path=s=>fileURLToPath(new URL(s,import.meta.url));await Bun.build({entrypoints:[path('./bootstrap.mjs')],target:'bun',env:'disable',macros:false,minify:false,compile:{outfile:" + json.dumps(str(stage/'work/client')) + ",executablePath:process.execPath,assets:" + json.dumps(names,separators=(',',':')) + ".map(s=>path('./'+s))}});\n"
            (graph / 'build.isolated.mjs').write_text(scaffold)
            (stage / 'home/bunfig.toml').write_text('env = false\n')
            (stage / 'home/tsconfig.json').write_text('{"compilerOptions":{}}\n')
            row, _, _ = bounded(layout + '-compile-source', ['/usr/bin/sandbox-exec','-f',profile_path,runtime,'--config=' + str(stage / 'home/bunfig.toml'),'--tsconfig-override=' + str(stage / 'home/tsconfig.json'),graph/'build.isolated.mjs'],stage/'work',environment,logs,file_bytes=512*1024*1024)
            assert row['exit_code'] == 0 and row['failure'] is None, layout + ' source compile'
            client = work / 'client-final'
            command(layout + '-restore-graph', [tools/'graph-fidelity-adapter',mapping,stage/'work/client',client,actual[expected['entry_index']]['virtual_name'],expected['startup_count'],expected['flags'] & 15,8])
            command(layout + '-codesign', ['/usr/bin/codesign','--force','--sign','-','--pagesize','4096','--preserve-metadata=entitlements,requirements,flags',client])
            command(layout + '-signature-verify', ['/usr/bin/codesign','--verify','--strict',client]); client.chmod(0o500)
            signature=signed_layout(client);assert signature['signature']['code_directories'][0]['page_size']==4096
            (logs/(layout+'-signed-layout.json')).write_text(json.dumps(signature,indent=2)+'\n')
            readback = work / 'readback'; command(layout + '-readback', [tools/'extract-native-graph',client,sha(client),readback])
            rebuilt = rows(readback / 'mapping.tsv')
            assert [[r['virtual_name'],r['loader_id'],r['encoding_id'],r['format_id'],r['side_id'],r['bytes'],r['storage_sha256']] for r in rebuilt] == [r[:5]+r[6:] for r in selected]
            core = critical_sections(engine); assert critical_sections(client) == core
            receipt['clients'][layout] = dict(path=str(client),sha256=sha(client),bytes=client.stat().st_size,
                all_module_rows_match_selected_source=True,source_engine_code_and_exception_sections_preserved=core,intentionally_edited_modules=edits,
                code_signing_page_size=4096,signed_layout_sha256=sha(logs/(layout+'-signed-layout.json')))
            if edits: receipt['original_descriptor_provider_preserved'] = False
        receipt.update(status='both_Mac_source_engine_clients_rebuilt_and_2609_rows_readback_exactly',
            compiled_client_flags=4479, original_graph_flags=expected['flags'], original_caches_reused=False, actual_client_execution_acceptance=False)
        return receipt
    finally:
        (logs/'native-client-build.json').write_text(json.dumps(receipt,indent=2)+'\n')


if __name__ == '__main__':
    p=argparse.ArgumentParser();p.add_argument('--arch',choices=['arm64','x64'],required=True)
    for name in ['engine','output','logs']:p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--original',type=Path)
    p.add_argument('--translated-compiler',action='store_true',help='ARM host diagnostic: translate only the public x64 compiler; captured client execution is not accepted')
    p.add_argument('--workspace',type=Path);a=p.parse_args()
    print(json.dumps(build(a.arch,a.original.resolve() if a.original else None,a.engine.resolve(),a.output.resolve(),a.logs.resolve(),a.workspace.resolve() if a.workspace else None,translated_compiler=a.translated_compiler)))
