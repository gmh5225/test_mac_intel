"""Build private Windows clients with an admitted engine inside AppContainer."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
from client_workspace import recipe, prepare_from_extraction, select, check_readback
from coff_admission import sha
from source_engine import pin as pin_engine, critical_sections

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'windows-recovery'))
from client_acceptance import PINS
from core_tool_acceptance import fresh_root, environment, write
from contained_protocol import ContainedProtocol


def build(arch, original, engine, output, logs, qualified_environment, workspace=None, *, baseline_control=False):
    assert os.name == 'nt' and os.environ['RUNNER_ARCH'].lower() == arch
    provenance = pin_engine(arch, engine, baseline_control=baseline_control)
    qualified = json.loads((qualified_environment / 'evidence/receipt.json').read_bytes())
    assert qualified['status'] == 'authored_windows_environment_qualified' and qualified['architecture'] == arch
    assert qualified['isolation']['status'] == 'qualified' and qualified['authored_inputs_only']
    assert not qualified['captured_client_executed']
    assert original is not None or workspace is not None
    if original is not None:
        assert original.is_file() and not original.is_symlink() and sha(original) == PINS[arch]['original']
    output.mkdir(); logs.mkdir(); tools = output / 'tools'; tools.mkdir()
    _, expected = recipe(arch)
    env = dict(os.environ)
    for key in list(env):
        if key.startswith('ACTIONS_') or any(v in key.upper() for v in ['TOKEN', 'SECRET', 'PASSWORD']): env.pop(key)
    env.pop('ARGV0', None)
    clean = {k: v for k, v in env.items() if k.upper() in {'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'SYSTEMDRIVE'}}
    record = dict(status='started', arch=arch, source_engine=provenance, clients={},
        baseline_compiler_control_only=baseline_control,
        original_input_supplied=original is not None, original_executed=False, original_native_prefix_reused=False,
        compiled_client_flags=4479, original_graph_flags=expected['flags'], captured_source_uploaded=False, goal_complete=False)
    def trusted(label, args):
        with (logs / (label + '.stdout')).open('xb') as out, (logs / (label + '.stderr')).open('xb') as error:
            p = subprocess.run(list(map(str, args)), env=env, stdout=out, stderr=error, timeout=180)
        assert p.returncode == 0, 'Trusted graph tool failed; keep private diagnostics'
        assert (logs / (label + '.stdout')).stat().st_size <= 2 * 1024 * 1024
        assert (logs / (label + '.stderr')).stat().st_size <= 262144
    try:
        compiler = shutil.which('cl.exe', path=env['PATH']); assert compiler
        for name in ['extract-pinned-graph', 'raw-graph-windows-adapter', 'graph-fidelity-windows-adapter']:
            trusted('compile-' + name, [compiler, '/nologo', '/std:c++20', '/EHsc', '/O2', '/MT',
                ROOT.parent / 'windows-recovery' / (name + '.cpp'), '/Fo' + str(tools / (name + '.obj')),
                '/Fe' + str(tools / (name + '.exe')), '/link', 'bcrypt.lib'])
        if workspace is None:
            extracted = output / 'extracted'
            trusted('extract-original-data', [tools / 'extract-pinned-graph.exe', original, PINS[arch]['original'], extracted])
            workspace = output / 'source-workspace'; record['workspace_preparation'] = prepare_from_extraction(arch, extracted, workspace)
        core = critical_sections(engine, arch)
        for layout in ['preserved', 'readable']:
            work = output / layout; chosen, edits = select(arch, workspace, layout, work)
            root = fresh_root(); shutil.copyfile(engine, root / 'bin/bun.exe')
            assert sha(root / 'bin/bun.exe') == provenance['binary_sha256']
            graph = root / 'work/project'
            trusted(layout + '-stage', [tools / 'raw-graph-windows-adapter.exe', 'stage', work / 'mapping.tsv', work / 'sources', graph])
            assets = sorted(p.name for p in graph.iterdir())
            assert not set(assets) & {'bootstrap.mjs', 'build.isolated.mjs', 'bunfig.toml', 'tsconfig.json'}
            startup = [row['virtual_name'] for row in expected['rows'][:7]]
            (graph / 'bootstrap.mjs').write_text(''.join('await import(JSON.parse(' + json.dumps(json.dumps(name)) + '));\n' for name in startup), encoding='utf-8', newline='\n')
            client = root / 'work/client.exe'
            script = "import{fileURLToPath}from'node:url';const path=s=>fileURLToPath(new URL(s,import.meta.url));const r=await Bun.build({entrypoints:[path('./bootstrap.mjs')],target:'bun',env:'disable',macros:false,minify:false,compile:{outfile:" + json.dumps(str(client)) + ",executablePath:process.execPath,assets:" + json.dumps(assets,separators=(',',':')) + ".map(s=>path('./'+s))}});if(!r.success){console.error(r.logs);process.exit(1)};\n"
            (graph / 'build.isolated.mjs').write_text(script, encoding='utf-8', newline='\n')
            (graph / 'bunfig.toml').write_text('env=false\n', encoding='utf-8'); (graph / 'tsconfig.json').write_text('{"compilerOptions":{}}\n', encoding='utf-8')
            current = environment(clean, root, 0); current.update(BUN_RUNTIME_TRANSPILER_CACHE_PATH='0', NO_COLOR='1')
            own = root / 'bin/owned-compiler.mjs'
            own.write_text('const fs=require("node:fs");fs.writeFileSync("owned-compiler.txt","owned compiler write");console.log(JSON.stringify({arch:process.arch,revision:Bun.revision.slice(0,9),ARGV0_absent:process.env.ARGV0===undefined,writable:fs.readFileSync("owned-compiler.txt","utf8")==="owned compiler write"}));\n', encoding='utf-8')
            def contained(label, args):
                folder = logs / (layout + '-' + label); folder.mkdir()
                # The launcher uses exclusive output files on every invocation;
                # the prior invocation has already retained both complete logs.
                for suffix in ['stdout', 'stderr']:
                    old = root / ('target.' + suffix)
                    if old.exists(): old.unlink()
                p = ContainedProtocol(qualified_environment / 'appcontainer-run.exe', root, current, 'bun.exe', args, folder, 'process')
                try:
                    if label == 'compile':
                        # Honor the launcher's existing 45-second OS deadline.
                        # Compilation has no interactive input; finish() then
                        # collects the same bounded launcher metadata normally.
                        p.process.stdin.close(); p.process.wait(timeout=60)
                    execution = p.finish()
                finally: p.retain()
                assert execution['exit_code'] == 0 and not execution['timeout'] and not execution['output_limit']
                assert execution['app_container'] and execution['capability_count'] == 0 and execution['remaining_processes'] == 0
                assert not execution['loopback_exemption'] and execution['loopback_exemption_removed'] and execution['null_device_grant_removed']
                assert not (folder / 'process.stderr').read_bytes(), 'Compiler emitted private diagnostics'
                return execution, (folder / 'process.stdout').read_bytes()
            control, raw = contained('owned-compiler', [own])
            assert json.loads(raw) == dict(arch=arch, revision='c6da4a4d3', ARGV0_absent=True, writable=True)
            execution, _ = contained('compile', ['--config=' + str(graph / 'bunfig.toml'), '--tsconfig-override=' + str(graph / 'tsconfig.json'), graph / 'build.isolated.mjs'])
            assert sha(root / 'bin/bun.exe') == provenance['binary_sha256'] and client.is_file() and not client.is_symlink()
            final = work / 'client-final.exe'
            trusted(layout + '-restore', [tools / 'graph-fidelity-windows-adapter.exe', work / 'mapping.tsv', client,
                final, expected['rows'][6]['virtual_name'], '7', '15', '8'])
            trusted(layout + '-readback', [tools / 'extract-pinned-graph.exe', final, sha(final), work / 'readback'])
            readback = check_readback(work / 'readback/mapping.tsv', chosen)
            # Hash-only typed inventories permit independent CI readback joins
            # without publishing source, assets or the rebuilt executable.
            for suffix, mapping in [('selected', work / 'mapping.tsv'), ('readback', work / 'readback/mapping.tsv')]:
                (logs / (layout + '-' + suffix + '-mapping.tsv')).write_text(mapping.read_text(encoding='utf-8'), encoding='utf-8', newline='\n')
            assert critical_sections(final, arch) == core
            record['clients'][layout] = dict(path=str(final), bytes=final.stat().st_size, sha256=sha(final),
                intentionally_edited_modules=edits, readback=readback, source_engine_code_and_exception_sections_preserved=core,
                native_compiler_execution=execution, owned_compiler_execution=control)
        record.update(status='both_native_Windows_baseline_diagnostic_clients_rebuilt_and_2586_typed_rows_readback_exactly' if baseline_control else 'both_native_Windows_private_clients_rebuilt_and_2586_typed_rows_readback_exactly',
            original_provider_source_adapted=False, source_only_workspace=original is None)
        return record
    finally: write(logs / 'native-client-build.json', record)
