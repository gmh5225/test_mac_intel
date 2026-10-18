"""Authored string-sort probes across official, public baseline and full engines."""
from pathlib import Path
import argparse, json, os, shutil
from source_engine import pin as pin_engine
from coff_admission import sha
from core_tool_acceptance import fresh_root, environment, write
from contained_protocol import ContainedProtocol


def main():
    ap = argparse.ArgumentParser()
    for name in ['engine', 'baseline', 'environment']: ap.add_argument('--' + name, type=Path, required=True)
    a = ap.parse_args(); out = a.environment.resolve(); q = json.loads((out / 'evidence/receipt.json').read_bytes())
    assert q['status'] == 'authored_windows_environment_qualified' and q['architecture'] == 'arm64' and q['isolation']['status'] == 'qualified'
    assert not q['captured_client_executed'] and q['authored_inputs_only']
    release = out / 'bun.exe'; assert sha(release) == q['runtime']['exe_sha256']
    proof = dict(full=pin_engine('arm64', a.engine.resolve()), baseline=pin_engine('arm64', a.baseline.resolve(), baseline_control=True),
        official=dict(binary_sha256=sha(release), authored_environment_qualification=True))
    probes = [
        ('version', 'console.log(JSON.stringify({arch:process.arch,version:Bun.version}));\n', b'{"arch":"arm64","version":"1.4.3"}\n'),
        ('Headers-ASCII', 'const h=new Headers([["z","last"],["a","first"],["m","middle"]]);console.log(JSON.stringify([...h.entries()]));\n', b'[["a","first"],["m","middle"],["z","last"]]\n'),
        ('URLSearchParams-ASCII', 'const p=new URLSearchParams("z=last&a=first&m=middle");p.sort();console.log(JSON.stringify([...p.entries()]));\n', b'[["a","first"],["m","middle"],["z","last"]]\n'),
        ('URLSearchParams-UTF16', 'const p=new URLSearchParams([["猫","cat"],["a","first"],["λ","lambda"]]);p.sort();console.log(JSON.stringify([...p.entries()]));\n', '[["a","first"],["λ","lambda"],["猫","cat"]]\n'.encode()),
        ('URLSearchParams-stable-prefix', 'const p=new URLSearchParams([["aa","long"],["a","one"],["a","two"],["","empty"]]);p.sort();console.log(JSON.stringify([...p.entries()]));\n', b'[["","empty"],["a","one"],["a","two"],["aa","long"]]\n'),
    ]
    logs = out / 'evidence/public-runtime-ABI-controls'; logs.mkdir()
    clean = {k: v for k, v in os.environ.items() if k.upper() in {'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'SYSTEMDRIVE'}}
    receipt = dict(status='started', arch='arm64', inputs=proof, cases=[], captured_input_used=False, production_qualification=False)
    for label, binary in [('official', release), ('baseline', a.baseline.resolve()), ('full', a.engine.resolve())]:
        for mode, options in [('default', {}), ('no-jit', dict(BUN_JSC_useJIT='0'))]:
            for case, script, wanted in probes:
                name = label + '-' + mode + '-' + case; log = logs / name; log.mkdir(); root = fresh_root()
                shutil.copyfile(binary, root / 'bin/bun.exe'); path = root / 'bin/owned.mjs'; path.write_text(script, encoding='utf-8', newline='\n')
                env = environment(clean, root, 9); env.update(NO_COLOR='1', BUN_RUNTIME_TRANSPILER_CACHE_PATH='0', **options)
                process = ContainedProtocol(out / 'appcontainer-run.exe', root, env, 'bun.exe', [path], log, 'process')
                try: meta = process.finish()
                finally: process.retain()
                assert not meta['loopback_exemption'] and meta['loopback_exemption_removed'] and meta['null_device_grant_removed']
                assert sha(root / 'bin/bun.exe') == sha(binary)
                observed = (log / 'process.stdout').read_bytes(); error = (log / 'process.stderr').read_bytes()
                row = dict(case=case, engine=label, mode=mode, execution=meta, input_sha256=sha(binary),
                    script_sha256=sha(path), expected_stdout_hex=wanted.hex(), stdout_sha256=sha(log / 'process.stdout'),
                    stderr_sha256=sha(log / 'process.stderr'), exact_owned_oracle_pass=meta['exit_code'] == 0 and observed == wanted and not error)
                assert case != 'version' or row['exact_owned_oracle_pass'], 'Basic authored runtime control failed'
                write(log / 'owned-script.json', dict(source=script, JSC_options=options)); write(log / 'receipt.json', row)
                receipt['cases'].append(row); write(logs / 'receipt.json', receipt)
    receipt.update(status='authored_official_baseline_and_full_runtime_string_sort_matrix_collected', observations=len(receipt['cases']))
    write(logs / 'receipt.json', receipt); print(json.dumps(dict(status=receipt['status'], observations=len(receipt['cases']), failures=[r['engine'] + ':' + r['mode'] + ':' + r['case'] for r in receipt['cases'] if not r['exact_owned_oracle_pass']])))


if __name__ == '__main__': main()
