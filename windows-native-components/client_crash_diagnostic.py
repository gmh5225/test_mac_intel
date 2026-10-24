"""Private baseline/full-engine and JSC-option comparisons; no admission claim."""
from pathlib import Path
import argparse, base64, contextlib, hashlib, json, os, shutil, tarfile, traceback, urllib.request
from client_build import build
from client_build_controls import seal_failure
from source_engine import pin as pin_engine
from coff_admission import sha
from client_acceptance import PINS
from core_tool_acceptance import fresh_root, environment, write
from contained_protocol import ContainedProtocol


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--arch', required=True, choices=['arm64', 'x64'])
    for name in ['engine', 'baseline', 'environment']: ap.add_argument('--' + name, type=Path, required=True)
    a = ap.parse_args(); out = a.environment.resolve(); engine = a.engine.resolve(); baseline = a.baseline.resolve()
    q = json.loads((out / 'evidence/receipt.json').read_bytes())
    assert q['status'] == 'authored_windows_environment_qualified' and q['architecture'] == a.arch and q['isolation']['status'] == 'qualified'
    full = pin_engine(a.arch, engine); base = pin_engine(a.arch, baseline, baseline_control=True)
    private = out / 'private-crash-diagnostic'; private.mkdir(); records = private / 'execution-records'; records.mkdir(); logs = private / 'client-build-logs'; logs.mkdir()
    public = out / 'evidence/private-crash-diagnostic'; public.mkdir()
    receipt = dict(status='started', arch=a.arch, full_source_engine=full, baseline_engine=base, observations=[],
        production_qualification=False, goal_complete=False, source_or_client_uploaded=False, original_provider_source_adapted=False)
    try:
        owned = private / 'owned'; (owned / 'execution-records').mkdir(parents=True)
        (owned / 'execution-records/owned.stdout').write_bytes(b'owned private crash diagnostic envelope\n')
        check = public / 'owned-envelope-control'; check.mkdir(); write(check / 'receipt.json', seal_failure(owned, check))
        pins = PINS[a.arch]; archive = private / 'original.tgz'
        with urllib.request.urlopen(f'https://registry.npmjs.org/@anthropic-ai/claude-code-win32-{a.arch}/-/claude-code-win32-{a.arch}-2.1.296.tgz', timeout=90) as response:
            data = response.read(160 * 1024 * 1024 + 1)
        assert len(data) <= 160 * 1024 * 1024 and hashlib.sha512(data).digest() == base64.b64decode(pins['integrity']); archive.write_bytes(data)
        original = private / 'original.exe'
        with tarfile.open(archive, 'r:gz') as tar:
            member = tar.getmember('package/claude.exe'); assert member.isfile() and member.size < 300 * 1024 * 1024
            original.write_bytes(tar.extractfile(member).read())
        assert sha(original) == pins['original']
        with (records / 'private-progress.txt').open('x', encoding='utf-8') as progress, contextlib.redirect_stdout(progress), contextlib.redirect_stderr(progress):
            rebuilt = build(a.arch, original, engine, private / 'full', logs / 'full', out)
            unmodified = build(a.arch, None, baseline, private / 'baseline', logs / 'baseline', out,
                workspace=private / 'full/source-workspace', baseline_control=True)
            receipt['builds'] = dict(full=rebuilt, baseline=unmodified)
            clean = {k: v for k, v in os.environ.items() if k.upper() in {'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'SYSTEMDRIVE'}}
            variants = [('default', {}), ('no-jit', {'BUN_JSC_useJIT': '0'}),
                ('serial-jit-and-gc', {'BUN_JSC_useConcurrentJIT': '0', 'BUN_JSC_numberOfGCMarkers': '1'})]
            binaries = {'original': original}
            for prefix, built in [('full', rebuilt), ('baseline', unmodified)]:
                for layout, row in built['clients'].items(): binaries[prefix + '-' + layout] = Path(row['path'])
            for label, binary in binaries.items():
                for option, values in variants:
                    for case, argv in [('version', ['--version']), ('help', ['--help']), ('mcp-help', ['mcp', '--help'])]:
                        name = label + '-' + option + '-' + case; folder = records / name; folder.mkdir()
                        root = fresh_root(); shutil.copyfile(binary, root / 'bin/client.exe'); env = environment(clean, root, 9)
                        env.update(NO_COLOR='1', BUN_RUNTIME_TRANSPILER_CACHE_PATH='0', **values)
                        process = ContainedProtocol(out / 'appcontainer-run.exe', root, env, 'client.exe', argv, folder, 'client')
                        try: execution = process.finish()
                        finally: process.retain()
                        assert not execution['loopback_exemption'] and execution['loopback_exemption_removed'] and execution['null_device_grant_removed']
                        assert sha(root / 'bin/client.exe') == sha(binary)
                        row = dict(case=name, input_sha256=sha(binary), JSC_diagnostic_options=values, execution=execution,
                            stdout_sha256=sha(folder / 'client.stdout'), stderr_sha256=sha(folder / 'client.stderr'))
                        receipt['observations'].append(row); write(folder / 'receipt.json', row); write(private / 'private-harness-receipt.json', receipt)
            receipt.update(status='private_native_client_baseline_and_JSC_option_diagnostic_matrix_collected',
                original_preserved=sha(original) == pins['original'], observed_processes=len(receipt['observations']))
    except BaseException as error:
        receipt.update(status='private_crash_diagnostic_failed', error_type=type(error).__name__, private_error=str(error)[:4096],
            private_traceback=traceback.format_exc(limit=12)[:16384])
    write(private / 'private-harness-receipt.json', receipt)
    envelope = seal_failure(private, public)
    write(public / 'summary.json', dict(status=receipt['status'], arch=a.arch, observed_processes=len(receipt['observations']),
        observations=receipt['observations'], private_logs_export=envelope, raw_streams_exported=False, production_qualification=False))
    assert receipt['status'] == 'private_native_client_baseline_and_JSC_option_diagnostic_matrix_collected', 'Inspect authenticated private diagnostic envelope'
    print(json.dumps(dict(status=receipt['status'], arch=a.arch, observed_processes=len(receipt['observations']))))


if __name__ == '__main__': main()
