"""Native clean, source-only and one-entry-edit builds; private inputs stay local."""
from pathlib import Path
import argparse
import base64
import contextlib
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import tarfile
import traceback
import urllib.request
from client_build import build
from source_engine import pin as pin_engine
from coff_admission import sha

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'windows-recovery'))
from client_acceptance import PINS
from core_tool_acceptance import fresh_root, environment, write
from contained_protocol import ContainedProtocol


def seal_failure(private, public):
    module_path = ROOT.parent / 'musl-native-components/private_diagnostics.py'
    spec = importlib.util.spec_from_file_location('Windows_private_diagnostic_envelope', module_path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    choices = [Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Git/usr/bin/openssl.exe',
        Path('C:/Program Files/Git/mingw64/bin/openssl.exe')]
    found = shutil.which('openssl')
    if found: choices.insert(0, Path(found))
    selected = next((p for p in choices if p.is_file()), None)
    assert selected is not None, 'Private diagnostic encryption runtime unavailable'
    previous = os.environ.get('PATH', '')
    try:
        os.environ['PATH'] = str(selected.parent) + os.pathsep + previous
        return module.seal(private, public)
    finally: os.environ['PATH'] = previous


def main():
    p = argparse.ArgumentParser(); p.add_argument('--arch', required=True, choices=['arm64', 'x64'])
    p.add_argument('--engine', type=Path, required=True); p.add_argument('--environment', type=Path, required=True); a = p.parse_args()
    out = a.environment.resolve(); qualified = json.loads((out / 'evidence/receipt.json').read_bytes())
    assert qualified['status'] == 'authored_windows_environment_qualified' and qualified['architecture'] == a.arch
    assert qualified['authored_inputs_only'] and not qualified['captured_client_executed'] and qualified['isolation']['status'] == 'qualified'
    engine = a.engine.resolve(); provenance = pin_engine(a.arch, engine)
    private = out / 'private-client-controls'; private.mkdir(); logs = private / 'client-build-logs'; logs.mkdir()
    records = private / 'execution-records'; records.mkdir()
    receipt = dict(status='started', arch=a.arch, source_engine=provenance, builds=[], versions=[],
        original_executed=False, rebuilt_captured_source_executed=False, original_native_prefix_reused=False,
        captured_original_source_or_client_exported=False, goal_complete=False)
    public = out / 'evidence/complete-source-client-build-controls'; public.mkdir()
    try:
        control = private / 'owned-envelope-control'; (control / 'execution-records').mkdir(parents=True)
        (control / 'execution-records/owned.stdout').write_bytes(b'owned Windows diagnostic envelope control\n')
        encrypted = public / 'owned-envelope-control'; encrypted.mkdir()
        write(encrypted / 'receipt.json', seal_failure(control, encrypted))
        pins = PINS[a.arch]; archive = private / 'original-input.tgz'
        with urllib.request.urlopen(f'https://registry.npmjs.org/@anthropic-ai/claude-code-win32-{a.arch}/-/claude-code-win32-{a.arch}-2.1.296.tgz', timeout=90) as response:
            body = response.read(160 * 1024 * 1024 + 1)
        assert len(body) <= 160 * 1024 * 1024 and hashlib.sha512(body).digest() == base64.b64decode(pins['integrity']); archive.write_bytes(body)
        original = private / 'original.exe'
        with tarfile.open(archive, 'r:gz') as t:
            member = t.getmember('package/claude.exe'); assert member.isfile() and member.size <= 300 * 1024 * 1024
            original.write_bytes(t.extractfile(member).read())
        assert sha(original) == pins['original']; receipt['original_sha256'] = sha(original)
        for i in [1, 2]:
            result = build(a.arch, original if i == 1 else None, engine, private / ('build-' + str(i)),
                logs / ('build-' + str(i)), out, workspace=None if i == 1 else private / 'build-1/source-workspace')
            receipt['builds'].append(result); write(private / 'private-harness-receipt.json', receipt)
        for layout in ['preserved', 'readable']:
            assert receipt['builds'][0]['clients'][layout]['sha256'] == receipt['builds'][1]['clients'][layout]['sha256'], 'Native original-data and source-only builds differ'
        edited = private / 'edited-workspace'; shutil.copytree(private / 'build-1/source-workspace', edited)
        entry = edited / 'readable/sources/m6'; source = entry.read_bytes(); old = b'(Claude Code)'; new = b'(Claude Code recovery source control)'
        assert source.count(old) == 1; entry.write_bytes(source.replace(old, new))
        result = build(a.arch, None, engine, private / 'build-edited', logs / 'build-edited', out, workspace=edited)
        receipt['builds'].append(result)
        assert result['clients']['preserved']['sha256'] == receipt['builds'][0]['clients']['preserved']['sha256']
        assert result['clients']['preserved']['intentionally_edited_modules'] == [] and result['clients']['readable']['intentionally_edited_modules'] == [6]
        clean = {k: v for k, v in os.environ.items() if k.upper() in {'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'SYSTEMDRIVE'}}
        for i, result in enumerate(receipt['builds']):
            for layout, row in result['clients'].items():
                root = fresh_root(); shutil.copyfile(row['path'], root / 'bin/client.exe'); log = records / (str(i) + '-' + layout); log.mkdir()
                env = environment(clean, root, 0); env.update(BUN_RUNTIME_TRANSPILER_CACHE_PATH='0', NO_COLOR='1')
                env.update(CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC='1', DISABLE_AUTOUPDATER='1', ENABLE_CLAUDEAI_MCP_SERVERS='false')
                process = ContainedProtocol(out / 'appcontainer-run.exe', root, env, 'client.exe', ['--version'], log, 'process')
                try: execution = process.finish()
                finally: process.retain()
                assert execution['exit_code'] == 0 and not execution['timeout'] and not execution['output_limit']
                assert execution['app_container'] and execution['capability_count'] == 0 and execution['remaining_processes'] == 0
                assert not execution['loopback_exemption'] and execution['loopback_exemption_removed'] and execution['null_device_grant_removed']
                wanted = b'2.1.296 ' + (new if i == 2 and layout == 'readable' else old) + b'\n'
                assert (log / 'process.stdout').read_bytes() == wanted and not (log / 'process.stderr').read_bytes(), 'Controlled client version differs'
                assert sha(root / 'bin/client.exe') == row['sha256']
                receipt['versions'].append(dict(build=i, layout=layout, client_sha256=row['sha256'], stdout_hex=wanted.hex(), execution=execution))
                receipt['rebuilt_captured_source_executed'] = True; write(private / 'private-harness-receipt.json', receipt)
        assert len(receipt['versions']) == 6 and sha(original) == pins['original']
        receipt.update(status='native_Windows_source_only_pristine_and_one_entry_edit_controls_passed',
            readback_rows=15516, version_executions=6, actual_protocol_client_acceptance=False)
        write(private / 'private-harness-receipt.json', receipt)
        shutil.copytree(logs, public / 'client-build-logs'); shutil.copytree(records, public / 'execution-records'); write(public / 'receipt.json', receipt)
        print(json.dumps(dict(status=receipt['status'], arch=a.arch, readback_rows=15516, versions=6)))
    except BaseException as error:
        receipt['status'] = 'failed_not_admitted'; receipt['error_type'] = type(error).__name__
        receipt['private_error'] = str(error)[:4096]
        receipt['private_traceback'] = traceback.format_exc(limit=12)[:16384]
        write(private / 'private-harness-receipt.json', receipt)
        try: envelope = seal_failure(private, public)
        except BaseException as sealing_error: envelope = dict(status='not_exported', error_type=type(sealing_error).__name__, plaintext_exported=False)
        write(public / 'failure-summary.json', dict(status='failed_not_admitted', arch=a.arch,
            error_type=type(error).__name__, private_logs_export=envelope, original_or_client_files_exported=False))
        raise RuntimeError('Native client controls failed; inspect only the private or encrypted diagnostic records') from None


if __name__ == '__main__': main()
