"""Private source-built clients against the pinned original and shared oracles."""
from pathlib import Path
import argparse
import base64
import contextlib
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import traceback
import urllib.request
from client_build import build
from client_build_controls import seal_failure
from client_search import accept_source_search
from source_engine import pin as pin_engine
from coff_admission import sha

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'windows-recovery'))
from client_acceptance import PINS
from configuration_acceptance import accept_configuration
from behavior_acceptance import accept_behavior
from core_tool_acceptance import accept_core_tools, accept_read_truncation, fresh_root, environment, write
from native_acceptance import accept_native
from contained_protocol import ContainedProtocol


def suite_root(private, name, qualified):
    target = private / 'suite-work' / name
    target.mkdir(parents=True); (target / 'evidence').mkdir()
    for name in ['receipt.json', 'loopback-qualification.json', 'helper-qualification.json', 'core-tool-fixture-qualification.json']:
        shutil.copyfile(qualified / 'evidence' / name, target / 'evidence' / name)
    shutil.copyfile(qualified / 'appcontainer-run.exe', target / 'appcontainer-run.exe')
    return target


def collect_suite_logs(private):
    # A suite workspace also contains executable fixtures and session files.
    # The encrypted envelope accepts only its bounded diagnostic evidence.
    work = private / 'suite-work'
    if work.exists():
        for suite in work.iterdir():
            source = suite / 'evidence'; target = private / 'execution-records' / suite.name
            if source.is_dir() and not target.exists(): shutil.copytree(source, target)


def smoke(out, original, candidates, clean):
    receipt = dict(status='started', cases=[])
    for name, argv, expected_exit in [('version', ['--version'], 0), ('help', ['--help'], 0),
        ('mcp-help', ['mcp', '--help'], 0), ('unknown-option', ['--neverd-isolation-unknown-option'], 1)]:
        observations = {}
        for label, binary in {'original': original, **candidates}.items():
            root = fresh_root(); shutil.copyfile(binary, root / 'bin/client.exe')
            logs = out / 'evidence' / (label + '-' + name); logs.mkdir()
            env = environment(clean, root, 9)
            transport = ContainedProtocol(out / 'appcontainer-run.exe', root, env, 'client.exe', argv, logs, 'client')
            try: execution = transport.finish()
            finally: transport.retain()
            assert execution['exit_code'] == expected_exit and not execution['loopback_exemption']
            assert execution['loopback_exemption_removed'] and execution['null_device_grant_removed']
            assert sha(root / 'bin/client.exe') == sha(binary)
            observations[label] = dict(exit_code=execution['exit_code'], stdout_sha256=sha(logs / 'client.stdout'),
                stderr_sha256=sha(logs / 'client.stderr'))
            write(logs / 'receipt.json', dict(input_sha256=sha(binary), execution=execution, observation=observations[label]))
        for label in candidates:
            assert observations['original'] == observations[label], 'Smoke pair differs; keep private streams'
            receipt['cases'].append(dict(case=name, layout=label, equal=True, observation=observations[label]))
    receipt.update(status='four_smoke_cases_match_each_layout', differential_pairs=len(receipt['cases']))
    write(out / 'evidence/smoke-acceptance.json', receipt)
    return receipt


def native_asset(arch, out, built, engine, clean):
    compiler = shutil.which('cl.exe'); assert compiler
    env = dict(os.environ)
    for key in list(env):
        if key.startswith('ACTIONS_') or any(v in key.upper() for v in ['TOKEN', 'SECRET', 'PASSWORD']): env.pop(key)
    env.pop('ARGV0', None)
    (out / 'captured-source/input').mkdir(parents=True)
    shutil.copyfile(built / 'extracted/input/m2361', out / 'captured-source/input/m2361')
    for name in ['raw-graph-windows-adapter', 'graph-fidelity-windows-adapter']:
        shutil.copyfile(built / 'tools' / (name + '.exe'), out / (name + '.exe'))
    def run(label, command, *, env=None, cwd=None, timeout=60, expected=0):
        # The scripts compiled here are the authored Node-API fixtures. The
        # retained binary asset is only data until the bounded load-only run.
        with (out / 'evidence' / (label + '.stdout')).open('xb') as stdout, (out / 'evidence' / (label + '.stderr')).open('xb') as stderr:
            result = subprocess.run(list(map(str, command)), cwd=cwd or out, env=env or clean,
                stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, timeout=timeout)
        assert (out / 'evidence' / (label + '.stdout')).stat().st_size <= 2 * 1024 * 1024
        assert (out / 'evidence' / (label + '.stderr')).stat().st_size <= 262144
        assert result.returncode == expected, 'Native load-only fixture failed; keep private diagnostics'
        return (out / 'evidence' / (label + '.stdout')).read_bytes()
    return accept_native(arch, out, engine, compiler, env, clean, run)


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--arch', required=True, choices=['arm64', 'x64'])
    ap.add_argument('--engine', type=Path, required=True); ap.add_argument('--environment', type=Path, required=True); args = ap.parse_args()
    out = args.environment.resolve(); engine = args.engine.resolve()
    qualified = json.loads((out / 'evidence/receipt.json').read_bytes())
    assert qualified['status'] == 'authored_windows_environment_qualified' and qualified['architecture'] == args.arch
    assert qualified['authored_inputs_only'] and not qualified['captured_client_executed'] and qualified['isolation']['status'] == 'qualified'
    for name in ['loopback-qualification.json', 'helper-qualification.json', 'core-tool-fixture-qualification.json']:
        assert json.loads((out / 'evidence' / name).read_bytes())['status'] == 'qualified', 'Authored fixture qualification is required'
    provenance = pin_engine(args.arch, engine)
    private = out / 'private-actual-client'; private.mkdir()
    records = private / 'execution-records'; records.mkdir(); build_logs = private / 'client-build-logs'; build_logs.mkdir()
    public = out / 'evidence/complete-source-client-acceptance'; public.mkdir()
    receipt = dict(status='started', arch=args.arch, source_engine=provenance, suites={}, goal_complete=False,
        original_provider_source_adapted=False, managed_search_launcher_used=False, external_rg_on_path=False,
        captured_original_source_or_client_exported=False, retained_native_export_functions_invoked=False)
    try:
        owned = private / 'owned-envelope-control'; (owned / 'execution-records').mkdir(parents=True)
        (owned / 'execution-records/owned.stdout').write_bytes(b'owned Windows actual-client diagnostic control\n')
        envelope_control = public / 'owned-envelope-control'; envelope_control.mkdir()
        write(envelope_control / 'receipt.json', seal_failure(owned, envelope_control))
        pins = PINS[args.arch]; archive = private / 'original-input.tgz'
        with urllib.request.urlopen(f'https://registry.npmjs.org/@anthropic-ai/claude-code-win32-{args.arch}/-/claude-code-win32-{args.arch}-2.1.296.tgz', timeout=90) as response:
            body = response.read(160 * 1024 * 1024 + 1)
        assert len(body) <= 160 * 1024 * 1024 and hashlib.sha512(body).digest() == base64.b64decode(pins['integrity']); archive.write_bytes(body)
        original = private / 'original.exe'
        with tarfile.open(archive, 'r:gz') as source:
            member = source.getmember('package/claude.exe'); assert member.isfile() and member.size <= 300 * 1024 * 1024
            original.write_bytes(source.extractfile(member).read())
        assert sha(original) == pins['original']; receipt['original_sha256'] = sha(original)
        # Existing oracles can report captured diagnostics on failure. Keep
        # every stream private until the entire matrix has passed.
        with (records / 'private-progress.txt').open('x', encoding='utf-8') as progress, contextlib.redirect_stdout(progress), contextlib.redirect_stderr(progress):
            built = private / 'build'
            receipt['build'] = build(args.arch, original, engine, built, build_logs / 'build', out)
            candidates = {name: Path(row['path']) for name, row in receipt['build']['clients'].items()}
            clean = {k: v for k, v in os.environ.items() if k.upper() in {'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'SYSTEMDRIVE'}}
            clean.update(BUN_RUNTIME_TRANSPILER_CACHE_PATH='0', NO_COLOR='1', PATH=str(Path(os.environ['SystemRoot']) / 'System32'))
            receipt['suites']['smoke'] = smoke(suite_root(private, 'smoke', out), original, candidates, clean)
            for layout, candidate in candidates.items():
                current = suite_root(private, layout + '-configuration-behavior', out)
                (current / 'authored-helper-build').mkdir()
                shutil.copyfile(out / 'authored-helper-build/helper.exe', current / 'authored-helper-build/helper.exe')
                receipt['suites'][layout + '_configuration'] = accept_configuration(current, original, candidate, clean)
                receipt['suites'][layout + '_behavior'] = accept_behavior(current, original, candidate, clean)
                assert receipt['suites'][layout + '_behavior']['status'] == 'twenty_two_behavior_cases_match'
                assert not receipt['suites'][layout + '_behavior']['unrun']
                write(private / 'private-harness-receipt.json', receipt)
            current = suite_root(private, 'tools', out)
            receipt['suites']['core_tools'] = accept_core_tools(current, original, candidates, clean)
            receipt['suites']['read_truncation'] = accept_read_truncation(current, original, candidates, clean)
            receipt['suites']['search_tools'] = accept_source_search(current, original, candidates, clean)
            current = suite_root(private, 'native-load-only', out)
            receipt['suites']['native_load_only'] = native_asset(args.arch, current, built, engine, clean)
            assert receipt['suites']['native_load_only']['status'] == 'embedded_native_load_only_pass'
        assert sha(original) == pins['original']
        for name, candidate in candidates.items(): assert sha(candidate) == receipt['build']['clients'][name]['sha256']
        assert len(receipt['suites']['smoke']['cases']) == 8
        for layout in candidates:
            assert len(receipt['suites'][layout + '_configuration']['cases']) == 7
            assert len(receipt['suites'][layout + '_behavior']['cases']) == 22
        assert len(receipt['suites']['core_tools']['cases']) == 28
        assert len(receipt['suites']['read_truncation']['cases']) == 14
        assert len(receipt['suites']['search_tools']['cases']) == 26
        receipt.update(status='both_Windows_source_clients_134_offline_pairs_and_native_load_only_passed',
            differential_pairs=134, typed_readback_rows=5172, original_and_clients_preserved=True,
            scope='Two layouts, 67 offline differential cases each; builtin search, unchanged provider source, retained native load/reflection only. No retained native function invocation or complete equivalence claim.')
        write(private / 'private-harness-receipt.json', receipt)
        collect_suite_logs(private)
        # Publish only validated fixture records, never source trees, clients,
        # extracted assets, snapshots or the original executable.
        for folder in records.iterdir():
            if folder.is_dir(): shutil.copytree(folder, public / folder.name)
        shutil.copytree(build_logs, public / 'client-build-logs'); write(public / 'receipt.json', receipt)
        print(json.dumps(dict(status=receipt['status'], arch=args.arch, differential_pairs=134, typed_readback_rows=5172)))
    except BaseException as error:
        receipt.update(status='failed_not_admitted', error_type=type(error).__name__, private_error=str(error)[:4096],
            private_traceback=traceback.format_exc(limit=12)[:16384])
        write(private / 'private-harness-receipt.json', receipt)
        try:
            collect_suite_logs(private)
            envelope = seal_failure(private, public)
        except BaseException as sealing_error: envelope = dict(status='not_exported', error_type=type(sealing_error).__name__, plaintext_exported=False)
        write(public / 'failure-summary.json', dict(status='failed_not_admitted', arch=args.arch,
            error_type=type(error).__name__, private_logs_export=envelope, original_or_client_files_exported=False))
        raise RuntimeError('Actual client acceptance failed; inspect only the private or encrypted diagnostic records') from None


if __name__ == '__main__': main()
