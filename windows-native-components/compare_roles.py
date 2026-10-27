"""Original/source Windows roles inside the previously qualified AppContainer.

Private raw records are exported only after every declared fixture passes.
No captured input, client, or unvalidated process stream enters diagnostics.
"""
from pathlib import Path
import argparse
import base64
import bz2
import gzip
import hashlib
import json
import os
import shutil
import sys
import tarfile
import traceback
import urllib.request
import zipfile
from source_engine import pin as pin_engine
from coff_admission import sha
from client_build_controls import seal_failure

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'windows-recovery'))
from client_acceptance import PINS
from core_tool_acceptance import fresh_root, environment, write
from contained_protocol import ContainedProtocol


def fixtures(root):
    work = root / 'work'; body = b'first\nNEEDLE\npreneedle\n'
    (work / 'input.txt').write_bytes(body); (work / 'owned 猫.txt').write_bytes('first\nλ猫\n'.encode())
    (work / 'input.gz').write_bytes(gzip.compress(body, mtime=0)); (work / 'input.bz2').write_bytes(bz2.compress(body))
    (work / 'input.zst').write_bytes(bytes.fromhex('28b52ffd0458b9000066697273740a4e4545444c450a7072656e6565646c650a2c682895'))
    (work / 'input.br').write_bytes(bytes.fromhex('0f0b8066697273740a4e4545444c450a7072656e6565646c650a03'))
    with zipfile.ZipFile(work / 'input.zip', 'w', compression=zipfile.ZIP_DEFLATED) as z: z.writestr('input.txt', body)
    (work / 'nested').mkdir(); (work / 'nested/child.txt').write_bytes(b'nested NEEDLE\n')


def matrix():
    result = []
    for role, nl in [('rg', b'\n'), ('ugrep', b'\r\n')]:
        common = [('literal', ['-n', 'NEEDLE', 'input.txt'], 0, b'2:NEEDLE\n'),
            ('PCRE', ['-P', '-o', '(?<=pre)needle', 'input.txt'], 0, b'needle' + nl),
            ('Unicode-path', ['-F', '-o', 'λ猫', 'owned 猫.txt'], 0, 'λ猫'.encode() + nl),
            ('absent', ['owned-absent', 'input.txt'], 1, b''),
            ('count', ['-c', 'NEEDLE', 'input.txt'], 0, b'1' + nl),
            ('only-file', ['-l', '--null', 'NEEDLE', 'input.txt'], 0, b'input.txt\0'),
            ('PCRE-invalid', ['-P', '(', 'input.txt'], 2, b'')]
        if role == 'ugrep':
            common += [('compressed-' + s, ['-z', '-h', '-o', 'NEEDLE', 'input.' + s], 0, b'NEEDLE\r\n') for s in ['gz', 'bz2', 'zst', 'br', 'zip']]
        else:
            common += [('context', ['-n', '-A', '1', 'NEEDLE', 'input.txt'], 0, b'2:NEEDLE\n3-preneedle\n')]
        for label, args, code, wanted in common:
            result.append(dict(role=role, case=label, args=['--no-config', *args], exit_code=code, stdout=wanted))
    return result


def main():
    p = argparse.ArgumentParser(); p.add_argument('--arch', required=True, choices=['arm64', 'x64'])
    p.add_argument('--engine', type=Path, required=True); p.add_argument('--environment', type=Path, required=True); a = p.parse_args()
    assert os.name == 'nt'
    out = a.environment.resolve(); qualified = json.loads((out / 'evidence/receipt.json').read_bytes())
    assert qualified['status'] == 'authored_windows_environment_qualified' and qualified['architecture'] == a.arch
    assert qualified['authored_inputs_only'] and not qualified['captured_client_executed'] and qualified['isolation']['status'] == 'qualified'
    engine = a.engine.resolve(); provenance = pin_engine(a.arch, engine)
    transport = out / 'role-transport.exe'; launcher = out / 'appcontainer-run.exe'; assert transport.is_file() and launcher.is_file()
    private = out / 'private-complete-source-role-records'; private.mkdir()
    records = private / 'execution-records'; records.mkdir()
    receipt = dict(status='started', arch=a.arch, source_engine=provenance, controls=[], pairs=[], child_environment=[],
        environment_receipt_sha256=sha(out / 'evidence/receipt.json'), transport_sha256=sha(transport),
        captured_source_uploaded=False, normalization='none for search exit/stdout/stderr pairs', goal_complete=False)
    clean = {k: v for k, v in os.environ.items() if k.upper() in {'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'SYSTEMDRIVE'}}
    def execute(label, target, argv0, args, role, *, child=False):
        root = fresh_root(); fixtures(root); log = records / label; log.mkdir()
        shutil.copyfile(transport, root / 'bin/transport.exe'); shutil.copyfile(target, root / 'bin/target.exe')
        if child:
            shutil.copyfile(transport, root / 'bin/receiver.exe')
            file = root / 'work/input.txt'
            args = ['--no-config', '--no-filename', '--fixed-strings', '--pre', str(root / 'bin/receiver.exe'),
                '-e', '"kind":"owned-rg-preprocessor"', '-e', 'NEEDLE', str(file)]
        env = environment(clean, root, 0); env.update(NO_COLOR='1', TERM='dumb')
        if role is not None: env['ARGV0'] = role
        write(log / 'arguments.json', dict(argv0=argv0, arguments=list(map(str, args)), environment_role=role))
        process = ContainedProtocol(launcher, root, env, 'transport.exe', [root / 'bin/target.exe', argv0, *args], log, 'process')
        try: execution = process.finish()
        finally: process.retain()
        assert execution['app_container'] and execution['capability_count'] == 0 and execution['remaining_processes'] == 0
        assert not execution['timeout'] and not execution['output_limit'] and not execution['loopback_exemption']
        assert execution['loopback_exemption_removed'] and execution['null_device_grant_removed']
        assert sha(root / 'bin/target.exe') == sha(target)
        stdout = (log / 'process.stdout').read_bytes(); stderr = (log / 'process.stderr').read_bytes()
        write(log / 'execution.json', execution)
        return execution['exit_code'], stdout, stderr, root
    try:
        for label, argv0, role in [('plain', 'owned-client', None), ('RG', 'rg.exe', 'unknown'), ('UG', 'C:\\owned 猫\\ugrep.exe', 'rg')]:
            code, raw, error, root = execute('authored-' + label, transport, argv0, ['--capture'], role)
            def hex16(value): return ''.join(f'{int.from_bytes(value[i:i+2], "little"):04x}' for i in range(0, len(value), 2))
            assert code == 37 and not error
            assert json.loads(raw) == dict(argv0_utf16_hex=hex16(argv0.encode('utf-16-le')), env_utf16_hex=None if role is None else hex16(role.encode('utf-16-le')))
            receipt['controls'].append(dict(case=label, exit_code=code))
        for i, role in enumerate([None, '', 'rg', 'unknown', 'ugrep', '猫']):
            code, raw, error, root = execute('authored-receiver-' + str(i), transport, 'receiver.exe', ['input.txt'], role)
            lines = raw.splitlines(keepends=True); assert code == 0 and not error
            assert b''.join(lines[1:]) == b'first\nNEEDLE\npreneedle\n'
            child = json.loads(lines[0]); assert set(child) == {'kind', 'env_utf16_hex', 'input_utf16_hex'} and child['kind'] == 'owned-rg-preprocessor'
            if role == '': assert child['env_utf16_hex'] in [None, '']
            else: assert child['env_utf16_hex'] == (None if role is None else hex16(role.encode('utf-16-le')))
            receipt['controls'].append(dict(case='receiver-' + str(i), exit_code=code, inherited_environment_verified=True))
        write(private / 'qualified-before-original.json', receipt)
        pins = PINS[a.arch]; archive = out / 'private-role-original-input.tgz'
        with urllib.request.urlopen(f'https://registry.npmjs.org/@anthropic-ai/claude-code-win32-{a.arch}/-/claude-code-win32-{a.arch}-2.1.296.tgz', timeout=90) as response:
            data = response.read(160 * 1024 * 1024 + 1)
        assert len(data) <= 160 * 1024 * 1024 and hashlib.sha512(data).digest() == base64.b64decode(pins['integrity']); archive.write_bytes(data)
        original = out / 'private-role-original.exe'
        with tarfile.open(archive, 'r:gz') as t:
            member = t.getmember('package/claude.exe'); assert member.isfile() and member.size <= 300 * 1024 * 1024
            original.write_bytes(t.extractfile(member).read())
        assert sha(original) == pins['original']; receipt['original_sha256'] = sha(original)
        for case in matrix():
            for mode in ['environment', 'actual-argv0-precedence']:
                role = case['role']; argv0 = 'owned-client' if mode == 'environment' else role + '.exe'
                selected = role if mode == 'environment' else ('ugrep' if role == 'rg' else 'rg')
                observations = []
                for label, target in [('original', original), ('source', engine)]:
                    prefix = role + '-' + case['case'] + '-' + mode + '-' + label
                    code, raw, error, root = execute(prefix, target, argv0, case['args'], selected)
                    assert code == case['exit_code'] and raw == case['stdout'], 'Declared native role output oracle failed'
                    if code != 2: assert not error, 'Unexpected role diagnostics'
                    else: assert error, 'Invalid expression needs clear diagnostics'
                    observations.append((code, raw, error))
                assert observations[0] == observations[1], 'Native original/source role pair differs'
                receipt['pairs'].append(dict(role=role, case=case['case'], selector=mode, exact_exit_stdout_stderr=True,
                    stdout_sha256=hashlib.sha256(observations[0][1]).hexdigest(), stderr_sha256=hashlib.sha256(observations[0][2]).hexdigest()))
                write(private / 'receipt.json', receipt)
        for i, role in enumerate([None, '', 'rg', 'unknown', 'ugrep', '猫']):
            for label, target in [('original', original), ('source', engine)]:
                code, raw, error, root = execute('rg-child-' + str(i) + '-' + label, target, 'rg.exe', [], role, child=True)
                lines = raw.splitlines(keepends=True); assert code == 0 and not error and len(lines) == 2 and lines[1] == b'NEEDLE\n'
                child = json.loads(lines[0]); assert set(child) == {'kind', 'env_utf16_hex', 'input_utf16_hex'} and child['kind'] == 'owned-rg-preprocessor' and child['env_utf16_hex'] is None
                expected = str(root / 'work/input.txt').encode('utf-16-le')
                assert child['input_utf16_hex'] == ''.join(f'{int.from_bytes(expected[j:j+2], "little"):04x}' for j in range(0, len(expected), 2))
                receipt['child_environment'].append(dict(case=i, label=label, ARGV0_consumed=True, exact_owned_input_bytes=True))
        assert sha(original) == pins['original'] and sha(engine) == provenance['binary_sha256']
        receipt.update(status='native_Windows_original_and_complete_source_roles_match_all_declared_owned_cases',
            exact_pairs=len(receipt['pairs']), child_environment_processes=12,
            RG_private_revision_metadata_equivalence_claimed=False, actual_recovered_client_qualified=False)
        write(private / 'receipt.json', receipt)
        public = out / 'evidence/complete-source-roles'; assert not public.exists(); shutil.copytree(private, public)
        print(json.dumps(dict(status=receipt['status'], pairs=receipt['exact_pairs'], child_environment_processes=12)))
    except BaseException as error:
        receipt.update(private_error=str(error)[:4096], private_traceback=traceback.format_exc(limit=12)[:16384])
        write(private / 'private-harness-receipt.json', receipt)
        encrypted = out / 'evidence/complete-source-role-failure-envelope'; encrypted.mkdir()
        try: envelope = seal_failure(private, encrypted)
        except BaseException as sealing_error: envelope = dict(status='not_exported', error_type=type(sealing_error).__name__, plaintext_exported=False)
        write(out / 'evidence/complete-source-role-failure-summary.json', dict(status='failed_not_admitted',
            error_type=type(error).__name__, validated_pairs=len(receipt['pairs']), private_raw_records_exported=False, encrypted_export=envelope))
        raise RuntimeError('Native original/source roles failed; inspect the private authenticated diagnostic envelope') from None


if __name__ == '__main__': main()
