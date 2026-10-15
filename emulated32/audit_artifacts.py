#!/usr/bin/env python3
"""Independently audit personal Actions legacy compatibility evidence offline."""
import argparse
import base64
from collections import Counter
from functools import lru_cache
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import subprocess
import zipfile

APPLE_SOURCE = '8f5f06762d0a811860e78f0ad0ab1dd96d923b98'
PE_SOURCE = 'a542f97ba769623d7b0f6f6c99d03c5a2cb1a0e8'
LINUX_SOURCE = 'fcee81c9a5e2f20a71090ade23ae833175f64c59'
CASES = {'original': 9}
CASES.update({case + '-' + route: code
              for case, code in [('nonleaf', 87), ('writable-pointer', 92), ('floating-stack', 93)]
              for route in ['ir', 'object', 'supplied-object']})
LINUX_CASES = {mode + '-original': 9 for mode in ['arm', 'thumb']}
LINUX_CASES.update({mode + '-' + case + '-' + route: code
                    for mode in ['arm', 'thumb']
                    for case, code in [('nonleaf', 87), ('writable-pointer', 92), ('floating-stack', 93)]
                    for route in ['ir', 'object', 'supplied-object', 'gcc-source', 'gcc-object']})


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_json(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, 'duplicate JSON key ' + key)
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs)


def safe_name(name):
    require(isinstance(name, str) and name and '\\' not in name and '\0' not in name,
            'invalid filename')
    require(all(part not in ('', '.', '..') and ':' not in part for part in name.split('/')),
            'unsafe filename ' + name)
    return name


def receipt(raw):
    value = read_json(raw)
    require(value['schema'] == 'neverd.source-patch.v1' and value['success'] is True,
            'failed publication receipt')
    require(value['language'] == 0 and len(value['installed']) == 1, 'not one C replacement')
    entry = value['installed'][0]
    require(value['requested'] == [{'original_va': entry['original_va'], 'symbol': entry['symbol']}],
            'requested/installed mismatch')
    require(entry['original_va'] != entry['replacement_va'] and entry['symbol'] == 'replacement',
            'replacement not relocated')
    return value


def observations(rows, inventory):
    expected = {(profile, case, repeat): (code, digest)
                for profile, cases in inventory.items()
                for case, (code, digest) in cases.items() for repeat in range(3)}
    require(len(rows) == len(expected), 'observation count')
    keys = [(r['profile'], r['case'], r['repeat']) for r in rows]
    require(len(set(keys)) == len(keys) and set(keys) == set(expected), 'observation inventory')
    for row in rows:
        code, digest = expected[(row['profile'], row['case'], row['repeat'])]
        require(type(row['repeat']) is int and type(row.get('actual')) is int, 'missing process exit')
        require(row['actual'] == row['expected'] == code, 'wrong process exit')
        require(row['sha256'] == digest and not row.get('error'), 'input hash or process failure')
        require(isinstance(row['stdout'], str) and isinstance(row['stderr'], str), 'missing output')
        command = row['command']
        if row['profile'] == 'linux-arm32':
            require(command == ['/work/linux-images/' + row['case'] + '.elf'], 'not direct guest ELF')
        elif row['profile'] == 'pe-arm32-wine':
            require(command == ['/usr/lib/wine/wine', '/work/pe-arm32/' + row['case'] + '.exe'],
                    'wrong Wine image/loader')
        elif row['profile'] == 'macos-i386':
            require(len(command) == 3 and command[:2] == ['/usr/bin/darling', 'shell'] and
                    command[2].startswith('/Volumes/SystemRoot/') and
                    command[2].endswith('/emulated32/apple/macos-i386/' + row['case']), 'wrong Darling command')
        else:
            require(len(command) == 3 and command[0].endswith('/touchhle-portable/touchHLE') and
                    command[1].endswith('/' + row['profile'] + '-' + row['case'] + '.app') and
                    command[2] == '--headless', 'wrong HLE command')
            require('touchHLE v0.3.0' in row['stderr'] and 'CPU emulation begins now.' in row['stderr'] and
                    'App called exit(), exiting.' in row['stderr'], 'missing HLE execution evidence')


def audit(args):
    jobs = read_json(args.jobs.read_bytes())['jobs']
    artifacts = read_json(args.metadata.read_bytes())['artifacts']
    job_name, artifact_prefix = {
        'linux': ('qemu-system-arm32', 'emulated32-linux-'),
        'darling': ('darling-i386', 'darling-i386-'),
        'touchhle': ('touchhle-arm32', 'touchhle-arm32-')}[args.mode]
    matched = [j for j in jobs if j['name'] == job_name]
    require(len(matched) == 1, 'missing/duplicate job')
    job = matched[0]
    require(job['run_id'] == args.run and job['head_sha'] == args.commit, 'wrong job identity')
    require(job['status'] == 'completed' and job['conclusion'] == 'success', 'job not passed')
    require(all(s['status'] == 'completed' and s['conclusion'] == 'success' for s in job['steps']),
            'non-successful step')
    matches = [a for a in artifacts if a['name'] == artifact_prefix + args.commit]
    require(len(matches) == 1, 'missing/duplicate artifact')
    metadata = matches[0]
    require(not metadata['expired'] and metadata['workflow_run']['id'] == args.run and
            metadata['workflow_run']['head_sha'] == args.commit, 'wrong artifact identity')
    archive = args.archive.read_bytes()
    require(len(archive) == metadata['size_in_bytes'] and 'sha256:' + sha(archive) == metadata['digest'],
            'GitHub artifact size/digest mismatch')
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        names = z.namelist()
        require(len(set(names)) == len(names), 'duplicate zip member')
        files = {safe_name(n): z.read(n) for n in names if not n.endswith('/')}
    paths = [n for n in files if n.endswith('runtime.json')]
    require(len(paths) == 1, 'missing/duplicate runtime report')
    runtime = read_json(files[paths[0]])
    require(runtime['complete'] is True and runtime['native_qualification'] is False,
            'incomplete or mislabeled runtime report')

    @lru_cache(None)
    def blob(path):
        safe_name(path)
        return subprocess.check_output(['git', '-C', str(args.repository), 'show', args.commit + ':' + path])

    checked_files, checked_receipts = set(), set()
    def inputs(directory, profile, source):
        index = read_json(blob(directory + '/evidence-files.json'))
        for name, digest in index.items():
            path = directory + '/' + safe_name(name)
            require(sha(blob(path)) == digest, 'source evidence digest ' + path)
            checked_files.add(path)
        raw = blob(directory + '/manifest.json')
        manifest = read_json(raw)
        require(manifest['schema'] == 'neverd.emulated32.inputs.v1' and
                manifest['platform'] == profile and manifest['generator_source_commit'] == source,
                'wrong input identity')
        require(manifest['engine_build_kind'] == 'integrated-llvm-source' and
                manifest['required_observations'] == 30 and not manifest['native_qualification'],
                'wrong producer qualification')
        require(len(manifest['images']) == 10 and {r['case'] for r in manifest['images']} == set(CASES),
                'input case inventory')
        rows = {}
        for row in manifest['images']:
            require(row['expected'] == CASES[row['case']], 'forged expected value')
            data = blob(directory + '/' + safe_name(row['path']))
            require(sha(data) == row['sha256'], 'image digest')
            if profile == 'windows-arm32':
                require(data[:2] == b'MZ', 'not PE')
                offset = struct.unpack_from('<I', data, 0x3c)[0]
                require(data[offset:offset+4] == b'PE\0\0' and
                        struct.unpack_from('<H', data, offset+4)[0] == manifest['cpu'] == 0x1c4,
                        'wrong PE architecture')
            else:
                cpu, subtype = {'macos-i386': (7, 3), 'ios-armv7': (12, 9), 'watchos-armv7k': (12, 12)}[profile]
                require(struct.unpack_from('<III', data) == (0xfeedface, cpu, subtype) and
                        (manifest['cpu'], manifest['cpu_subtype']) == (cpu, subtype), 'wrong Mach-O architecture')
                require(not manifest['sdk_qualification'], 'false SDK qualification')
            if row['case'] != 'original':
                path = directory + '/' + safe_name(row['receipt'])
                raw_receipt = blob(path)
                require(sha(raw_receipt) == row['receipt_sha256'], 'receipt digest')
                proof = receipt(raw_receipt)
                route = next(r for r in ['supplied-object', 'object', 'ir'] if row['case'].endswith('-' + r))
                case = row['case'][:-len(route)-1]
                if route == 'supplied-object':
                    extension = '.obj' if profile == 'windows-arm32' else '.o'
                    obj = blob(directory + '/' + case + extension)
                    require(proof['input_kind'] == 2 and proof['object_sha256'] == sha(obj) and
                            proof['object_bytes'] == len(obj), 'supplied object provenance')
                else:
                    require(proof['input_kind'] == 0 and proof['compiler'] == 0 and
                            proof['artifact'] == (1 if route == 'object' else 0) and
                            proof['source_sha256'] == sha(blob(directory + '/' + case + '.c')),
                            'source provenance')
                checked_receipts.add(path)
            rows[row['case']] = (CASES[row['case']], row['sha256'])
        return manifest, sha(raw), rows

    inventory, source_commits = {}, {}
    if args.mode == 'linux':
        host = read_json(files['host.json'])
        require(host['complete'] is True and host['qemu_exit'] == 0 and
                int(host['run_id']) == args.run and host['harness_commit'] == args.commit and
                int(host['run_attempt']) == job['run_attempt'], 'wrong QEMU host identity')
        require(host['host_machine'] == 'aarch64' and host['command'][:7] ==
                ['qemu-system-arm', '-accel', 'tcg', '-M', 'virt', '-cpu', 'cortex-a15'], 'wrong emulation mode')
        require(runtime['schema'] == 'neverd.emulated32.linux-system.v1' and
                runtime['execution_kind'] == 'qemu-system-tcg' and
                runtime['guest']['machine'] == 'armv7l' and runtime['guest']['pointer_bits'] == 32,
                'not complete ARM32 guest')
        console = files['console.log'].decode(errors='replace')
        encoded = re.findall(r'^NEVERD_GUEST_REPORT:([A-Za-z0-9+/=]+)\r?$', console, re.M)
        require(len(encoded) == 1 and read_json(base64.b64decode(encoded[0], validate=True)) == runtime,
                'report not from guest console')
        require('NEVERD_GUEST_DONE:True' in console and 'Booting Linux on physical CPU' in console,
                'missing guest boot/completion')
        original_zip = blob('linux-arm32/qualified-images.zip')
        require(sha(original_zip) == 'ad7cdad1ebab507ff99a64b913ddf2c03d9503e1a54deae715981bfa1805e6ce',
                'wrong historical input archive')
        with zipfile.ZipFile(io.BytesIO(original_zip)) as z:
            manifest = read_json(z.read('manifest.json'))
            require(manifest['commit'] == runtime['image_commit'] == LINUX_SOURCE and
                    manifest['engine_source_digest'] == runtime['engine_source_digest'], 'ELF source identity')
            require(len(manifest['images']) == 32 and
                    {r['case'] for r in manifest['images']} == set(LINUX_CASES), 'ELF input inventory')
            rows = {}
            for row in manifest['images']:
                data = z.read(safe_name(row['path']))
                require(data[:6] == b'\x7fELF\x01\x01' and struct.unpack_from('<H', data, 18)[0] == 40,
                        'not little endian ELF ARM32')
                require(sha(data) == row['sha256'], 'ELF digest')
                if not row['case'].endswith('-original'):
                    name = row['case'] + '-0-receipt.json'
                    receipt(z.read(name))
                    checked_receipts.add('linux-arm32/' + name)
                rows[row['case']] = (LINUX_CASES[row['case']], row['sha256'])
            inventory['linux-arm32'] = rows
        pe, digest, rows = inputs('emulated32/pe-arm32', 'windows-arm32', PE_SOURCE)
        require(runtime['pe_manifest'] == pe and runtime['pe_manifest_sha256'] == digest, 'wrong PE runtime input')
        require(runtime['wine_initialization']['actual'] == 0, 'Wine initialization failed')
        require(runtime['wine_initialization']['command'] ==
                ['/usr/lib/wine/wine', 'wineboot', '--init'], 'not normal installed Wine initialization')
        require(runtime['wine_server_session']['actual'] == 0 and
                runtime['wine_server_session']['command'] == ['/usr/lib/wine/wineserver32', '-p'],
                'missing persistent Wine runtime session')
        prefix = read_json(files['prefix-installation.json'])
        require(prefix == runtime['wine_prefix_installation'] and prefix['complete'] is True and
                prefix['initialization']['actual'] == 0 and prefix['pointer_bits'] == 32 and
                prefix['execution_kind'] == 'arm64-kernel-compatibility' and
                prefix['counted_patch_observations'] == 0, 'incorrect installation/execution separation')
        inventory['pe-arm32-wine'] = rows
        source_commits = {'linux-arm32': LINUX_SOURCE, 'pe-arm32-wine': PE_SOURCE}
    else:
        require(runtime['schema'] == 'neverd.emulated32.apple.v1' and
                runtime['execution_kind'] == args.mode and not runtime['apple_os_qualification'] and
                not runtime['watchos_runtime_qualification'], 'false Apple OS qualification')
        require(int(runtime['run_id']) == args.run and runtime['harness_commit'] == args.commit and
                int(runtime['run_attempt']) == job['run_attempt'], 'wrong Apple job identity')
        profiles = ['macos-i386'] if args.mode == 'darling' else ['ios-armv7', 'watchos-armv7k']
        require(runtime['host']['machine'] == 'x86_64' and runtime['host']['system'] ==
                ('Linux' if args.mode == 'darling' else 'Darwin'), 'wrong execution host')
        require(set(runtime['inputs']) == set(profiles), 'wrong input profiles')
        if args.mode == 'darling':
            require(runtime['initialization']['actual'] == 0, 'Darling initialization failed')
        for profile in profiles:
            manifest, digest, rows = inputs('emulated32/apple/' + profile, profile, APPLE_SOURCE)
            require(runtime['inputs'][profile] == {'manifest_sha256': digest, 'manifest': manifest},
                    'Apple runtime input mismatch')
            inventory[profile], source_commits[profile] = rows, APPLE_SOURCE
    observations(runtime['observations'], inventory)
    return {'schema': 'neverd.emulated32.independent-audit.v1', 'complete': True,
            'mode': args.mode, 'run_id': args.run, 'job_id': job['id'], 'harness_commit': args.commit,
            'source_commits': source_commits, 'artifact': {key: metadata[key] for key in
                ['id', 'name', 'size_in_bytes', 'digest']},
            'observations': len(runtime['observations']), 'images': sum(len(v) for v in inventory.values()),
            'publication_receipts': len(checked_receipts), 'source_evidence_files': len(checked_files),
            'profiles': dict(Counter(r['profile'] for r in runtime['observations'])),
            'native_hardware_qualification': False, 'microsoft_windows_qualification': False,
            'apple_os_qualification': False, 'watchos_runtime_qualification': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['linux', 'darling', 'touchhle'], required=True)
    for option in ['jobs', 'metadata', 'archive', 'repository', 'output']:
        parser.add_argument('--' + option, type=Path, required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--run', type=int, required=True)
    args = parser.parse_args()
    require(re.fullmatch('[0-9a-f]{40}', args.commit), 'invalid harness commit')
    result = audit(args)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
