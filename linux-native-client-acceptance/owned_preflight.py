"""Exercise kernel semantics using owned code before admitting any client."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cpu', choices=['x86_64', 'aarch64'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output; out.mkdir()
    receipt = dict(status='owned_preflight_started', expected_cpu=args.cpu,
                   reported_cpu=platform.machine(), client_executed=False,
                   physical_audio_access=False, records=[])
    try:
        assert platform.system() == 'Linux' and platform.machine() == args.cpu
        assert os.getuid() != 0
        source = Path(__file__).with_name('seccomp-kernel-control.c')
        receipt['source_sha256'] = hashlib.sha256(source.read_bytes()).hexdigest()
        binary = out / 'owned-seccomp-control'
        commands = [('compile', ['gcc', '-O2', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(binary)])]
        for mode in ['baseline', 'prctl', 'syscall', 'exec', 'malformed']:
            commands.append((mode, [str(binary), mode]))
        for label, command in commands:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
            (out / (label + '.stdout')).write_bytes(result.stdout)
            (out / (label + '.stderr')).write_bytes(result.stderr)
            row = dict(label=label, command=command, returncode=result.returncode,
                       stdout_sha256=hashlib.sha256(result.stdout).hexdigest(),
                       stderr_sha256=hashlib.sha256(result.stderr).hexdigest())
            receipt['records'].append(row)
            assert result.returncode == 0 and not result.stderr, 'Owned kernel control failed: ' + label
            if label != 'compile':
                value = json.loads(result.stdout); row['observation'] = value
                if label == 'malformed':
                    assert value == dict(mode='malformed', result=-1, errno=22)
                else:
                    assert value['compiled_cpu'] == args.cpu and value['kernel_cpu'] == args.cpu
                    filtered = label != 'baseline'
                    assert value['mode'] == ('inherited' if label == 'exec' else label)
                    assert value['pid_result'] == (-1 if filtered else 0)
                    assert value['pid_errno'] == (123 if filtered else 0)
                    assert value['socket_result'] == 0 and value['socket_errno'] == 0
                    assert value['no_new_privs'] == 1
                    assert value['seccomp_mode'] == (2 if filtered else 0)
        version = subprocess.run(['bwrap', '--version'], capture_output=True, check=True, timeout=10)
        assert version.stdout == b'bubblewrap 0.6.1\n' and not version.stderr
        nested = subprocess.run(['bwrap', '--unshare-all', '--ro-bind', '/', '/', '--tmpfs', '/tmp',
                                 '--proc', '/proc', '--dev', '/dev', '--die-with-parent', '--new-session',
                                 '--', '/bin/sh', '-c', 'test ! -e /dev/snd && test -e /proc/self/status'],
                                capture_output=True, timeout=15)
        (out / 'nested.stdout').write_bytes(nested.stdout)
        (out / 'nested.stderr').write_bytes(nested.stderr)
        receipt['nested_namespace'] = dict(returncode=nested.returncode,
                                          stdout_sha256=hashlib.sha256(nested.stdout).hexdigest(),
                                          stderr_sha256=hashlib.sha256(nested.stderr).hexdigest())
        assert nested.returncode == 0 and not nested.stdout and not nested.stderr
        receipt['status'] = 'owned_kernel_and_nested_namespace_controls_passed'
    except BaseException as error:
        receipt.update(status='owned_preflight_failed_client_not_admitted', error_type=type(error).__name__, error=str(error))
        raise
    finally:
        (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        print(json.dumps({k: receipt[k] for k in ['status', 'expected_cpu', 'client_executed']}), flush=True)


if __name__ == '__main__':
    main()
