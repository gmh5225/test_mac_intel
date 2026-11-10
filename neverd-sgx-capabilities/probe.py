"""Record SGX availability without counting discovery as enclave execution."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
source = Path(__file__).with_name('cpuid.c')
compiler = shutil.which('clang') or shutil.which('cc')
if compiler is None:
    raise SystemExit('A native C compiler is required for the CPUID probe')
with tempfile.TemporaryDirectory(prefix='neverd-sgx-capability-') as temporary:
    binary = Path(temporary) / 'cpuid'
    subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-O2', str(source), '-o', str(binary)], check=True)
    raw = subprocess.check_output([str(binary)], text=True)
leaves = json.loads(raw)
(args.output / 'cpuid.json').write_text(raw)
registers = {(leaf['leaf'], leaf['subleaf']): leaf['registers']
             for leaf in leaves if leaf['available']}
leaf7 = registers.get((7, 0), [0] * 4)
leaf12 = registers.get((0x12, 0), [0] * 4)
epc = registers.get((0x12, 2), [0] * 4)
brand = b''.join(struct.pack('<4I', *registers.get((leaf, 0), [0] * 4))
                 for leaf in range(0x80000002, 0x80000005))
devices = []
for name in ('/dev/sgx_enclave', '/dev/sgx/enclave', '/dev/isgx'):
    entry = {'path': name, 'exists': Path(name).exists(),
             'opened_read_write': False}
    if entry['exists']:
        try:
            fd = os.open(name, os.O_RDWR | os.O_CLOEXEC)
            os.close(fd)
            entry['opened_read_write'] = True
        except OSError as error:
            entry['error_number'] = error.errno
            entry['error'] = error.strerror
    devices.append(entry)
features = {'sgx': bool(leaf7[1] & (1 << 2)),
            'sgx_launch_control': bool(leaf7[2] & (1 << 30)),
            'sgx1': bool(leaf12[0] & 1), 'sgx2': bool(leaf12[0] & 2),
            'first_epc_section': epc[0] & 15,
            'hypervisor': bool(registers.get((1, 0), [0] * 4)[2] & (1 << 31))}
reasons = []
if not features['sgx'] or not features['sgx1']:
    reasons.append('SGX1 is not exposed by CPUID')
if features['first_epc_section'] != 1:
    reasons.append('CPUID does not enumerate an EPC section')
if platform.system() != 'Linux':
    reasons.append('The Linux SGX enclave runner requires a Linux kernel driver')
if not any(device['opened_read_write'] for device in devices):
    reasons.append('No accessible SGX enclave device')
report = {
    'schema_version': 1, 'kind': 'runner-capability-discovery',
    'status': 'unavailable' if reasons else 'candidate-needs-enclave-execution',
    'enclave_instruction_executions': 0, 'sgx_qualified': False,
    'reasons': reasons, 'features': features, 'devices': devices,
    'cpu_brand': brand.decode('ascii', errors='replace').strip('\x00 '),
    'system': platform.system(), 'machine': platform.machine(),
    'kernel': platform.release(),
    'runner_image': {key: os.environ.get(key) for key in
                     ('RUNNER_OS', 'RUNNER_ARCH', 'ImageOS', 'ImageVersion')},
    'source_commit': os.environ.get('GITHUB_SHA'),
    'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
    'probe_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    'compiler': subprocess.check_output([compiler, '--version'], text=True),
}
text = json.dumps(report, indent=2) + '\n'
(args.output / 'capabilities.json').write_text(text)
print(text)
summary = os.environ.get('GITHUB_STEP_SUMMARY')
if summary:
    with open(summary, 'a') as stream:
        stream.write('SGX capability: **' + report['status'] + '**\n\n')
        stream.write('Enclave instructions executed: **0**. This is discovery, '
                     'not SGX semantic qualification.\n\n')
        for reason in reasons:
            stream.write('- ' + reason + '\n')
