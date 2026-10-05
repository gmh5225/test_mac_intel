#!/usr/bin/env python3
"""Bounded independent HVF API control. Never a complete NeverD acceptance gate.

Collector/guard reuse is AGPL-3.0-only via the pinned NeverD helper and this
repository's existing upstream_hvf_control.py. Native derivative is BSD-2-Clause.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import subprocess
import sys
from intel_api_contract import audit
from upstream_hvf_control import collect

HELPER = '4e80b1394cfb2489fde177b30167629db71e693d'
TIMEOUT = 600
SOURCES = ['native/hvf_intel_real_mode.c', 'native/hvf_lifecycle.h',
           'native/HVFDOS-LICENSE.txt', 'native/hypervisor.entitlements',
           'native/test_hvf_lifecycle.c', 'scripts/intel_api_contract.py',
           'scripts/test_intel_api_contract.py', 'scripts/intel_api_lifecycle.py',
           'scripts/test_intel_api_lifecycle.py',
           'scripts/upstream_hvf_control.py', 'scripts/test_upstream_hvf_control.py',
           '.github/workflows/intel-api-lifecycle.yml',
           '.github/actions/intel-api-control/action.yml',
           '.github/actions/intel-api-control/run.cjs',
           '.github/actions/intel-api-control/observation.cjs',
           '.github/actions/intel-api-control/observation.test.cjs',
           '.github/actions/intel-api-control/snapshot.cjs',
           '.github/actions/intel-api-control/snapshot.test.cjs']


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], timeout=10, text=True).strip()


def contract(source, diagnostics, binary, mode, observation):
    if observation not in ('live', 'final-only'):
        raise ValueError('unknown observation mode')
    workflow = os.environ.get('GITHUB_SHA', '')
    if not re.fullmatch('[0-9a-f]{40}', workflow) or git(source, 'rev-parse', 'HEAD') != workflow:
        raise ValueError('workflow/source identity mismatch')
    if git(source, 'diff', '--name-only', 'HEAD') or git(diagnostics, 'diff', '--name-only', 'HEAD'):
        raise ValueError('tracked inputs changed')
    if git(diagnostics, 'rev-parse', 'HEAD') != HELPER:
        raise ValueError('diagnostic helper changed')
    tracked = set(git(source, 'ls-files', '-z').split('\0'))
    if not set(SOURCES) <= tracked:
        raise ValueError('untracked runtime source')
    return {'kind': 'independent-real-mode-finite-control', 'complete_native_acceptance': False,
            'workflow_commit': workflow, 'source_commit': workflow, 'helper_commit': HELPER,
            'source_hashes': {name: digest(source/name) for name in SOURCES},
            'binary_sha256': digest(binary), 'command': [str(binary), mode, '1000'],
            'mode': mode, 'observation': observation, 'event_version': 2,
            'iterations': 1000, 'timeout_seconds': TIMEOUT,
            'guest_hex': 'a30002ebfe', 'slice_ns': 5_000_000, 'budget_ns': 2_000_000_000,
            'call_limit': 4096, 'event_limit': 65536, 'max_output_bytes': 32*1024*1024,
            'vm_generations': 1000 if mode == 'vm' else 1, 'cpu_generations': 1000,
            'source': str(source), 'binary': str(binary),
            'stdout_transport': 'bounded PTY collector with OPOST disabled',
            'run_id': os.environ.get('GITHUB_RUN_ID'), 'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT'),
            'runner_image': os.environ.get('HVF_INTEL_IMAGE'), 'image_version': os.environ.get('ImageVersion'),
            'workflow_repository': os.environ.get('GITHUB_REPOSITORY'),
            'limitations': ['authored derivative of hvdos real-mode setup, not unchanged upstream',
                'no NeverD long-mode state, managed MSRs, projection, LLVM or cancellation controller',
                'one owner and retained backing, vCPU destroy then unmap then optional VM destroy',
                'final-only removes concurrent live observation as a bundle and can lose all native evidence on runner loss',
                'pass does not exonerate omitted components or establish physical Intel Mac behavior']}


def host_observations(binary):
    commands = [['sw_vers'], ['uname', '-a'], ['clang', '--version'], ['xcrun', '--show-sdk-version'],
                ['xcrun', '--show-sdk-path'], ['sysctl', 'kern.hv_support', 'kern.hv_vmm_present',
                  'machdep.cpu.brand_string', 'machdep.cpu.features'], ['file', str(binary)]]
    observations = []
    for command in commands:
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        observations.append({'command': command, 'status': result.returncode,
                             'stdout': result.stdout, 'stderr': result.stderr})
    return observations


def verify_binary(binary):
    if subprocess.check_output(['lipo', '-archs', str(binary)], text=True, timeout=10).strip() != 'x86_64':
        raise ValueError('binary must contain only x86_64')
    subprocess.run(['codesign', '--verify', '--strict', str(binary)], check=True, timeout=10)
    result = subprocess.run(['codesign', '-d', '--entitlements', ':-', str(binary)],
                            capture_output=True, check=True, timeout=10)
    if plistlib.loads(result.stdout).get('com.apple.security.hypervisor') is not True:
        raise ValueError('missing Hypervisor entitlement')


def result_passed(status, audited, error):
    return (type(status['status']) is int and status['status'] == 0
            and status['timed_out'] is False and status['child_retired'] is True
            and status['controller_interrupted'] is False and status['collection_error'] is None
            and audited is not None and error is None
            and status['output_sha256'] == audited['output_sha256'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=['prepare', 'execute'])
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--diagnostics', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--mode', choices=['vcpu', 'vm'], required=True)
    parser.add_argument('--observation', choices=['live', 'final-only'], required=True)
    args=parser.parse_args()
    source, diagnostics, binary, evidence=(p.resolve() for p in
        (args.source,args.diagnostics,args.binary,args.evidence))
    if platform.system()!='Darwin' or platform.machine()!='x86_64':
        raise ValueError('native Intel macOS required')
    current=contract(source,diagnostics,binary,args.mode,args.observation)
    verify_binary(binary)
    if args.stage=='prepare':
        evidence.mkdir(parents=True,exist_ok=False)
        current['host_observations']=host_observations(binary)
        save(evidence/'plan.json',current)
        return 0
    plan=json.loads((evidence/'plan.json').read_text())
    if {k:v for k,v in plan.items() if k!='host_observations'} != current:
        raise ValueError('sealed control inputs changed')
    sys.path.insert(0,str(diagnostics))
    from scripts.diagnose_hvf_methods import NativeChildren, test_environment
    status=collect(current['command'],source,evidence,test_environment(os.environ),TIMEOUT,NativeChildren,raw_output=True)
    error=None; audited=None
    output=evidence/'output.log'
    try:
        if output.stat().st_size>current['max_output_bytes']:
            raise ValueError('native output exceeded explicit limit')
        audited=audit(output.read_bytes(),args.mode)
    except ValueError as failure:
        error=str(failure)
    passed=result_passed(status,audited,error)
    save(evidence/'result.json',{'kind':'independent-real-mode-finite-result','passed':passed,
         'complete_native_acceptance':False,'audit':audited,'audit_error':error,
         'output_sha256':status['output_sha256']})
    return 0 if passed else 1


if __name__=='__main__': sys.exit(main())
