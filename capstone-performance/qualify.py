"""Build and run the fork's own tests against actual, frozen product sources."""
import argparse
import json
import os
import platform
from pathlib import Path
import shutil
import subprocess
import xml.etree.ElementTree as ET

from run import EVIDENCE, ROOT, SOURCE, WORK, cleanup, command, fetch, sha, write

def tests(source, label, preset, selection=None):
    d=WORK/('build-'+label)
    flags=['-DCAPSTONE_ARCHITECTURE_DEFAULT=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON',
           '-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']
    subset = preset in ('diet', 'reduced')
    units = ['register_descriptors', 'x86_bextr_flags', 'x86_mapping_counts', 'x86_reg_access', 'x86_scan_batch', 'sstream', 'api', 'mapping']
    if subset:
        flags += ['-DCAPSTONE_ARCHITECTURE_DEFAULT=' + ('ON' if preset == 'diet' else 'OFF'), '-DCAPSTONE_X86_SUPPORT=ON',
                  '-DCAPSTONE_ARM_SUPPORT=ON', '-DCAPSTONE_AARCH64_SUPPORT=ON', '-DCAPSTONE_PPC_SUPPORT=ON',
                  '-DCAPSTONE_ARC_SUPPORT=ON', '-DCAPSTONE_LOONGARCH_SUPPORT=ON',
                  '-DCAPSTONE_BUILD_DIET=ON' if preset=='diet' else '-DCAPSTONE_X86_REDUCE=ON']
    if preset=='user-alloc':
        subset = True
        flags.extend(['-DCAPSTONE_USE_DEFAULT_ALLOC=OFF', '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF', '-DCAPSTONE_X86_SUPPORT=ON'])
        units = ['x86_mapping_counts']
    if preset=='static-crt':
        subset=True
        units=['x86_printer_prechecked','x86_mapping_counts','x86_encoding_accuracy','sstream']
        flags.extend(['-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=ON'])
    if preset=='sanitized':
        flags.extend(['-DCMAKE_C_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer',
                      '-DCMAKE_CXX_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer',
                      '-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined'])
        os.environ['ASAN_OPTIONS']='halt_on_error=1:detect_leaks=1'
        os.environ['UBSAN_OPTIONS']='halt_on_error=1:print_stacktrace=1'
    generator = ['-G','Visual Studio 17 2022','-A','x64','-DCMAKE_C_FLAGS=/MP4'] if platform.system()=='Windows' else [
        '-G','Ninja','-DCMAKE_C_COMPILER=clang','-DCMAKE_CXX_COMPILER=clang++']
    command(['cmake','-S',source,'-B',d,*generator,'-DCMAKE_BUILD_TYPE=Release',
             '-DCAPSTONE_BUILD_MACOS_THIN=ON',*flags],label+'-config')

    targets = ['--target', 'capstone_static', *units] if subset else []
    command(['cmake','--build',d,'--config','Release','--parallel','3', *targets],label+'-build')
    args=['ctest','--test-dir',d,'-C','Release','--parallel','2','--output-on-failure','--no-tests=error',
          '--output-junit',str(EVIDENCE/(label+'-ctest.xml'))]
    if subset and not selection:
        args += ['-R', '^unit_('+'|'.join(units)+')$']
    if selection:
        names=EVIDENCE/'failed-names.txt';names.write_text('\n'.join(selection)+'\n')
        args+=['--tests-from-file',str(names)]
    with (EVIDENCE/(label+'-ctest.log')).open('w') as f:
        completed=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT)
    xml=ET.parse(EVIDENCE/(label+'-ctest.xml'))
    cases=list(xml.iter('testcase'))
    assert cases
    failed=[x.attrib['name'] for x in cases if x.find('failure') is not None or x.find('error') is not None]
    skipped=[x.attrib['name'] for x in cases if x.find('skipped') is not None]
    if completed.returncode and not failed:raise RuntimeError('ctest stopped without a failing case')
    result=dict(total=len(cases),failed=failed,skipped=skipped,returncode=completed.returncode)
    write(label+'-summary.json',result)
    return failed

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('candidate',choices=['combined'])
    parser.add_argument('preset',choices=['sanitized','windows-release','static-crt','intel-release','diet','reduced','user-alloc'])
    args=parser.parse_args()
    assert not WORK.exists() and not EVIDENCE.exists()
    EVIDENCE.mkdir();WORK.mkdir()
    ref=json.loads((SOURCE/'manifest.json').read_text())['capstone_revision']
    source=fetch('candidate','https://github.com/NeverSight/capstone.git',ref)
    patches=['combined-product.patch']
    for i,f in enumerate(patches):
        command(['git','apply','--check',SOURCE/f],f'check-{i}',source)
        command(['git','apply',SOURCE/f],f'patch-{i}',source)
    command(['git','diff','--check'],'source-diff',source)
    write('inputs.json',dict(ref=ref,preset=args.preset,candidate=args.candidate,
                             patches={f:sha(SOURCE/f) for f in patches}))
    failed=tests(source,'candidate',args.preset)
    if failed:
        base=fetch('base','https://github.com/NeverSight/capstone.git',ref)
        inherited=tests(base,'base',args.preset,failed)
        write('baseline-comparison.json',dict(candidate_failed=failed,also_failed_on_base=inherited))
        if set(failed)!=set(inherited):raise RuntimeError('New test failures')
    write('completed.json',dict(complete=True))

if __name__=='__main__':
    try:
        main()
    finally:
        EVIDENCE.mkdir(exist_ok=True)
        cleanup()
