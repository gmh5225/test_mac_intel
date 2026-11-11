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
    units = ['x86_mapping_counts', 'x86_reg_access', 'x86_scan_batch', 'sstream', 'api', 'mapping']
    if subset:
        flags += ['-DCAPSTONE_ARCHITECTURE_DEFAULT=' + ('ON' if preset == 'diet' else 'OFF'), '-DCAPSTONE_X86_SUPPORT=ON',
                  '-DCAPSTONE_ARM_SUPPORT=ON', '-DCAPSTONE_AARCH64_SUPPORT=ON', '-DCAPSTONE_PPC_SUPPORT=ON',
                  '-DCAPSTONE_ARC_SUPPORT=ON', '-DCAPSTONE_LOONGARCH_SUPPORT=ON',
                  '-DCAPSTONE_BUILD_DIET=ON' if preset=='diet' else '-DCAPSTONE_X86_REDUCE=ON']
    if preset=='user-alloc':
        subset = True
        flags.extend(['-DCAPSTONE_USE_DEFAULT_ALLOC=OFF', '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF', '-DCAPSTONE_X86_SUPPORT=ON'])
        units = ['x86_mapping_counts']
    if preset=='windows-release':
        subset = True
        flags.extend(['-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON'])
        units = ['x86_mapping_counts']
    if preset=='sanitized':
        flags.extend(['-DCMAKE_C_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer',
                      '-DCMAKE_CXX_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer',
                      '-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined'])
        os.environ['ASAN_OPTIONS']='halt_on_error=1:detect_leaks=1'
        os.environ['UBSAN_OPTIONS']='halt_on_error=1:print_stacktrace=1'
    generator = ['-G','Visual Studio 17 2022','-A','x64'] if platform.system()=='Windows' else [
        '-G','Ninja','-DCMAKE_C_COMPILER=clang','-DCMAKE_CXX_COMPILER=clang++']
    command(['cmake','-S',source,'-B',d,*generator,'-DCMAKE_BUILD_TYPE=Release',
             '-DCAPSTONE_BUILD_MACOS_THIN=ON',*flags],label+'-config')

    targets = ['--target', 'capstone_static', *units] if subset else []
    command(['cmake','--build',d,'--config','Release','--parallel','3', *targets],label+'-build')
    args=['ctest','--test-dir',d,'-C','Release','--parallel','2','--output-on-failure','--no-tests=error',
          '--output-junit',str(EVIDENCE/(label+'-ctest.xml'))]
    if subset and not selection:
        args += ['-R', '^unit_('+'|'.join(units+([] if preset=='user-alloc' else ['ppc_alias_hints_generator','ppc_alias_hints_parser']))+')$']
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
    parser.add_argument('preset',choices=['sanitized','windows-release','intel-release','diet','reduced','user-alloc'])
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
    engine = source / 'cs.c'
    with engine.open('a') as f:
        f.write("""
static const cs_opt_mem frozen_hooks = { malloc, calloc, realloc, free, vsnprintf };
void dump_initial_hooks(void)
{
    printf("owner expr=%d,%d,%d,%d,%d stored=%d,%d,%d,%d,%d system=%d\\n",
           cs_mem_malloc==malloc, cs_mem_calloc==calloc, cs_mem_realloc==realloc, cs_mem_free==free, cs_vsnprintf==vsnprintf,
           cs_mem_malloc==frozen_hooks.malloc, cs_mem_calloc==frozen_hooks.calloc, cs_mem_realloc==frozen_hooks.realloc,
           cs_mem_free==frozen_hooks.free, cs_vsnprintf==frozen_hooks.vsnprintf, cs_mem_uses_system_defaults());
}
""")
    unit = source / 'tests/unit/x86_mapping_counts.c'
    u = unit.read_text().replace('bool shared_ids =', 'extern void dump_initial_hooks(void); dump_initial_hooks(); bool shared_ids =')
    u = u.replace('cs_close(&second);', 'printf("expected=%d actual=%d,%d owned=%d,%d lookup=%p,%p regs=%p,%p\\n", expect_shared,shared_ids,shared_regs,h->x86_uses_shared_luts,h2->x86_uses_shared_luts,(void*)h->x86_insn_lut,(void*)h2->x86_insn_lut,(void*)h->x86_insn_reg_lut,(void*)h2->x86_insn_reg_lut); cs_close(&second);')
    unit.write_text(u)
    failed=tests(source,'candidate',args.preset)
    if failed:
        raise RuntimeError('See exact hook and handle diagnostics in the CTest log')
    write('completed.json',dict(complete=True))

if __name__=='__main__':
    try:
        main()
    finally:
        EVIDENCE.mkdir(exist_ok=True)
        cleanup()
