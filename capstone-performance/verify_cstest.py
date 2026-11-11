"""Exercise imported archive paths with two configurations in the same build tree."""
import json
from pathlib import Path
import platform
import subprocess
import sys
from run import EVIDENCE, SOURCE, WORK, cleanup, command, fetch, sha, write

def configure(build, source, generator):
    flags = ['-A','x64'] if platform.system() == 'Windows' else ['-DCMAKE_C_COMPILER=clang','-DCMAKE_CXX_COMPILER=clang++']
    command(['cmake','-G',generator,*flags,'-S',source,'-B',build,
             '-DCMAKE_CONFIGURATION_TYPES=Release;Debug','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
             '-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_CSTEST=ON',
             '-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF'],'configure-'+build.name)

def run():
    EVIDENCE.mkdir();WORK.mkdir()
    revision=json.loads((SOURCE/'manifest.json').read_text())['capstone_revision']
    src=fetch('source','https://github.com/NeverSight/capstone.git',revision)
    gen=sys.argv[1]
    write('inputs.json',dict(revision=revision,generator=gen,patch=sha(SOURCE/'cstest-multiconfig.patch')))
    build=WORK/'build'
    configure(build,src,gen)
    args=['cmake','--build',str(build),'--config','Release','--parallel','3','--target','cstest']
    with (EVIDENCE/'original-build.log').open('w') as f:
        original=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT)
    log=(EVIDENCE/'original-build.log').read_text(errors='replace').lower()
    if not original.returncode or ('cmocka' not in log and 'cyaml' not in log and 'libyaml' not in log) or not any(x in log for x in ('lnk1181','missing and no known rule','cannot find','no such file')):
        raise RuntimeError('unmodified baseline did not reproduce the external archive link failure')
    command(['git','apply',SOURCE/'cstest-multiconfig.patch'],'apply',src)
    configure(build,src,gen)
    fixture=src/'tests/MC/X86'
    for config in ['Release','Debug']:
        command(['cmake','--build',build,'--config',config,'--parallel','3','--target','cstest'],'build-'+config)
        matches=list(build.glob('suite/cstest/'+config+'/cstest*'))
        exe,=[p for p in matches if p.name in ('cstest','cstest.exe')]
        command([exe,fixture],'mc-x86-'+config)
    write('completed.json',dict(reproduced=True,passed=['Release','Debug']))
if __name__=='__main__':
    try:run()
    finally:
        EVIDENCE.mkdir(exist_ok=True)
        cleanup()
