"""Compare shared-output code generation without linking the caller-gate diagnostic."""
from pathlib import Path
import json
import platform
import shlex
import shutil
import subprocess

import run

try:
    run.WORK.mkdir()
    run.EVIDENCE.mkdir()
    manifest=json.loads((run.SOURCE/'manifest.json').read_text())
    base=run.fetch('base','https://github.com/NeverSight/capstone.git',manifest['capstone_revision'])
    build=run.WORK/'base-build'
    run.command(['cmake','-S',base,'-B',build,'-G','Ninja',
                 '-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON',
                 '-DCMAKE_C_COMPILER=clang',f'-DCMAKE_OSX_ARCHITECTURES={platform.machine()}',
                 '-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON',
                 '-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF',
                 '-DCAPSTONE_BUILD_CSTOOL=OFF'],'configure')
    diagnostic=run.WORK/'caller-gate-diagnostic'
    run.command(['git','init',diagnostic],'diagnostic-init')
    shutil.copyfile(base/'cs.c',diagnostic/'cs.c')
    patch=run.SOURCE/'caller-gate-diagnostic.patch'
    assert run.sha(patch)==manifest['source_lineage'][patch.name]['sha256']
    run.command(['git','apply','--include=cs.c','--check',patch],'diagnostic-patch-check',diagnostic)
    run.command(['git','apply','--include=cs.c',patch],'diagnostic-patch-apply',diagnostic)
    assert (diagnostic/'cs.c').read_bytes() != (base/'cs.c').read_bytes()
    assert 'if ((opcode & 0xe0) != 0xc0 && opcode != 0x62)' in (diagnostic/'cs.c').read_text()
    commands=json.loads((build/'compile_commands.json').read_text())
    original=next(row for row in commands if row['file']==str(base/'cs.c'))
    products={}
    for label,filename in [('base',base/'cs.c'),('caller-gate',diagnostic/'cs.c')]:
        args=shlex.split(original['command'])
        assembly=run.EVIDENCE/(label+'-cs.s')
        args[args.index('-o')+1]=str(assembly)
        args[args.index('-c')]='-S'
        args[args.index(original['file'])]=str(filename)
        args+=['-I',str(base)]
        run.command(args,label+'-assembly',original['directory'])
        products[label]={'source_sha256':run.sha(filename),'assembly_sha256':run.sha(assembly)}
    assert products['base']['assembly_sha256']!=products['caller-gate']['assembly_sha256']
    run.write('verified.json',dict(baseline=manifest['capstone_revision'],products=products,
              purpose='Corrected standalone assembly comparison for the R569 shared-wrapper gate',
              host=list(platform.uname())))
    run.command(['clang','--version'],'compiler')
    shutil.copyfile(build/'compile_commands.json',run.EVIDENCE/'compile_commands.json')
finally:
    if run.EVIDENCE.exists():
        run.cleanup()
