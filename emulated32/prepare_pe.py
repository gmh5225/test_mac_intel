#!/usr/bin/env python3
"""Compile and publish real ARMNT C fixtures with an existing NeverD binary."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--repository', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--build', type=Path, required=True)
a = p.parse_args()
r = a.repository.resolve()
out = a.output.resolve()
out.mkdir(parents=True, exist_ok=False)
sys.path.insert(0, str(r))
from scripts import check_source_patch_pe_runtime as pe
from scripts.check_source_patch_snapshot_runtime import engine_digest
cache=a.build.resolve()/'CMakeCache.txt'
assert ('LLVM_SOURCE_DIR:STATIC='+str(r/'third_party/llvm-project/llvm')) in cache.read_text(), 'use the integrated LLVM source build'
subprocess.run(['git','-C',str(r/'third_party/llvm-project'),'diff','--exit-code','HEAD'],check=True)

subprocess.run(["git", "diff", "--exit-code", "HEAD", "--", "lib", "include", "cmake", "tools/neverd", "CMakeLists.txt"], cwd=r, check=True)
from scripts.prepare_source_patch_additional_fixtures import portable_receipt
clang = Path('/opt/homebrew/opt/llvm/bin/clang')
linker = Path('/opt/homebrew/opt/lld/bin/lld-link')
cli = a.build.resolve() / 'bin/neverd'
lib = cli.parent / 'libneverd.dylib'
triple = 'thumbv7-pc-windows-msvc'
commands = []
def run(cmd, name):
    commands.append([str(x) for x in cmd])
    return pe.run(commands[-1], out / (name + '.log'))
def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()
source = out / 'original.c'
source.write_text(pe.ORIGINAL)
obj = out / 'original.obj'
original = out / 'original.exe'
run([clang, '--target=' + triple, '-mthumb', '-O0', '-funwind-tables', '-c', source, '-o', obj], 'compile-original')
run([linker, obj, '/out:' + str(original), '/entry:entry', '/subsystem:console', '/nodefaultlib', '/dynamicbase', '/debug:dwarf', '/timestamp:0', '/implib:' + str(out / 'original.lib')], 'link-original')
assert pe.machine(original) == 0x1c4
addresses = pe.function_addresses(lib, original)
rows = [{'case':'original', 'path':original.name, 'expected':9, 'sha256':digest(original)}]
for case, (expected, text) in pe.CASES.items():
    src = out / (case + '.c'); src.write_text(text)
    binding = 'original_fp' if case == 'floating-stack' else 'original_helper'
    for route in ('ir','object','supplied-object'):
        output = out / (case + '-' + route + '.exe')
        cmd = [cli,'patch',original,'--entry=replacement',f'--func={addresses["target"]:#x}',
               '--patch-report','-o',output,f'--bind=function:{binding}={addresses[binding]:#x}']
        if route == 'supplied-object':
            object_path = out / (case + '.obj')
            run([clang,'--target='+triple,'-mthumb','-O2','-funwind-tables','-ffunction-sections','-c',src,'-o',object_path],case+'-object')
            cmd += ['--from-object=' + str(object_path)]
        else:
            cmd += ['--from-source='+str(src),'--artifact='+route,'--language=c','--compiler-path='+str(clang)]
        result = run(cmd,case+'-'+route)
        receipts = [json.loads(x) for x in result.stdout.splitlines() if x.startswith('{')]
        receipts = [x for x in receipts if x.get('schema') == 'neverd.source-patch.v1']
        assert len(receipts)==1 and receipts[0]['success'] and len(receipts[0]['installed'])==1
        assert pe.machine(output)==0x1c4 and digest(original)==rows[0]['sha256']
        receipt = out / (case+'-'+route+'-receipt.json')
        receipt.write_bytes(portable_receipt(receipts[0],r,out,out))
        rows.append({'case':case+'-'+route,'path':output.name,'expected':expected,'sha256':digest(output),
                     'receipt':receipt.name,'receipt_sha256':digest(receipt)})
report = {'schema':'neverd.emulated32.inputs.v1','platform':'windows-arm32','cpu':0x1c4,
          'generator_source_commit':subprocess.check_output(['git','-C',str(r),'rev-parse','HEAD'],text=True).strip(),
          'engine_source_digest':engine_digest(r),'engine_build_kind':'integrated-llvm-source','build_cache_sha256':hashlib.sha256(cache.read_bytes()).hexdigest(),'engine_binaries':{x.name:digest(x) for x in (cli,lib)},
          'compiler':run([clang,'--version'],'compiler-version').stdout,
          'images':rows,'required_observations':30,'native_qualification':False}
(out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
(out/'commands.json').write_bytes(portable_receipt({'commands':commands},r,out,out))
print('Compiled and published 10 ARMNT images and 9 receipts; execution pending.')
