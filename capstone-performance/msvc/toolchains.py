"""Compare library codegen with one physical consumer object, linker and iced build."""
import math
import os
from pathlib import Path
import re
import shutil
import statistics
import subprocess

import run as perf

source, work = perf.source, perf.work
ref = 'c3fd1f110810201fa4d82a2d057ed82f5b08d5b1'

def libraries_and_driver():
    base = perf.fetch('base', 'capstone', ref)
    perf.fetch('iced', 'iced', perf.manifest['iced_revision'])
    trees = {'msvc':base}
    for name, expected in {'profiles': '5fa2553adbd9403242303bee81d75e72d7c81de74f7a1b62b4fdbc3e34c31685'}.items():
        trees[name]=work/name
        patch=source/(name+'.patch')
        assert perf.digest(patch.read_bytes())==expected
        perf.run(['git','worktree','add','--detach',trees[name],'HEAD'],name+'-worktree',base)
        perf.run(['git','apply',patch],name+'-apply',trees[name])
    adapter = work/'adapter'
    adapter.mkdir()
    for name in ('Cargo.lock','iced.rs'):
        shutil.copyfile(source/name,adapter/name)
    (adapter/'Cargo.toml').write_text('''[package]
name = "iced_compare"
version = "0.1.0"
edition = "2021"
[lib]
crate-type = ["staticlib"]
path = "iced.rs"
[dependencies]
iced-x86 = { path = "../iced/src/rust/iced-x86", default-features = false, features = ["std","decoder","intel","instr_info"] }
[profile.release]
panic = "abort"
opt-level = 3
''')
    perf.run(['cargo','build','--locked','--release','--manifest-path',adapter/'Cargo.toml'],'cargo-build')
    abi = '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded' + ('DLL' if perf.crt=='MD' else '')
    opts=['-G','Visual Studio 17 2022','-A','x64',abi,'-DCMAKE_C_FLAGS=/MP4']
    lib_paths={}
    for name,src in trees.items():
        build=work/(name+'-build')
        perf.run(['cmake','-S',src,'-B',build,*opts,
                  '-DCAPSTONE_ARCHITECTURE_DEFAULT=ON','-DCAPSTONE_X86_SUPPORT=ON',
                  '-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME='+('ON' if perf.crt=='MT' else 'OFF'),
                  '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF'],name+'-configure')
        perf.run(['cmake','--build',build,'--config','Release','--parallel','4','--target','capstone_static'],name+'-build')
        lib_paths[name]=(build/'Release/capstone.lib').as_posix()
        record_codegen(name,build)
    driver=work/'driver';driver.mkdir()
    names=['msvc','profiles']
    lines=['cmake_minimum_required(VERSION 3.15)','project(shared_driver CXX)',
           f'add_library(consumer OBJECT "{(source/"msvc/compare.cpp").as_posix()}")',
           'target_compile_features(consumer PRIVATE cxx_std_17)',
           f'target_include_directories(consumer PRIVATE "{(base/"include").as_posix()}")']
    for name in names:
        lines += [f'add_executable({name} $<TARGET_OBJECTS:consumer>)',
                  f'target_link_libraries({name} PRIVATE "{lib_paths[name]}" "{(work/"cargo-target/release/iced_compare.lib").as_posix()}" advapi32 bcrypt ntdll userenv ws2_32)']
    (driver/'CMakeLists.txt').write_text('\n'.join(lines)+'\n')
    build=work/'driver-build'
    perf.run(['cmake','-S',driver,'-B',build,*opts],'driver-configure')
    perf.run(['cmake','--build',build,'--config','Release','--parallel','3'],'driver-build')
    obj,=build.rglob('compare.obj')
    progs={k:build/'Release'/(k+'.exe') for k in names}
    perf.write('products.json',{'consumer':perf.digest(obj.read_bytes()),'libraries':{k:perf.digest(Path(v).read_bytes()) for k,v in lib_paths.items()},'executables':{k:perf.digest(v.read_bytes()) for k,v in progs.items()}})
    return progs

def record_codegen(name,build):
    tool=shutil.which('llvm-objdump') or str(Path(os.environ['ProgramFiles'])/'LLVM/bin/llvm-objdump.exe')
    interesting={'fill_insn','cs_decode_full_insn','cs_disasm_iter','X86_getInstruction','X86_Intel_printInst','X86_reg_access','decodeInstructionFull','readModRM','translateFullOperands','validateScanOperands','translateOperand','translateRMMemoryFull','readOperandsScan','X86_scanBatch','X86_getInstructionScanResult','consumeByte','lookAtByte','decodeGenericScan','trySimpleLegacyScan','getInstructionScanResultAfterInitial'}
    found={}
    for stem in ('cs','X86DisassemblerDecoder','X86Disassembler','X86IntelInstPrinter','X86Mapping'):
        obj,=build.rglob(stem+'.obj')
        data=subprocess.check_output([tool,'-dr','--no-show-raw-insn','--x86-asm-syntax=intel',str(obj)],text=True,errors='replace')
        title=None
        for line in data.splitlines():
            symbol=re.match(r'^[0-9a-fA-F]+ <(.+)>:$',line)
            if symbol:
                label=symbol[1]
                if label.startswith(('$LN','$LL','$LNLL')): continue
                title=label if label in interesting else None
                if title: found[title]=[]
            elif title and line.strip():
                found[title].append(line)
    perf.write(name+'-prologues.json',{k:v[:55] for k,v in found.items()})
    from collections import Counter
    perf.write(name+'-relocations.json',{k:dict(Counter(line.split()[-1] for line in v if 'IMAGE_REL_AMD64_REL32' in line).most_common(40)) for k,v in found.items()})
    perf.write(name+'-instructions.json',{k:len([z for z in v if re.match(r'^\s*[0-9a-f]+:\s+[a-z]',z)]) for k,v in found.items()})
    flags={}
    for q in build.rglob('*.command.1.tlog'):
        if q.parent.name.lower().startswith('capstone.') and q.stat().st_size<1000000:
            data=q.read_bytes()
            flags[str(q.relative_to(build))]=data.decode('utf-16' if data.startswith((b'\xff\xfe',b'\xfe\xff')) else 'utf-8',errors='replace').splitlines()[:4]
    perf.write(name+'-compiler-commands.json',flags)

def measure(progs,cases):
    rows=[]
    def sample(label,case,mode,n):
        import json
        exe=progs['msvc' if label=='iced' else label]
        return json.loads(subprocess.check_output([exe,'iced' if label=='iced' else 'capstone',mode,str(case['bits']),str(n),case['path']]))
    orders=[['msvc','profiles','iced','profiles','msvc'],['profiles','msvc','iced','msvc','profiles']]
    for c in cases:
        for mode in ('scan','format','detail'):
            n=1
            while (probe:=sample('msvc',c,mode,n))['wall_ns']<10000000: n*=4
            repeats=max(1,math.ceil(n*90000000/probe['wall_ns']))
            pairs=[]
            for round_id in range(6):
                raw=[(k,sample(k,c,mode,repeats)) for k in orders[round_id%2]]
                def result(r,fields): return tuple(r[k] for k in fields)
                common_fields=('instructions','rejected','boundary_hash')
                assert len({result(r,common_fields+('value_hash',)) for k,r in raw if k!='iced'})==1
                agree=len({result(r,common_fields) for k,r in raw})==1
                values={k:[r['thread_cycles'] for name,r in raw if name==k] for k in ['msvc','profiles','iced']}
                baseline=statistics.mean(values['msvc'])
                pairs.append(dict(raw=raw,relative={k:baseline/statistics.mean(v) for k,v in values.items()},iced={k:values['iced'][0]/statistics.mean(v) if agree else None for k,v in values.items()},aa={k:v[0]/v[-1] for k,v in values.items() if k!='iced'}))
            rows.append(dict(case=c['name'],mode=mode,repeats=repeats,pairs=pairs))
            perf.write('measurements.json',rows)
try:
    perf.write('inputs.json',dict(crt=perf.crt,capstone=ref,iced=perf.manifest['iced_revision'],patches={'profiles': '5fa2553adbd9403242303bee81d75e72d7c81de74f7a1b62b4fdbc3e34c31685'}))
    progs=libraries_and_driver()
    measure(progs,perf.get_cases())
    perf.write('completed.json',dict(success=True))
finally:
    before=sum(p.stat().st_size for p in work.rglob('*') if p.is_file())
    def writable(func,path,exc):
        os.chmod(path,0o700);func(path)
    shutil.rmtree(work,onerror=writable)
    perf.write('cleanup.json',dict(bytes=before,removed=not work.exists()))
