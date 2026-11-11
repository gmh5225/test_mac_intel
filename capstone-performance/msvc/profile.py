"""Locate remaining native decoder, printer and register-info work with sampled PCs."""
import csv
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
from collections import Counter
import run as p

ref = 'c3fd1f110810201fa4d82a2d057ed82f5b08d5b1'
src, work, ev = p.source, p.work, p.evidence

def profile():
    tree = p.fetch('capstone', 'capstone', ref)
    p.fetch('iced', 'iced', p.manifest['iced_revision'])
    patch = src/'common.patch'
    assert p.digest(patch.read_bytes()) == '4dac9de16eab2738dd8edf56c97394d452596bd6343155ea15aed839b5c22417'
    p.run(['git','apply',patch], 'apply-native-output', tree)
    adapter = work/'adapter'
    adapter.mkdir()
    for name in ('Cargo.lock','iced.rs'):
        shutil.copyfile(src/name, adapter/name)
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
debug = 1
''')
    p.run(['cargo','build','--locked','--release','--manifest-path',adapter/'Cargo.toml'],'cargo-profile-build')
    driver = (src/'msvc/compare.cpp').read_text()
    driver = driver.replace('int main(int argc', '#include "pc-samples.hpp"\nint main(int argc')
    driver = driver.replace('    Result result = run(repeats);','    PcSamples samples; samples.start();\n    Result result = run(repeats);\n    samples.finish();')
    (work/'driver.cpp').write_text(driver)
    shutil.copyfile(src/'msvc/pc-samples.hpp',work/'pc-samples.hpp')
    with (tree/'CMakeLists.txt').open('a') as f:
        f.write('''
target_compile_options(capstone PRIVATE /Z7)
add_executable(sample_decode "${PROFILE_DIR}/driver.cpp")
target_compile_features(sample_decode PRIVATE cxx_std_17)
target_compile_options(sample_decode PRIVATE /Z7)
target_link_options(sample_decode PRIVATE /DEBUG:FULL /OPT:REF /OPT:ICF /INCREMENTAL:NO)
target_link_libraries(sample_decode PRIVATE capstone_static "${ICED_ADAPTER}" advapi32 bcrypt ntdll userenv ws2_32 dbghelp)
''')
    build = work/'build'
    p.run(['cmake','-S',tree,'-B',build,'-G','Visual Studio 17 2022','-A','x64','-T','host=x64',
           '-DPROFILE_DIR='+work.as_posix(),'-DICED_ADAPTER='+(work/'cargo-target/release/iced_compare.lib').as_posix(),
           '-DCAPSTONE_ARCHITECTURE_DEFAULT=ON','-DCAPSTONE_X86_SUPPORT=ON',
           '-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF'],'profile-configure')
    p.run(['cmake','--build',build,'--config','Release','--target','sample_decode','--parallel','4'],'profile-build')
    exe = build/'Release/sample_decode.exe'
    p.write('inputs.json',dict(capstone=ref,patch=p.digest(patch.read_bytes()),iced=p.manifest['iced_revision'],
                               executable=p.digest(exe.read_bytes()),compiler='MSVC Release /Z7',image=os.environ['ImageVersion']))
    import bisect,re
    objdump=shutil.which('llvm-objdump') or str(Path(os.environ['ProgramFiles'])/'LLVM/bin/llvm-objdump.exe')
    headers=subprocess.check_output([objdump,'-p',exe],text=True,errors='replace')
    base=int(re.search(r'^ImageBase\s+([a-fA-F0-9]+)',headers,re.M)[1],16)
    disasm=subprocess.check_output([objdump,'-d','--x86-asm-syntax=intel',exe],text=True,errors='replace')
    excerpt=[(int(m[1],16)-base,line.strip()) for line in disasm.splitlines() if (m:=re.match(r'^\s*([a-fA-F0-9]+):\s+',line))]
    ips=[i for i,_ in excerpt]
    summaries = []
    for case in p.get_cases():
        if case['name'] not in ('putty-32-0.85','kernel32-64','scalar64','simd64'): continue
        for mode in ('scan','format','detail'):
            for library in ('capstone','iced'):
                def args(n):
                    return [exe,library,mode,str(case['bits']),str(n),case['path']]
                n = 1
                while (probe:=json.loads(subprocess.check_output(args(n))))['wall_ns'] < 25_000_000: n *= 4
                repeats = max(1,math.ceil(n * 3_000_000_000 / probe['wall_ns']))
                pcs = ev/(library+'-'+case['name']+'-'+mode+'.tsv')
                env = dict(os.environ,CAPSTONE_PC_SAMPLES=str(pcs))
                row = json.loads(subprocess.check_output(args(repeats),env=env,timeout=55))
                assert row['instructions']*n == probe['instructions']*repeats
                total=0;symbols=Counter();lines=Counter();locations=Counter();edges=Counter()
                with pcs.open(newline='') as f:
                    for sample in csv.DictReader(f,delimiter='\t'):
                        count=int(sample['count']);total+=count
                        symbols[sample['module']+'!'+sample['symbol']]+=count
                        lines[Path(sample['file']).name+':'+sample['line']]+=count
                        locations[(sample['module'],sample['rva'])]+=count
                        if sample['module'].lower() in ('vcruntime140','ucrtbase') or sample['symbol'] in ('memcpy','memset','memmove','consumeByte'):
                            edges[(sample['symbol'],sample['caller_module'],sample['caller_rva'],sample['caller_symbol'])]+=count
                assert sum(c for s,c in symbols.items() if 'sample_decode!' in s.lower() and not s.endswith('!?')) > total * .20,(total,symbols.most_common(8))
                calls=[]
                for (callee,module,addr,name),count in edges.most_common(40):
                    i=bisect.bisect_left(ips,int(addr,16))
                    asm=[l for _,l in excerpt[max(0,i-7):i+3]] if module.lower()=='sample_decode' else []
                    calls.append(dict(callee=callee,caller=name,next_rva=addr,samples=count,asm=asm))
                summaries.append(dict(calls=calls,case=case['name'],mode=mode,library=library,samples=total,
                                      symbols=symbols.most_common(35),lines=lines.most_common(35),pcs=locations.most_common(12)))
                p.write('samples.json', summaries)
                print(case['name'],mode,library,total,symbols.most_common(3),flush=True)
    p.write('complete.json',dict(profiles=len(summaries)))

try:
    profile()
finally:
    before=sum(path.stat().st_size for path in work.rglob('*') if path.is_file())
    def writable(func,path,exc):
        os.chmod(path,0o700); func(path)
    shutil.rmtree(work,onerror=writable)
    p.write('cleanup.json',dict(bytes=before,removed=not work.exists()))
