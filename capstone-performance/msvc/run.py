"""Measure ordinary MSVC Capstone and iced on the same pinned Windows thread."""
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import statistics
import struct
import subprocess
import sys
import tempfile

source = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(source))
from corpus import digest, elf_text, pe_text

evidence = Path('capstone-evidence').resolve()
evidence.mkdir(exist_ok=True)
work = Path(tempfile.mkdtemp(prefix='capstone-msvc-', dir=os.environ['RUNNER_TEMP']))
manifest = json.loads((source / 'manifest.json').read_text())
crt = sys.argv[1]
assert crt in ('MD', 'MT') and platform.machine() == 'AMD64'
os.environ['CARGO_TARGET_DIR'] = str(work / 'cargo-target')
if crt == 'MT':
    os.environ['RUSTFLAGS'] = '-C target-feature=+crt-static'


def write(name, value):
    (evidence / name).write_text(json.dumps(value, indent=2) + '\n')


def run(cmd, name, cwd=None):
    with (evidence / (name + '.log')).open('w', encoding='utf-8') as log:
        subprocess.run(list(map(str, cmd)), cwd=cwd, stdout=log, stderr=subprocess.STDOUT, check=True)
    return (evidence / (name + '.log')).read_text(encoding='utf-8', errors='replace').strip()


def fetch(name, repo, rev):
    target = work / name
    run(['git', 'init', target], name + '-init')
    run(['git', 'config', 'core.autocrlf', 'false'], name + '-lf', target)
    run(['git', 'fetch', '--depth=1', 'https://github.com/NeverSight/' + repo + '.git', rev],
        name + '-fetch', target)
    run(['git', 'checkout', '--detach', 'FETCH_HEAD'], name + '-checkout', target)
    assert run(['git', 'rev-parse', 'HEAD'], name + '-revision', target) == rev
    return target


def make_programs():
    base = fetch('base', 'capstone', manifest['capstone_revision'])
    fetch('iced', 'iced', manifest['iced_revision'])
    common=source/'printer-fixed.patch'
    assert digest(common.read_bytes())==manifest['source_lineage'][common.name]['sha256']
    run(['git','apply',common],'common-printer',base)
    exports=('X86_getInstructionScan','X86_getInstructionScanResult','X86_scanBatch','X86_scanCallTarget','cs_disasm_iter','decodeInstruction','decodeInstructionFull','decodeInstructionScan')
    for label in ('extent','early'):
        tree=work/label
        patch=source/('iterator-'+label+'.patch')
        assert digest(patch.read_bytes())==manifest['source_lineage'][patch.name]['sha256']
        run(['git','worktree','add','--detach',tree,'HEAD'],label+'-tree',base)
        run(['git','apply',patch],label+'-apply',tree)
        impl=(tree/'arch/X86/X86DisassemblerDecoder.c').as_posix()
        h=''.join('#define '+name+' '+label+'_'+name+'\n' for name in exports)
        (base/'arch/X86'/('Bench'+label.title()+'.c')).write_text(h+'#include "'+impl+'"\n')
    adapter = work / 'adapter'
    adapter.mkdir()
    for name in ['Cargo.lock', 'iced.rs']:
        shutil.copyfile(source / name, adapter / name)
    (adapter / 'Cargo.toml').write_text("""[package]
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
""")
    run(['cargo', 'build', '--release', '--locked', '--manifest-path', adapter / 'Cargo.toml'], 'cargo-build')
    driver=work/'same.cpp'
    text=(source/'msvc/compare.cpp').read_text()
    user_fn='static Result capstone_run('
    declaration='#include <cstdlib>\nextern "C" decltype(cs_disasm_iter) extent_cs_disasm_iter, early_cs_disasm_iter;\nstatic decltype(&cs_disasm_iter) bench_iter = cs_disasm_iter;\n'
    text=text.replace(user_fn,declaration+user_fn).replace('bool ok = cs_disasm_iter(', 'bool ok = bench_iter(')
    main='int main(int argc, char **argv) {'
    driver.write_text(text.replace(main,main+'\n  unsigned sel=std::atoi(std::getenv("CAPSTONE_BENCH_ITER"));\n  bench_iter=sel==2 ? early_cs_disasm_iter : sel==1 ? extent_cs_disasm_iter : cs_disasm_iter;'))
    with (base/'CMakeLists.txt').open('a') as f:
        f.write('\ntarget_sources(capstone PRIVATE arch/X86/BenchExtent.c arch/X86/BenchEarly.c)\nadd_executable(same "'+driver.as_posix()+'")\ntarget_compile_features(same PRIVATE cxx_std_17)\ntarget_link_libraries(same PRIVATE capstone_static "'+(work/'cargo-target/release/iced_compare.lib').as_posix()+'" advapi32 bcrypt ntdll userenv ws2_32)\n')
    build=work/'build'
    run(['cmake','-S',base,'-B',build,'-G','Visual Studio 17 2022','-A','x64','-T','host=x64','-DCMAKE_C_FLAGS=/MP1','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME='+('ON' if crt=='MT' else 'OFF'),'-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF'],'config')
    run(['cmake','--build',build,'--config','Release','--parallel','1','--target','same'],'build')
    exe=build/'Release/same.exe'
    objdump=shutil.which('llvm-objdump') or str(Path(os.environ['ProgramFiles'])/'LLVM/bin/llvm-objdump.exe')
    import re
    data={}
    for stem,label in [('X86DisassemblerDecoder','cs_disasm_iter'),('BenchExtent','extent_cs_disasm_iter'),('BenchEarly','early_cs_disasm_iter')]:
        obj,=build.rglob(stem+'.obj')
        out=subprocess.check_output([objdump,'-dr','--no-show-raw-insn','--x86-asm-syntax=intel','--disassemble-symbols='+label,str(obj)],text=True,errors='replace')
        assert '<'+label+'>:' in out, label
        data[label]=out.splitlines()[:70]
    write('entry-code.json',data)
    return exe

def get_cases():
    cases = []
    def add(name, bits, data, binary_hash=None):
        p = work / (name + '.text')
        p.write_bytes(data)
        cases.append(dict(name=name, bits=bits, path=str(p), size=len(data), sha256=digest(data),
                          binary_sha256=binary_hash))
    for row in manifest['inputs']:
        if row['kind'] != 'pe':
            continue
        p = work / (row['name'] + '.exe')
        run(['curl.exe', '-fsSL', '--retry', '3', '--max-time', '120', row['url'], '-o', p],
            'download-' + row['name'])
        binary = p.read_bytes()
        assert digest(binary) == row['package_sha256']
        data = pe_text(binary)
        assert digest(data) == row['text_sha256']
        add(row['name'], row['selector'], data, digest(binary))
    for bits, system in [(32, 'SysWOW64'), (64, 'System32')]:
        p = Path(os.environ['SystemRoot']) / system / 'kernel32.dll'
        b = p.read_bytes()
        assert struct.unpack_from('<H', b, struct.unpack_from('<I', b, 60)[0] + 4)[0] == (0x14c if bits == 32 else 0x8664)
        add('kernel32-' + str(bits), bits, pe_text(b), digest(b))
    for name, bits, flags in [('scalar32', 32, ['-fno-vectorize','-fno-slp-vectorize']),
                             ('scalar64', 64, ['-fno-vectorize','-fno-slp-vectorize']),
                             ('simd64', 64, ['-mavx2','-mfma'])]:
        obj = work / (name + '.o')
        triple = ('i686' if bits == 32 else 'x86_64') + '-unknown-linux-gnu'
        run(['clang', '-target', triple, '-O3', '-ffreestanding', *flags, '-c',
             source / ('simd.c' if name == 'simd64' else 'scalar.c'), '-o', obj], name + '-compile')
        add(name, bits, elf_text(obj.read_bytes()))
    write('cases.json', cases)
    return cases


def measure(exe):
    labels=('stock','extent','early')
    def sample(case,mode,label,n):
        env=dict(os.environ,CAPSTONE_BENCH_ITER=str(labels.index(label)))
        return json.loads(subprocess.check_output([exe,'capstone',mode,str(case['bits']),str(n),case['path']],env=env))
    rows=[]
    for case in get_cases():
        if case['name'] not in ('putty-32-0.85','putty-64-0.85','kernel32-64','simd64'):
            continue
        for mode in ('format','detail'):
            n=1
            while (probe:=sample(case,mode,'stock',n))['wall_ns']<12_000_000:n*=4
            n=max(1,math.ceil(n*75_000_000/probe['wall_ns']))
            pairs=[]
            for i in range(6):
                order=labels[i%3:]+labels[:i%3]
                raw=[(label,sample(case,mode,label,n))for label in order+order[::-1]]
                assert len({tuple(x[k]for k in ('instructions','rejected','boundary_hash','value_hash'))for _,x in raw})==1
                times={l:statistics.geometric_mean(row['thread_cycles']for label,row in raw if label==l)for l in labels}
                pairs.append(dict(raw=raw,gain={l:times['stock']/times[l]for l in labels}))
            rows.append(dict(case=case['name'],mode=mode,pairs=pairs));write('measurement.json',rows)
try:
    exe=make_programs()
    write('inputs.json',dict(capstone=manifest['capstone_revision'],crt=crt,image=digest(exe.read_bytes()),system=os.environ.get('ImageVersion')))
    measure(exe)
    write('completed.json',{'success':True})
finally:
    before = sum(p.stat().st_size for p in work.rglob('*') if p.is_file())
    def writable(func, path, exc):
        os.chmod(path, 0o700)
        func(path)
    shutil.rmtree(work, onerror=writable)
    write('cleanup.json', dict(logical_bytes=before, removed=not work.exists()))
