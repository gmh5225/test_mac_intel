"""Measure AMD64 runtime-function spans with identical traversal and shared handles."""
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import tempfile
from pdata import functions
d=Path(__file__).resolve().parent
s=d.parent
e=Path('capstone-evidence').resolve()
e.mkdir(exist_ok=True)
manifest=json.loads((s/'manifest.json').read_text())
win=os.name=='nt'
def save(name,obj):
    (e/name).write_text(json.dumps(obj,indent=2)+'\n')
def run(args,label,cwd):
    with (e/(label+'.log')).open('w') as f:
        subprocess.run(args,cwd=cwd,stdout=f,stderr=subprocess.STDOUT,check=True)
def sha(b):
    return hashlib.sha256(b).hexdigest()
def main(w):
    cs=w/'base';iced=w/'iced';other=w/'candidate'
    refs={'capstone':manifest['capstone_revision'],'iced':manifest['iced_revision']}
    for name,dest in [('capstone',cs),('iced',iced)]:
        run(['git','-c','core.autocrlf=false','init',dest],name+'-init',w)
        run(['git','config','core.autocrlf','false'],name+'-lf',dest)
        run(['git','fetch','-q','--depth=1','https://github.com/NeverSight/'+name,refs[name]],name+'-fetch',dest)
        run(['git','checkout','-q','--detach','FETCH_HEAD'],name+'-checkout',dest)
    run(['git','worktree','add','-q','--detach',other,'HEAD'],'candidate-tree',cs)
    patch=s/'windows-formatter.patch';h=sha(patch.read_bytes());assert h==manifest['source_lineage'][patch.name]['sha256']
    run(['git','apply',patch],'candidate-patch',other)
    ad=w/'adapter';ad.mkdir();shutil.copyfile(s/'Cargo.lock',ad/'Cargo.lock')
    rust=(s/'iced.rs').read_text().replace('repeats: u32,\n    output:', 'repeats: u32,\n    ip: u64,\n    output:').replace('bytes, 0x100000,','bytes, ip,').replace('set_ip(0x100000 +','set_ip(ip +')
    assert 'ip: u64,' in rust
    (ad/'iced.rs').write_text(rust+(d/'iced-trace.rs').read_text())
    (ad/'Cargo.toml').write_text('''[package]
name="iced_compare"
version="0.1.0"
edition="2021"
[lib]
crate-type=["staticlib"]
path="iced.rs"
[dependencies]
iced-x86={path="../iced/src/rust/iced-x86",default-features=false,features=["std","decoder","intel","instr_info"]}
[profile.release]
panic="abort"
opt-level=3
''')
    run(['cargo','build','--release','--locked'],'iced-build',ad)
    lib=ad/'target/release'/('iced_compare.lib' if win else 'libiced_compare.a')
    t=(s/'msvc/compare.cpp').read_text()
    head=t[:t.index('static Result capstone_run(')].replace('size_t, unsigned, Result *','size_t, unsigned, uint64_t, Result *')
    i=t.index('  for (unsigned repeat',t.index('#endif',t.index('#ifdef USE_BATCH',t.index('static Result capstone_run('))))
    j=t.index('  cs_free(insn, 1);',i)
    loop=t[i:j].replace('  for (unsigned repeat = 0; repeat < repeats; ++repeat) {','  {').replace('uint64_t ip = 0x100000;','uint64_t ip = start_ip;')
    (w/'functions.cpp').write_text(head+'static Result cs_span(const uint8_t *bytes,size_t count,csh handle,cs_insn *insn,uint64_t start_ip,unsigned mode) {\n  Result result;\n'+loop+'  return result;\n}\n'+(d/'driver.inc').read_text())
    executables={}
    code={}
    for name,tree in [('base',cs),('candidate',other)]:
        with (tree/'CMakeLists.txt').open('a') as f:
            f.write('\nadd_executable(functions "'+(w/'functions.cpp').as_posix()+'")\ntarget_compile_features(functions PRIVATE cxx_std_17)\ntarget_link_libraries(functions PRIVATE capstone_static "'+lib.as_posix()+'" '+('advapi32 bcrypt ntdll userenv ws2_32' if win else 'dl m pthread')+')\n')
        b=w/(name+'-build');opts=['-G','Visual Studio 17 2022','-A','x64','-DCMAKE_C_FLAGS=/MP4'] if win else ['-G','Ninja','-DCMAKE_C_COMPILER=clang','-DCMAKE_CXX_COMPILER=clang++']
        run(['cmake','-S',tree,'-B',b,*opts,'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME='+('ON' if os.environ['CRT']=='MT' else 'OFF'),'-DCAPSTONE_ARCHITECTURE_DEFAULT=ON','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF'],name+'-configure',w)
        run(['cmake','--build',b,'--config','Release','--target','functions','--parallel','4'],name+'-build',w)
        executables[name]=b/('Release/functions.exe' if win else 'functions')
        objdump=shutil.which('llvm-objdump') or str(Path(os.environ['ProgramFiles'])/'LLVM/bin/llvm-objdump.exe')
        code[name]={}
        for stem in ('cs','SStream','Mapping','X86Disassembler','X86DisassemblerDecoder','X86IntelInstPrinter','X86IntelInstPrinterPrechecked'):
            obj,=b.rglob(stem+'.obj')
            listing=subprocess.check_output([objdump,'-dr','--no-show-raw-insn',obj],text=True,errors='replace')
            code[name][stem]=sha('\n'.join(line for line in listing.splitlines() if 'file format' not in line and line.strip()).encode())
        save('native-code.json',code)

    row=next(r for r in manifest['inputs'] if r['name']=='putty-64-0.85')
    binary=w/'putty.exe'
    run(['curl','-fsSL','--retry','3',row['url'],'-o',binary],'putty-download',w)
    assert sha(binary.read_bytes())==row['package_sha256']
    programs={'putty-64-0.85':binary}
    if win:programs['kernel32-64']=Path(os.environ['SystemRoot'])/'System32/kernel32.dll'
    if hasattr(os,'sched_setaffinity'):os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    save('inputs.json',dict(refs=refs,patch=h,images={k:sha(v.read_bytes()) for k,v in executables.items()},runner=os.environ.get('ImageVersion')))
    rows=[]
    for name,path in programs.items():
        image=path.read_bytes();text,spans,outside=functions(image)
        bs=w/(name+'.text');bs.write_bytes(text)
        if name=='putty-64-0.85':assert sha(text)==row['text_sha256']
        def table(label,items):
            result=w/(name+'-'+label+'.tsv')
            result.write_text(''.join('%d %d %d\n'%tuple(v) for v in items));return result
        full=table('all',spans)
        traces=[subprocess.check_output([ex,'audit','0','1',bs,full],text=True) for ex in executables.values()]
        assert traces[0]==traces[1]
        (e/(name+'-functions.tsv')).write_text(traces[0]);numbers=[list(map(int,line.split())) for line in traces[0].splitlines()]
        assert [n[:3] for n in numbers]==[list(v) for v in spans]
        common=[v[:3] for v in numbers if v[1]==v[5]]
        missed=[v for v in numbers if v[1]!=v[5]]
        comparable=table('equal',common)
        save(name+'-coverage.json',dict(binary=sha(image),text=sha(text),text_bytes=len(text),span_bytes=sum(v[1] for v in spans),total=len(spans),common=len(common),common_bytes=sum(v[1] for v in common),outside=outside,different=missed))
        for panel,intervals in [('all',full),('common',comparable)]:
            for mode in range(3):
                def sample(label,n):
                    engine='iced' if label=='iced' else 'capstone'
                    exe=executables['base' if label in ('iced','base') else 'candidate']
                    return list(map(int,subprocess.check_output([exe,engine,str(mode),str(n),bs,intervals]).split()))
                n=1
                while (probe:=sample('base',n))[1]<15_000_000:n*=4
                n=max(1,math.ceil(n*150_000_000/probe[1]))
                labels=['base','candidate']+(['iced'] if panel=='common' else [])
                pairs=[]
                for i in range(7):
                    order=labels[i%len(labels):]+labels[:i%len(labels)]
                    raw=[(label,sample(label,n)) for label in order+order[::-1]]
                    assert len({tuple(out[2:]) for label,out in raw if label!='iced'})==1
                    if panel=='common':assert len({tuple(out[2:5]) for label,out in raw})==1
                    med={label:statistics.geometric_mean(v[0] for k,v in raw if k==label) for label in labels}
                    pairs.append(dict(gain=med['base']/med['candidate'],iced=med['iced']/med['candidate'] if 'iced' in med else None,raw=raw))
                rows.append(dict(name=name,panel=panel,mode=mode,repeats=n,gain=statistics.median(v['gain'] for v in pairs),iced=statistics.median(v['iced'] for v in pairs) if panel=='common' else None,pairs=pairs));save('measurement.json',rows)
    save('complete.json',dict(panels=len(rows)))
work=Path(tempfile.mkdtemp(dir=os.environ['RUNNER_TEMP']))
try:main(work)
finally:
    size=sum(f.stat().st_size for f in work.rglob('*') if f.is_file())
    def writable(fn,path,exc):
        os.chmod(path,0o700);fn(path)
    shutil.rmtree(work,onerror=writable);save('cleanup.json',dict(removed=not work.exists(),bytes=size))
