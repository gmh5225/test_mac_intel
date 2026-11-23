from pathlib import Path
import hashlib,itertools,json,math,os,platform,random,shutil,statistics,subprocess as sp,tempfile
import frozen_deb,pe_panels
r=Path(__file__).resolve().parent;root=r.parent;src=root/'source';nd=root/'neverd-config';out=root/'evidence';out.mkdir(exist_ok=True)
rd=lambda p:json.loads(p.read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(n,v):(out/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def git(p,*args):return sp.check_output(['git','-C',p,*args],text=True).strip()
def run(*args):sp.run(args,check=True)
m=rd(r/'experiment.json');q=m['stages']['bare'];exp=rd(r/'reference-counts.json')
assert git(src,'rev-parse','HEAD')==m['checkout_commit'] and git(src,'write-tree')==m['checkout_tree']
assert git(nd,'rev-parse','HEAD')==m['neverd']['commit']
for path,blob in m['neverd']['blobs'].items():assert git(nd,'hash-object',path)==blob
t=Path(tempfile.mkdtemp());b=t/'build';proj=t/'project';header=src/'arch/X86/X86VectorRegisterWriter.h'
try:
    first=header.read_bytes();(t/'baseline.h').write_bytes(first)
    patch=r/'bare.patch';assert sha(patch)==q['sha256'];run('git','-C',src,'apply','--index',patch);assert git(src,'write-tree')==q['tree']
    saved=header.read_bytes();(t/'candidate.h').write_bytes(saved);s=saved.decode()
    mark='extern CAPSTONE_INTERNAL const char X86_vectorRegisterOperands';assert s.count(mark)==1
    s=s.replace(mark,'extern void trace_vector_write(char *,unsigned,unsigned,unsigned,const char *);'+chr(10)+mark)
    for k,func in enumerate(('writeVectorRegister','appendVectorRegister')):
        anchor=func+'(char *out, unsigned bank, unsigned n)'+chr(10)+'{';assert s.count(anchor)==1
        s=s.replace(anchor,anchor+chr(10)+f'    trace_vector_write(out,bank,n,{k},__BASE_FILE__);')
    header.write_text(s)
    tables=(src/'arch/X86/X86GenVectorOutput.inc').read_text();start=tables.index('CAPSTONE_INTERNAL const char X86_vectorRegisterOperands');end=tables.index('\n};',start)+3;(t/'table.inc').write_text(tables[start:end]+'\n')
    (proj/'cmake').mkdir(parents=True);(proj/'third_party').mkdir();(proj/'third_party/capstone').symlink_to(src,target_is_directory=True);shutil.copy2(nd/'cmake/NeverDCapstoneCompilerOptions.inc',proj/'cmake')
    menu=(nd/'CMakeLists.txt').read_text();start=menu.index('# --- Capstone (our fork');(proj/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(Trace LANGUAGES C CXX)\n'+menu[start:menu.index('# --- NeverD CMake helpers',start)])
    run('cmake','-G','Ninja','-S',proj,'-B',b,'-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON')
    run('cmake','--build',b,'--parallel','4','--target','capstone_static');lib,=b.rglob('libcapstone.a');assert len(sp.check_output(['ar','t',lib]).splitlines())==49
    run('clang++','-std=c++17','-O3','-I',t,r/'replay.cpp','-o',t/'replay')
    run('clang++','-std=c++17','-O2','-I',src,'-I',src/'include',r/'capture.cpp',lib,'-o',t/'capture')
    dummy=t/'dummy.cpp';dummy.write_text('extern "C" void trace_vector_write(char*,unsigned,unsigned,unsigned,const char*) {}\n')
    run('clang++','-std=c++17','-O2','-I',src/'include',r/'vectors.cpp',dummy,lib,'-o',t/'vectors')
    for f in ('libmvec.json','libmvec.py'):shutil.copy2(r/f,t/f)
    run('python3','-B',t/'libmvec.py');gl=rd(t/'libmvec.json')
    glibc=[('libmvec-amd64',64,t/'libmvec.text',[(0,gl['bytes'],gl['address'])],gl)]
    rows={};os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    save('compiler',dict(version=sp.check_output(['clang++','--version'],text=True),replay=sha(t/'replay'),sources=[sha(t/f)for f in ('baseline.h','candidate.h','table.inc')]))
    for name,bits,f,spans,_ in itertools.chain(frozen_deb.prepare(t),pe_panels.prepare(t),glibc):
        if name not in exp:continue
        v=m['provenance'][name];assert sha(f)==v['text_sha256'] and len(spans)==v['input_functions']
        sf=t/'spans.tsv'
        def emit(rr):sf.write_text(''.join('%d %d %d\n'%tuple(z) for z in rr))
        emit(spans);excluded={tuple(z[:3])for z in v['excluded_incompatible_extents']}
        if v['selection']=='simd-functions':
            views=[list(map(int,l.split()))for l in sp.check_output([t/'vectors',str(bits),f,sf],text=True).splitlines()]
            assert len(views)==len(spans);entries=[z for z,(n,vec)in zip(spans,views)if tuple(z)not in excluded and vec>=8 and vec>=.15*n]
        else:entries=[z for z in spans if tuple(z)not in excluded]
        emit(entries);assert len(entries)==v['timed_functions'] and sha(sf)==v['extent_sha256']
        stream=t/'vector-writes.bin';raw=sp.check_output([t/'capture',str(bits),f,sf,stream],text=True).splitlines()
        info=list(map(int,raw[0].split()));owners={line.split()[0]:int(line.split()[1])for line in raw[1:]}
        calls=info[-1];assert info==exp[name] and stream.stat().st_size==4*calls and sum(owners.values())==calls
        run(t/'replay',stream,'test','1')
        def invoke(k,reps):return list(map(int,sp.check_output(['setarch',platform.machine(),'-R',t/'replay',stream,k,str(reps)]).split()))
        cycles=[];rep=0
        if calls:
            warm=max(1,10000000//calls);rep=max(1,round(20000000*warm/invoke('base',warm)[0]));order=['base','copy','rows','fuse'];rng=random.Random(name)
            for i in range(17):
                rng.shuffle(order);obs=[(k,invoke(k,rep))for k in order+order[::-1]]
                assert len({t[2]for _,t in obs})==1;cycles.append(obs)
        rows[name]=dict(counts=info,owners=owners,trace=sha(stream),extent=sha(sf),cycles=cycles,rep=rep);save('rows',rows)
    assert set(rows)==set(exp);save('complete',dict(complete=True,source=q,neverd=m['neverd'],cases=len(rows)))
finally:
    size=sum(p.stat().st_size for p in t.rglob('*')if p.is_file() and not p.is_symlink());shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=size))
