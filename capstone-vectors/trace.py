from pathlib import Path
import hashlib,itertools,json,shutil,subprocess as sp,tempfile
import frozen_deb,pe_panels
r=Path(__file__).resolve().parent;root=r.parent;src=root/'source';nd=root/'neverd-config'
out=root/'evidence';out.mkdir(exist_ok=True)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rd(p):return json.loads(p.read_text())
def save(n,v):(out/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def git(p,*args):return sp.check_output(['git','-C',p,*args],text=True).strip()
def run(*args):sp.run(args,check=True)
m=rd(r/'source.json');samples=rd(r/'samples.json')
assert git(src,'rev-parse','HEAD')==m['capstone'] and git(src,'write-tree')==m['tree']
assert git(nd,'rev-parse','HEAD')==m['neverd']['commit']
for name,blob in m['neverd']['blobs'].items():assert git(nd,'hash-object',name)==blob
events=[('cs.c','\tMCInst mci;'),('arch/X86/X86Mapping.c','void X86_get_insn_id(cs_struct'),('arch/X86/X86Mapping.c','const uint8_t *X86_get_op_access(cs_struct'),('arch/X86/X86IntelInstPrinter.c','void X86_Intel_printInst(MCInst'),('cs.c','static inline void fill_insn(struct cs_struct'),('SStream.c','void SStream_concat_hex64(SStream'),('arch/X86/X86IntelInstPrinterNumbers.c','void X86_Intel_printHexPrechecked(SStream')]
def instrument(base):
    for file in sorted({e[0]for e in events}):
        path=base/file;s=path.read_text()
        for index,(name,marker) in enumerate(events):
            if name!=file:continue
            assert s.count(marker)==1,(name,marker)
            at=s.index(marker) if index==0 else s.index('{',s.index(marker))+1
            s=s[:at]+'\n\t++path_events['+str(index)+'];\n'+s[at:]
        path.write_text(('' if file=='cs.c' else 'extern ')+'unsigned path_events[7];\n'+s)
instrument(src)
t=Path(tempfile.mkdtemp());b=t/'build';proj=t/'project';nd_key='# --- Capstone (our fork'
try:
    (proj/'cmake').mkdir(parents=True);(proj/'third_party').mkdir();(proj/'third_party/capstone').symlink_to(src,target_is_directory=True)
    shutil.copy2(nd/'cmake/NeverDCapstoneCompilerOptions.inc',proj/'cmake')
    menu=(nd/'CMakeLists.txt').read_text();pos=menu.index(nd_key)
    (proj/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(Trace LANGUAGES C CXX)\n'+menu[pos:menu.index('# --- NeverD CMake helpers',pos)])
    run('cmake','-G','Ninja','-S',proj,'-B',b,'-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON')
    run('cmake','--build',b,'--parallel','4','--target','capstone_static')
    lib,=b.rglob('libcapstone.a');order=sp.check_output(['ar','t',lib],text=True).splitlines();assert len(order)==49
    run('clang++','-O2','-std=c++17','-I',src,'-I',src/'include',r/'trace.cpp',lib,'-o',t/'trace')
    run('clang++','-O2','-I',src/'include',r/'vectors.cpp',lib,'-o',t/'vectors')
    for file in ('libmvec.json','libmvec.py'):shutil.copy2(r/file,t/file)
    run('python3','-B',t/'libmvec.py');gl=rd(t/'libmvec.json')
    glibc=[('libmvec-amd64',64,t/'libmvec.text',[(0,gl['bytes'],gl['address'])],gl)]
    results={}
    for name,bits,f,spans,_ in itertools.chain(frozen_deb.prepare(t),pe_panels.prepare(t),glibc):
        if name not in samples:continue
        v=samples[name];assert sha(f)==v['text_sha256'] and len(spans)==v['input_functions']
        sf=t/'spans.tsv'
        def emit(rows):sf.write_text(''.join('%d %d %d\n'%z for z in rows))
        emit(spans);excluded={tuple(z[:3])for z in v['excluded_incompatible_extents']}
        if v['selection']=='simd-functions':
            views=[list(map(int,line.split()))for line in sp.check_output([t/'vectors',str(bits),f,sf],text=True).splitlines()]
            assert len(views)==len(spans)
            entries=[z for z,(n,vec)in zip(spans,views)if tuple(z) not in excluded and vec>=8 and vec>=.15*n]
        else:entries=[z for z in spans if tuple(z)not in excluded]
        emit(entries);assert len(entries)==v['timed_functions'] and sha(sf)==v['extent_sha256']
        histogram=out/(name+'-events.tsv')
        raw=sp.check_output([t/'trace',str(bits),f,sf,histogram],text=True)
        checks=[list(map(int,line.split()))for line in raw.splitlines()]
        assert len(checks)==4 and len({tuple(z[2:])for z in checks})==1 and checks[0][2]>0
        results[name]=dict(extents=sha(sf),checks=checks,histogram=sha(histogram));save('progress',results)
    assert len(results)==6
    save('checked',dict(complete=True,source=m,samples=results,events=['complete_decode','map_id','operand_access','intel_printer','split_output','shared_hex','private_intel_hex'],members=len(order)))
finally:
    size=sum(p.stat().st_size for p in t.rglob('*')if p.is_file()and not p.is_symlink())
    shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=size))
