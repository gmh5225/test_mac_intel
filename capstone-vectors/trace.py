from pathlib import Path
import hashlib,itertools,json,os,shutil,subprocess as sp,tempfile
import frozen_deb,pe_panels
r=Path(__file__).resolve().parent;s=r.parent/'source';out=r.parent/'evidence';out.mkdir(exist_ok=True)
def run(a):sp.run(a,check=True)
def read(p):return json.loads(p.read_text())
def save(n,q):(out/(n+'.json')).write_text(json.dumps(q,indent=2)+'\n')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
q=read(r/'attribution-source.json');prior=read(r/'samples.json')
def git(*a):return sp.check_output(['git','-C',s,*a],text=True).strip()
assert git('rev-parse','HEAD')==q['checkout']
assert git('write-tree')==q['tree']
vfile=s/'arch/X86/X86VectorOutput.c';vfile.write_text(vfile.read_text()+'\n'+(r/'row.inc').read_text());shutil.copy2(r/'census-vex-rows.inc',vfile.parent/'census-vex-rows.inc')
w=Path(tempfile.mkdtemp());b=w/'build'
try:
    run(['cmake','-G','Ninja','-S',s,'-B',b,'-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_ARM_SUPPORT=ON','-DCAPSTONE_AARCH64_SUPPORT=ON','-DCAPSTONE_MIPS_SUPPORT=ON','-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -fomit-frame-pointer -Wno-error=incompatible-pointer-types-discards-qualifiers','-DCAPSTONE_X86_NEAR_INDIRECT_OUTPUT=ON','-DCAPSTONE_MIPS_PRECHECK_PRINTED_ALIAS=ON','-DCAPSTONE_MIPS_FINAL_OUTPUT_TRIM=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=OFF','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF'])
    run(['cmake','--build',b,'--target','capstone_static','--parallel','4'])
    run(['clang','-O2','-DCAPSTONE_HAS_X86','-DCAPSTONE_USE_SYS_DYN_MEM','-I',s,'-I',s/'include','-c',r/'edge.c','-o',w/'edge.o'])
    run(['clang++','-O2','-std=c++17','-I',s,'-I',s/'include',r/'trace.cpp',w/'edge.o','-Wl,--wrap=cs_decode_full_insn',b/'libcapstone.a','-o',w/'trace'])
    run(['clang++','-O2','-I',s/'include',r/'vectors.cpp',b/'libcapstone.a','-o',w/'vectors'])
    for file in ('libmvec.json','libmvec.py'):shutil.copy2(r/file,w/file)
    run(['python3','-B',w/'libmvec.py']);glibc=read(w/'libmvec.json')
    extra=[('libmvec-amd64',64,w/'libmvec.text',[(0,glibc['bytes'],glibc['address'])],glibc)]
    summary={}
    for name,bits,f,spans,_ in itertools.chain(frozen_deb.prepare(w),pe_panels.prepare(w),extra):
        if name not in prior:continue
        p=prior[name];assert sha(f)==p['text_sha256'] and len(spans)==p['input_functions']
        sf=w/'spans.tsv';sf.write_text(''.join('%d %d %d\n'%v for v in spans))
        excluded={tuple(z[:3])for z in p['excluded_incompatible_extents']}
        if p['selection']=='simd-functions':
            views=[list(map(int,l.split()))for l in sp.check_output([w/'vectors',str(bits),f,sf],text=True).splitlines()]
            assert len(views)==len(spans)
            used=[v for v,(a,vec)in zip(spans,views)if tuple(v)not in excluded and vec>=8 and vec>=.15*a]
        else:used=[v for v in spans if tuple(v)not in excluded]
        sf.write_text(''.join('%d %d %d\n'%v for v in used))
        assert len(used)==p['timed_functions'] and sha(sf)==p['extent_sha256']
        with (out/(name+'-comparison.log')).open('w') as log:
            lines=sp.check_output([w/'trace',str(bits),f,sf,out/(name+'-shapes.tsv')],text=True,stderr=log)
        (out/(name+'.tsv')).write_text(lines)
        values=list(map(int,lines.split()));assert len(values)==6 and values[0]==values[-1] and values[0]>=values[2]>=values[3]
        summary[name]=dict(source=p,values=values,shape_sha256=sha(out/(name+'-shapes.tsv')))
    assert len(summary)==6
    save('checked',dict(complete=True,source=q,samples=summary))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*')if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
