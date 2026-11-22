from pathlib import Path
import hashlib,itertools,json,os,shutil,subprocess as sp,tempfile
import frozen_deb,pe_panels,re
r=Path(__file__).resolve().parent;s=r.parent/'source';out=r.parent/'evidence';out.mkdir(exist_ok=True)
def run(a):sp.run(a,check=True)
def read(p):return json.loads(p.read_text())
def save(n,q):(out/(n+'.json')).write_text(json.dumps(q,indent=2)+'\n')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
q=read(r/'attribution-source.json');prior=read(r/'samples.json')
def git(*a):return sp.check_output(['git','-C',s,*a],text=True).strip()
assert git('rev-parse','HEAD')==q['checkout']
assert git('write-tree')==q['tree']
for bits,unit,second,expected in [(64,'X86Sse64Output.c','X86VectorFallback64.c',2),(32,'X86Vex32Output.c','X86RegisterFallback32.c',1)]:
    fallback=s/'arch/X86'/second
    source,observed=re.subn(r'return cs_decode_full_insn(?:_body)?\(handle, code, size, insn,\s*insn_size, batch\);','return false;',fallback.read_text())
    assert observed==expected
    fallback.write_text(source)
    file=s/'arch/X86'/unit
    with file.open('a') as f:
        f.write('\nbool observedOutput%d(csh h,const uint8_t *p,size_t n,cs_insn *insn,uint16_t *length,unsigned *path){\n'%(bits))
        f.write('cs_struct *handle=(cs_struct *)(uintptr_t)h; if(tryOutput%d(handle,p,n,insn,length)){*path=1;return true;} if(X86_decodeOutputMiss%d(handle,p,n,insn,length,false)){*path=2;return true;} *path=0;return false;}\n'%(bits,bits))
w=Path(tempfile.mkdtemp());b=w/'build'
try:
    nd=r.parent/'neverd-config';record=q['neverd']
    assert sp.check_output(['git','-C',nd,'rev-parse','HEAD'],text=True).strip()==record['commit']
    for name,blob in record['blobs'].items():assert sp.check_output(['git','-C',nd,'hash-object',name],text=True).strip()==blob
    text=(nd/'CMakeLists.txt').read_text();a=text.index('# --- Capstone (our fork');end=text.index('# --- NeverD CMake helpers',a)
    project=w/'project';(project/'cmake').mkdir(parents=True);(project/'third_party').mkdir();(project/'third_party/capstone').symlink_to(s,target_is_directory=True)
    shutil.copy2(nd/'cmake/NeverDCapstoneCompilerOptions.inc',project/'cmake')
    (project/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(Profile LANGUAGES C CXX)\n'+text[a:end])
    run(['cmake','-G','Ninja','-S',project,'-B',b,'-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang'])
    commands=read(b/'compile_commands.json')
    near=sorted({Path(c['file']).name for c in commands if '-DCAPSTONE_X86_NEAR_INDIRECT_OUTPUT' in c['command'].split()})
    assert near==['X86Sse64Output.c']
    save('compile',dict(neverd=record,near=near,sha256=sha(b/'compile_commands.json')))
    run(['cmake','--build',b,'--target','capstone_static','--parallel','4'])
    run(['clang++','-O2','-std=c++17','-I',s,'-I',s/'include',r/'trace.cpp',next(b.rglob('libcapstone.a')),'-o',w/'trace'])
    run(['clang++','-O2','-I',s/'include',r/'vectors.cpp',next(b.rglob('libcapstone.a')),'-o',w/'vectors'])
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
        records=[list(map(int,l.split()))for l in lines.splitlines()]
        counts=[sum(l[-1]for l in records if l[0]==k)for k in range(5)]
        assert sum(counts)>0 and counts[4]>0
        summary[name]=dict(source=p,counts=counts,shape_sha256=sha(out/(name+'-shapes.tsv')),histogram_sha256=hashlib.sha256(lines.encode()).hexdigest())
    assert len(summary)==6
    save('checked',dict(complete=True,source=q,samples=summary))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*')if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
