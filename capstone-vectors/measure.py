from pathlib import Path
import hashlib,itertools,json,math,os,platform,random,shutil,statistics,subprocess as sp,sys,tempfile
r=Path(__file__).resolve().parent;p=r.parent
e=p/'evidence';e.mkdir(exist_ok=True);rd=lambda f:json.loads(f.read_text())
q=rd(r/'tree.json');m=rd(r/'experiment.json');dev=m['neverd'];base=p/'source';root=p/'neverd-config';ice=p/'iced-source'
def save(name,value):
    f=e/(name+'.json');temp=f.with_suffix('.tmp');temp.write_text(json.dumps(value,indent=2)+'\n');temp.replace(f)
def get(*args,**kwargs):return sp.check_output(args,text=True,**kwargs)
def run(*args,**kwargs):sp.run(args,check=True,**kwargs)
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def interval(values):
    x=sorted(values);n=len(x)
    def rank(q):
        return next(k for k in range(1,n+1) if 40*sum(math.comb(n,i)*k**i*(n-k)**(n-i) for i in range(n//2+1,n+1))>=q*n**n)-1
    return [statistics.median(x),x[rank(1)],x[rank(39)]]
w=Path(tempfile.mkdtemp());project=w/'project';build=w/'build';ad=w/'adapter'
try:
    assert get('git','-C',base,'rev-parse','HEAD').strip()==m['checkout_commit'] and get('git','-C',base,'write-tree').strip()==m['checkout_tree']
    assert get('git','-C',root,'rev-parse','HEAD').strip()==dev
    assert get('git','-C',ice,'rev-parse','HEAD').strip()==m['iced_revision']
    assert all(sha(r/f)==v for f,v in m['drivers'].items())
    (project/'third_party').mkdir(parents=True);(project/'third_party/capstone').symlink_to(base)
    (project/'cmake').mkdir();cm='cmake/NeverDCapstoneCompilerOptions.inc'
    (project/cm).write_bytes(sp.check_output(['git','-C',root,'show',dev+':'+cm]))
    v=get('git','-C',root,'show',dev+':CMakeLists.txt')
    (project/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(Layers LANGUAGES C CXX)\n'+v[v.index('# --- Capstone (our fork'):v.index('# --- NeverD CMake helpers')])
    run('cmake','-G','Ninja','-S',project,'-B',build,'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON')
    run('cmake','--build',build,'--target','capstone_static','--parallel','4');lib,=build.rglob('libcapstone.a')
    files={Path(c['file']).name for c in rd(build/'compile_commands.json')};assert {'MipsMapping.c','AArch64Mapping.c','ARMMapping.c','X86Sse64Output.c'}<=files and 'X86PublicOutput.c' not in files
# Compile uninstrumented probes first to verify identical instruction boundaries and output.
    for f in ('frozen_deb.py','jpeg_archive.py','pe_panels.py','pdata.py','pe-images.json','inputs.json','vectors.cpp','libmvec.py','libmvec.json'):shutil.copyfile(r/f,w/f)
    run('clang++','-std=c++17','-O2','-I',base/'include',w/'vectors.cpp',lib,'-o',w/'vectors')
    def profile(tag):
        run('clang++','-std=c++17','-O2','-I',base,'-I',base/'include',r/'profile.cpp',lib,'-o',w/tag)
    profile('original')
    paths=[('arch/X86/X86VectorFallback64.c','X86_decodeOutputMiss64(cs_struct *handle','fn'),('arch/X86/X86Disassembler.c','const int ret = decodeInstruction(insn, decode_code, decode_size, mode);','line'),('arch/X86/X86IntelInstPrinter.c','void X86_Intel_printInst(MCInst *MI, SStream *O, void *Info)','fn')]
    hashes={}
    for i,(path,mark,how) in enumerate(paths):
        f=base/path;z=f.read_text();assert z.count(mark)==1,(f,mark);at=z.index(mark)
        if how=='fn':at=z.index('\n{',at)+2
        f.write_text(z[:at]+'\n\textern unsigned cap_profile[3];\n\t++cap_profile['+str(i)+'];\n\t'+z[at:]);hashes[path]=sha(f)
    run('cmake','--build',build,'--target','capstone_static','--parallel','4');profile('counted')
    cc=rd(build/'compile_commands.json')
    entry=next(j for j in cc if j['file'].endswith('/X86Sse64Output.c') and 'capstone_x86_iter64' in j['command'])
    flags={k:k in entry['command'] for k in ('CAPSTONE_X86_NEAR_INDIRECT_OUTPUT','CAPSTONE_X86_COMPACT_SCALAR_ROWS')}
    panel_rows={};forms={}
    def panel(name,bits,f,span):
        for detail in (0,1):
            for public in (0,1):
                def run_probe(tag):
                    tsv=w/'forms.tsv';nums=list(map(int,get(w/tag,f,span,str(bits),str(detail),str(public),tsv).split()))
                    assert len(nums)==4
                    rows={}
                    for row in tsv.read_text().splitlines():
                        namekey,*items=row.split('\t');assert namekey not in rows;rows[namekey]=list(map(int,items))
                    assert sum(v[0]for v in rows.values())==nums[0]
                    return nums,rows
                checked,counts=run_probe('counted');baseline,base_counts=run_probe('original')
                assert checked==baseline and {k:v[0]for k,v in counts.items()}=={k:v[0]for k,v in base_counts.items()}
                assert all(sum(v[1:])==0 for v in base_counts.values())
                key=f'{name}/{detail}/{public}'
                forms[key]=counts;panel_rows[key]=dict(checked=checked,totals=[sum(v[i]for v in counts.values())for i in range(4)],extents=sha(span))
    inputs=rd(w/'inputs.json');(w/'inputs.json').write_text(json.dumps({n:v for n,v in inputs.items()if n in m['samples']}))
    sys.path.insert(0,str(w));import pe_panels,frozen_deb
    run(sys.executable,'-B',w/'libmvec.py');raw=rd(w/'libmvec.json')
    fixtures=list(itertools.chain([('libmvec-amd64',64,w/'libmvec.text',[(0,raw['bytes'],raw['address'])],raw)],pe_panels.prepare(w),frozen_deb.prepare(w)))
    assert {row[0]for row in fixtures}==set(m["samples"])
    for name,bits,f,spans,_ in fixtures:
        spec=m['provenance'][name]
        assert sha(f)==spec['text_sha256']
        selected=[s for s in spans if tuple(s) not in {tuple(a[:3]) for a in spec['excluded_incompatible_extents']}]
        path=w/(name+'.tsv')
        def emit(v):path.write_text(''.join('%d %d %d\n'%tuple(a) for a in v))
        emit(selected)
        if m['samples'][name]=='simd-functions':
            view=[list(map(int,z.split())) for z in get(w/'vectors',str(bits),f,path).splitlines()]
            assert len(view)==len(selected)
            selected=[s for s,x in zip(selected,view)if x[1]>=8 and x[1]>=.15*x[0]];emit(selected)
        assert sha(path)==spec['extent_sha256']
        panel(name,bits,f,path)
        if name=='libssl3t64-amd64':
            recovered=w/'recovered.tsv';targets=[s[:3]for s in spec['excluded_incompatible_extents']]
            assert len(targets)==6 and sum(n for _,n,_ in targets)==19594
            recovered.write_text(''.join('%d %d %d\n'%tuple(z) for z in targets))
            panel('openssl-ifma',64,f,recovered)
    assert len(panel_rows)==28
    save('forms',forms)
    save('complete',dict(complete=True,source=m['checkout_commit'],dev=dev,flags=flags,panels=panel_rows,host=platform.machine(),compiler=get('clang','--version').splitlines()[0],instrumented=hashes))

finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
