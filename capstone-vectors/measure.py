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
    sources=rd(r/'sources.json')
    for f in ('frozen_deb.py','jpeg_archive.py','pe_panels.py','pdata.py','pe-images.json','inputs.json','vectors.cpp','libmvec.py','libmvec.json'):shutil.copyfile(r/f,w/f)
    run('clang++','-std=c++17','-O2','-I',base/'include',w/'vectors.cpp',lib,'-o',w/'vectors')
    inputs=rd(w/'inputs.json');(w/'inputs.json').write_text(json.dumps({n:v for n,v in inputs.items()if n in m['samples']}))
    sys.path.insert(0,str(w));import pe_panels,frozen_deb
    run(sys.executable,'-B',w/'libmvec.py');raw=rd(w/'libmvec.json')
    fixtures=list(itertools.chain([('libmvec-amd64',64,w/'libmvec.text',[(0,raw['bytes'],raw['address'])],raw)],pe_panels.prepare(w),frozen_deb.prepare(w)))
    assert {row[0]for row in fixtures}==set(m["samples"])
    programs={}
    for name,bits,f,spans,_ in fixtures:
        if bits!=32:continue
        spec=m['provenance'][name];assert sha(f)==spec['text_sha256']
        excluded={tuple(x[:3])for x in spec['excluded_incompatible_extents']};selected=[s for s in spans if tuple(s) not in excluded]
        ranges=w/(name+'.tsv')
        def emit(items):ranges.write_text(''.join('%d %d %d\n'%tuple(a)for a in items))
        emit(selected)
        if m['samples'][name]=='simd-functions':
            v=[list(map(int,z.split()))for z in get(w/'vectors','32',f,ranges).splitlines()]
            assert len(v)==len(selected)
            emit([s for s,z in zip(selected,v) if z[1]>=8 and z[1]>=.15*z[0]])
        assert sha(ranges)==spec['extent_sha256']
        programs[name]=(f,ranges)
    assert len(programs)==3
    baselines={};effects={};libs={}
    for label in ('shipping','old','fallback','entry'):
        run('git','-C',base,'restore','--source=HEAD','--staged','--worktree','--','.')
        if label!='shipping':
            patch=r/(label+'.patch');assert sha(patch)==sources[label]['sha256']
            run('git','-C',base,'apply','--index',patch);assert get('git','-C',base,'write-tree').strip()==sources[label]['tree']
        def build_probe(tag):
            run('cmake','--build',build,'--target','capstone_static','--parallel','4')
            run('clang++','-std=c++17','-O2','-I',base,'-I',base/'include',r/'syntax-probe.cpp',lib,'-o',w/tag)
        build_probe('plain');libs[label]=sha(lib)
        def at_function(path,mark,number):
            f=base/path;s=f.read_text();assert s.count(mark)==1,(path,mark)
            a=s.index('\n{',s.index(mark))+2
            f.write_text(s[:a]+'\n\textern uint64_t cap_profile[5];\n\t++cap_profile['+str(number)+'];'+s[a:])
        at_function('arch/X86/X86MemoryFallback32.c','X86_decodeOutputMiss32(cs_struct *handle',0)
        at_function('arch/X86/X86RegisterFallback32.c','X86_decodeRegisterFallback32(cs_struct *handle',1)
        if label!='shipping':
            name='arch/X86/X86MemoryFallback32.c';at_function(name,'X86_decodeAccumulatorFallback32(cs_struct *handle',2)
            f=base/name;s=f.read_text();mark='\t\t\twriteUnsignedRegisterImmediate(';assert s.count(mark)==1
            f.write_text(s.replace(mark,'\t\t\t++cap_profile[3];\n'+mark))
        for syntax in ('Intel','ATT'):
            at_function('arch/X86/X86'+syntax+'InstPrinter.c','void X86_'+syntax+'_printInst(MCInst *MI,',4)
        build_probe('counted');rows={}
        for name,(file,ranges) in programs.items():
            for detail in (0,1):
                for public in (0,1):
                    for att in (0,1):
                        key=f'{name}/{detail}/{public}/{att}'
                        def counts(tag):return list(map(int,get(w/tag,file,ranges,'32',str(detail),str(public),str(att)).split()))
                        plain=counts('plain');marked=counts('counted')
                        assert len(marked)==9 and marked[:4]==plain[:4] and plain[4:]==[0]*5 and marked[0]>0
                        if label=='shipping':baselines[key]=plain[:4]
                        else:assert plain[:4]==baselines[key]
                        rows[key]=dict(records=marked[:4],calls=marked[4:],extent=sha(ranges))
        effects[label]=rows;save('counts',effects)
    save('complete',dict(complete=True,source=sources,compiler=get('clang','--version').splitlines()[0],machine=platform.machine(),dev=dev,archives=libs,inputs={k:[sha(f),sha(s)]for k,(f,s)in programs.items()}))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
