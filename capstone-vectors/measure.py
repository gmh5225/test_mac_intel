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
    counters=[]
    markers=[('arch/X86/X86Disassembler.c','bool X86_getInstruction(csh'),('arch/X86/X86IntelInstPrinter.c','void X86_Intel_printInst(MCInst'),('arch/X86/X86IntelInstPrinter.c','static void printOperand(MCInst *MI, unsigned OpNo, SStream *O)\n{'),('arch/X86/X86IntelInstPrinter.c','static void printMemReference(MCInst *MI, unsigned Op, SStream *O)\n{'),('arch/X86/X86Mapping.c','unsigned short X86_register_map(unsigned short id)\n{'),('arch/X86/X86Mapping.c','const uint8_t *X86_get_op_access(cs_struct *h'),('SStream.c','void(SStream_concat0)(SStream *ss, const char *s)\n{'),('arch/X86/X86Mapping.c','void X86_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)\n{')]
    for tag in ('clean','instrumented'):
        if tag=='instrumented':
            for i,(f,v) in enumerate(markers):
                src=base/f;txt=src.read_text();assert txt.count(v)==1,(f,v,txt.count(v));at=txt.index('{',txt.index(v))+1
                txt=txt[:at]+'\n\textern uint64_t path_counts[8];\n\t++path_counts['+str(i)+'];\n'+txt[at:];src.write_text(txt)
            run('cmake','--build',build,'--target','capstone_static','--parallel','4')
        run('clang++','-std=c++17','-O2','-I',base,'-I',base/'include',r/'counters.cpp',lib,'-o',w/tag);counters.append(sha(lib))
    assert counters[0]!=counters[1];save('archives',dict(clean=counters[0],instrumented=counters[1],markers=markers))
    for f in ('frozen_deb.py','jpeg_archive.py','pe_panels.py','pdata.py','pe-images.json','inputs.json','vectors.cpp','libmvec.py','libmvec.json'):shutil.copyfile(r/f,w/f)
    run('clang++','-O2','-I',base/'include',w/'vectors.cpp',lib,'-o',w/'vectors')
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    cases={};counts={}
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
        for mode in (1,2):
            v={tag:list(map(int,get(w/tag,str(bits),f,path,str(mode)).split()))for tag in ('clean','instrumented')}
            assert len(v['clean'])==len(v['instrumented'])==32 and v['clean'][:7]==v['instrumented'][:7]
            assert sum(v['clean'][7:23])==0 and sum(v['instrumented'][23:])==v['clean'][0] and v['instrumented'][8]>0
            counts[name+'/'+str(mode)]=v;save('counts',counts)
    assert len(counts)==12
    save('complete',dict(complete=True,source=q,neverd=dev))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
