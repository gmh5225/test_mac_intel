from pathlib import Path
import hashlib,itertools,json,math,os,platform,random,shutil,statistics,subprocess as sp,sys,tempfile
r=Path(__file__).resolve().parent;p=r.parent
e=p/'evidence';e.mkdir(exist_ok=True);rd=lambda f:json.loads(f.read_text())
q=rd(r/'source.json')['base'];m=rd(r/'experiment.json');dev=m['neverd'];base=p/'source';root=p/'neverd-config';ice=p/'iced-source'
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
    for f in ('frozen_deb.py','jpeg_archive.py','pe_panels.py','pdata.py','pe-images.json','inputs.json','vectors.cpp','libmvec.py','libmvec.json'):
        shutil.copyfile(r/f,w/f)
    run('clang++','-O2','-std=c++17','-I',base/'include',w/'vectors.cpp',lib,'-o',w/'vectors')
    run('clang++','-O2','-std=c++17','-I',base/'include',r/'trace.cpp','-ldl','-o',w/'trace')
    export=w/'export.c';export.write_text((r/'trial-export.c').read_text()+'\nuint64_t measure_rip_counts[3];\nuint64_t measure_rip_count(unsigned n) {return measure_rip_counts[n];}\n')
    def link(tag):
        run('clang','-fPIC','-shared','-I',base/'include',export,'-Wl,--whole-archive',lib,'-Wl,--no-whole-archive','-o',w/(tag+'.so'))
    link('base')
    entry=next(row['command'] for row in rd(build/'compile_commands.json') if row['file'].endswith('/X86Sse64Output.c'))
    def change(path,old,new):
        s=path.read_text();assert s.count(old)==1;path.write_text(s.replace(old,new))
    v=base/'arch/X86/X86VectorFallback64.c';p64=base/'arch/X86/X86Sse64Output.c'
    for path in (v,p64):
        change(path,'#include "../../cs_priv.h"','#include "../../cs_priv.h"\nextern uint64_t measure_rip_counts[3];')
    pred='size >= 6 && code[0] == 0xff && (code[1] == 0x15 || code[1] == 0x25)'
    k='\tconst struct X86SimpleOutput *row =\n\t\t&x86_indirect64'
    change(p64,k,'\tif ('+pred+') ++measure_rip_counts[0];\n'+k)
    change(v,'fallback:\n','fallback:\n\tif ('+pred+') {\n\t\t++measure_rip_counts[1];\n\t\tif (!X86_OUTPUT_UNSUPPORTED(handle, false)) ++measure_rip_counts[2];\n\t}\n')
    run('cmake','--build',build,'--target','capstone_static','--parallel','4');link('count')
    save('build',dict(source=q,neverd=m['neverd'],tree=m['checkout_tree'],near_option='CAPSTONE_X86_NEAR_INDIRECT_OUTPUT' in entry,host=platform.machine(),compiler=entry))
    inputs=rd(w/'inputs.json');(w/'inputs.json').write_text(json.dumps({n:v for n,v in inputs.items()if n in m['samples']}))
    sys.path.insert(0,str(w));import pe_panels,frozen_deb
    run(sys.executable,'-B',w/'libmvec.py');raw=rd(w/'libmvec.json')
    records={}
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
        modes={}
        for route in range(8):
            values=list(map(int,get(w/'trace',w/'base.so',w/'count.so',f,path,str(bits),str(route)).split()))
            assert len(values)==9 and values[0]>0 and values[2]==spec['bytes']
            modes[str(route)]=values
        assert all(v[:4]==modes['0'][:4] and v[5]==modes['0'][5] for v in modes.values())
        records[name]=modes
    save('complete',dict(complete=True,source=q,neverd=m['neverd'],records=records))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
