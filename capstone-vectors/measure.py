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
    assert all(sha(r/f)==v for f,v in m['drivers'].items())
    (project/'third_party').mkdir(parents=True);(project/'third_party/capstone').symlink_to(base)
    (project/'cmake').mkdir();cm='cmake/NeverDCapstoneCompilerOptions.inc'
    (project/cm).write_bytes(sp.check_output(['git','-C',root,'show',dev+':'+cm]))
    v=get('git','-C',root,'show',dev+':CMakeLists.txt')
    (project/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(Layers LANGUAGES C CXX)\n'+v[v.index('# --- Capstone (our fork'):v.index('# --- NeverD CMake helpers')])
    run('cmake','-G','Ninja','-S',project,'-B',build,'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON')
    run('cmake','--build',build,'--target','capstone_static','--parallel','4');lib,=build.rglob('libcapstone.a')
    files={Path(c['file']).name for c in rd(build/'compile_commands.json')};assert {'MipsMapping.c','AArch64Mapping.c','ARMMapping.c','X86Sse64Output.c'}<=files and 'X86PublicOutput.c' not in files

    from training import fetch
    rows=fetch(r,w);corpus={row['arch']:row for row in rows if row['arch'] not in ('amd64','i386')}
    assert len(corpus)==5 and len([row for row in rows if row['arch'] in corpus])==5
    save('corpus',corpus)
    from bisect import bisect_right
    run('clang++','-O3','-DNDEBUG','-std=c++17','-I',base/'include',r/'profile-foreign.cpp',lib,'-no-pie','-o',w/'base')
    src=base/'SStream.c';original=src.read_text();t='\\tva_start(ap, fmt);\\n\\tret = cs_vsnprintf'
    assert original.count(t)==1
    src.write_text(original.replace(t,"\\tva_start(ap, fmt);\\n\\textern void trace_format_owner(void *, const char *, va_list);\\n\\ttrace_format_owner(__builtin_return_address(0), fmt, ap);\\n\\tret = cs_vsnprintf"))
    run('cmake','--build',build,'--target','capstone_static','--parallel','4')
    exe=w/'traced';run('clang++','-O3','-DNDEBUG','-std=c++17','-I',base/'include',r/'profile-foreign.cpp',r/'owners.cpp',lib,'-Wl,--wrap=clock','-no-pie','-o',exe)
    src.write_text(original)
    assert not get('git','-C',base,'status','--porcelain')
    starts={};sz={}
    for line in get('nm','-n','-S','-C','--defined-only',exe).splitlines():
        c=line.split(None,3)
        if len(c)!=4 or c[2] not in ('t','T','w','W'):continue
        addr=int(c[0],16);size=int(c[1],16)
        if size>sz.get(addr,0):starts[addr]=c[3];sz[addr]=size
    order=sorted(starts);assert len(order)>500
    out={}
    for arch,row in corpus.items():
        f=w/(row['name']+'.text');assert sha(f)==row['text_sha256'];panels=out[arch]={}
        for mode in range(4):
            args=(arch,f,str(mode),'1');expected=list(map(int,get(w/'base',*args).split()))[2:]
            actual=list(map(int,get(exe,*args,env=dict(os.environ,FORMAT_CALLS=str(w/'counts.tsv'))).split()))[2:]
            assert actual==expected and actual[0]>0
            rows=[]
            for line in (w/'counts.tsv').read_text().splitlines():
                pc,n,fmt,a,b=line.split('\\t');addr=int(pc,16)-1;j=bisect_right(order,addr)-1;start=order[j];assert j>=0 and addr<start+sz[start],line
                rows.append([starts[start],hex(addr-start+1),*(bytes.fromhex(x).decode('ascii') for x in (fmt,a,b)),int(n)])
            panels[str(mode)]=dict(signature=actual,calls=sum(a[-1]for a in rows),sites=rows)
            save('owners',out)
    save('complete',dict(complete=True,source=q,neverd=dev,lib=sha(lib),control=sha(w/'base'),traced=sha(exe),host=platform.machine(),panels=sum(map(len,out.values()))))

finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
