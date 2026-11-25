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
    from costs import profile
    rows=fetch(r,w);corpus={row['arch']:row for row in rows if row['arch'] not in ('amd64','i386')}
    assert len(corpus)==5 and len([row for row in rows if row['arch'] in corpus])==5
    save('corpus',corpus)
    for tag in ('foreign','profile-foreign'):
        run('clang++','-O3','-DNDEBUG','-std=c++17','-I',base/'include',r/(tag+'.cpp'),lib,'-no-pie','-o',w/tag)
    results=[]
    for arch,row in corpus.items():
        name=row['name'];path=w/(name+'.text')
        assert sha(path)==row['text_sha256']
        for mode in range(4):
            z=profile(w/'profile-foreign',arch,mode,0,path,None,w,e,name)
            native=list(map(int,get(w/'profile-foreign',arch,path,str(mode),'1').split()))[2:]
            assert z['raw_signature']==native
            original=list(map(int,get(w/'foreign',arch,path,str(min(mode,2)),'1').split()))[2:]
            assert original[:3]==native[:3]
            if mode!=3:assert original==native
            z['original']=original;results.append(z);save('profile',results)
    save('complete',dict(complete=True,source=q,neverd=dev,cases=len(results),lib=sha(lib),driver=sha(r/'foreign.cpp'),profile_driver=sha(r/'profile-foreign.cpp'),cpu=platform.machine()))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
