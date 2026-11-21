from pathlib import Path
import hashlib,json,os,platform,shutil,subprocess as sp,tempfile
d=Path(__file__).resolve().parent;root=d.parent;s=root/'source';out=root/'evidence';out.mkdir(exist_ok=True)
t=Path(tempfile.mkdtemp());tests=['sstream','utils','mcinst','instruction_bytes','feature_mode','mapping']
def run(args,n,cwd=None):
    with (out/(n+'.log')).open('w')as log:r=sp.run(list(map(str,args)),cwd=cwd,stdout=log,stderr=sp.STDOUT)
    if r.returncode:print((out/(n+'.log')).read_text(errors='replace')[-2900:],flush=True);r.check_returncode()
def put(n,v):(out/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def g(*a):return sp.check_output(['git','-C',s,*a],text=True).strip()
def sha(b):return hashlib.sha256(b).hexdigest()
try:
    m=json.loads((d/'tree.json').read_text());z=sp.check_output(['git','-C',root,'cat-file','blob','HEAD:portable-next/candidate.patch'])
    assert sha(z)==m['sha256'] and g('rev-parse','HEAD')==m['parent']
    patch=t/'current.patch';patch.write_bytes(z)
    a=t/'harness';a.mkdir();shutil.copyfile(d/'records.c',a/'records.c')
    (a/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(PortableRecords LANGUAGES C CXX)\nenable_testing()\nadd_subdirectory("'+s.as_posix()+'" capstone)\nadd_executable(records records.c)\ntarget_link_libraries(records PRIVATE capstone_static)\n')
    b=t/'b';windows=os.name=='nt'
    opts=['cmake','-S',a,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=OFF','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+k+'_SUPPORT=ON'for k in ['PPC']]]
    if windows:opts+=['-DCMAKE_C_COMPILER=cl','-DCMAKE_CXX_COMPILER=cl','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=ON','-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded']
    run(opts,'configure');bins={};trees={}
    for label in ('base','candidate'):
        if label=='candidate':
            g('apply','--index',str(patch));assert g('write-tree')==m['tree']
        trees[label]=g('write-tree')
        run(['cmake','--build',b,'--parallel','4','--target','records',*tests],'build-'+label)
        run(['ctest','--test-dir',b,'-C','Release','--parallel','3','--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(tests)+')$'],'tests-'+label)
        exe,=[f for f in b.rglob('records.exe' if windows else 'records')if f.is_file()]
        dest=t/(label+('.exe'if windows else ''));shutil.copy2(exe,dest);bins[label]=dest
    with sp.Popen([bins['base']],stdout=sp.PIPE,stderr=sp.PIPE)as left,sp.Popen([bins['candidate']],stdout=sp.PIPE,stderr=sp.PIPE)as right:
        dig=hashlib.sha256();size=0
        while True:
            x=left.stdout.read(65536);y=right.stdout.read(65536)
            assert x==y,('different bytes',size)
            if not x:break
            size+=len(x);dig.update(x)
        a=left.stderr.read();b=right.stderr.read();assert left.wait()==right.wait()==0 and a==b
        assert a.startswith(b'262144 states, ')and size>262144
    put('checked',dict(source=m,trees=trees,host=platform.platform(),machine=platform.machine(),compiler=os.environ.get('VSCMD_ARG_TGT_ARCH','clang'),states=262144,summary=a.decode().strip(),bytes=size,raw_sha256=dig.hexdigest(),tests=tests))
finally:
    size=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);put('cleanup',dict(removed=not t.exists(),bytes=size))
