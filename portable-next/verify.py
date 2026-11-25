from pathlib import Path
import hashlib,json,os,platform,shutil,subprocess as sp,sys,tempfile
r=Path(__file__).resolve().parent;src=r.parent/'source';e=r.parent/'evidence';e.mkdir(exist_ok=True);rd=lambda f:json.loads(f.read_text())
q=rd(r/'tree.json');profile=os.environ['SCAN_PROFILE'];cc=os.environ.get('NATIVE_COMPILER') or '';win=os.name=='nt';w=Path(tempfile.mkdtemp())
def save(n,z):(e/(n+'.json')).write_text(json.dumps(z,indent=2)+'\n')
def log(name,args,env=None):
    with (e/(name+'.log')).open('wb')as f:
        proc=sp.run(args,stdout=f,stderr=sp.STDOUT,env=env)
    if proc.returncode:
        print((e/(name+'.log')).read_text(errors='replace')[-3500:]);proc.check_returncode()
def git(*a):return sp.check_output(['git','-C',src,*a],text=True).strip()
try:
    assert git('rev-parse','HEAD')==q['parent']
    project=w/'project';project.mkdir();b=w/'build';lines=['cmake_minimum_required(VERSION 3.22)','project(MipsNames LANGUAGES C CXX)','enable_testing()',f'add_subdirectory("{src.as_posix()}" capstone)']
    for kind in ('static','shared'):
        lines+=['add_executable(record_'+kind+' "'+(r/'probe.c').as_posix()+'")','target_link_libraries(record_'+kind+' PRIVATE capstone_'+kind+')']
    (project/'CMakeLists.txt').write_text('\n'.join(lines)+'\n')
    cfg=['cmake','-G','Ninja','-S',project,'-B',b,'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_MIPS_SUPPORT=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']
    if cc in ('gcc','clang'):os.environ.update(CC=cc,CXX='g++'if cc=='gcc' else 'clang++')
    if win:cfg+=['-DCMAKE_C_COMPILER=cl','-DCMAKE_CXX_COMPILER=cl','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=ON','-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded']
    if profile=='diet':cfg+=['-DCAPSTONE_BUILD_DIET=ON']
    units=['mips_scan'] if profile=='diet' else ['mips_register_names','mips_scan','mips_reglist_offset','mips_msa_control','mips16_word_order','mips16_immediates','mips16_memory_calls','mips16_shifts_hilo','mips16_frames','mips16e2']
    results={};objects={};tree={}
    for tag in ('base','release'):
        if tag=='release':
            p=w/'release.patch';p.write_bytes(sp.check_output(['git','-C',r.parent,'cat-file','blob','HEAD:portable-next/candidate.patch']))
            assert hashlib.sha256(p.read_bytes()).hexdigest()==q['sha256'];git('apply','--index',str(p));assert git('write-tree')==q['tree']
        tree[tag]=git('write-tree');log(tag+'-generator',[sys.executable,'-B',src/'suite/synctools/mips_register_names.py','--check'])
        log(tag+'-config',cfg);log(tag+'-build',['cmake','--build',b,'--target','record_static','record_shared',*units,'--parallel','4'])
        log(tag+'-tests',['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(units)+')$'])
        env=dict(os.environ)
        if win:
            dll,=[x for x in b.rglob('capstone.dll')if x.is_file()]
            env['PATH']=str(dll.parent)+os.pathsep+env['PATH']
        results[tag]={}
        for kind in ('static','shared'):
            exe,=[x for x in b.rglob('record_'+kind+('.exe' if win else '')) if x.is_file()]
            results[tag][kind]=list(map(int,sp.check_output([exe],env=env,text=True).split()))
        assert results[tag]['static']==results[tag]['shared'] and sum(results[tag]['static'][:2])==32768
        if platform.system()=='Linux':
            objects[tag]={str(f.relative_to(b)):hashlib.sha256(f.read_bytes()).hexdigest()for f in b.rglob('*.c.o') if 'capstone.dir' in str(f)}
            assert len(objects[tag])>=10
    assert results['base']==results['release']
    changed=[]
    if objects:
        assert objects['base'].keys()==objects['release'].keys();changed=[Path(k).name for k in objects['base']if objects['base'][k]!=objects['release'][k]]
        enabled=platform.machine()=='x86_64' and cc=='clang' and profile=='full'
        assert changed==(['MipsInstPrinter.c.o'] if enabled else []),(changed,enabled)
    save('complete',dict(complete=True,source=q,trees=tree,records=results,units=units,changed_objects=changed,arch=platform.machine(),platform=platform.system(),compiler=cc,profile=profile))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
