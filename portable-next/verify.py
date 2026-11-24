from pathlib import Path
import hashlib,json,os,shutil,subprocess as sp,sys,tempfile
d=Path(__file__).resolve().parent;s=d.parent/'source';out=d.parent/'evidence';out.mkdir(exist_ok=True);t=Path(tempfile.mkdtemp());profile=os.environ['SCAN_PROFILE'];win=os.name=='nt';rd=lambda f:json.loads(f.read_text());stages=rd(d/'stages.json')
def save(n,v):(out/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def cmd(n,args):
    with (out/(n+'.log')).open('w')as log:x=sp.run(args,stdout=log,stderr=sp.STDOUT)
    if x.returncode:print((out/(n+'.log')).read_text(errors='replace')[-1800:]);x.check_returncode()
def g(*a):return sp.check_output(['git','-C',s,*a],text=True).strip()
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
try:
    project=t/'project';project.mkdir();b=t/'build'
    cm=['cmake_minimum_required(VERSION 3.22)','project(PublicRecords LANGUAGES C CXX)','enable_testing()',f'add_subdirectory("{s.as_posix()}" capstone)',f'add_executable(checker "{(d/"compare.cpp").as_posix()}")','target_compile_features(checker PRIVATE cxx_std_17)',f'target_include_directories(checker PRIVATE "{(s/"include").as_posix()}")']
    if profile=='noatt':cm.append('target_compile_definitions(checker PRIVATE VERIFY_NO_ATT)')
    (project/'CMakeLists.txt').write_text('\n'.join(cm)+'\n')
    shutil.copy2(d/'fetch.py',t/'fetch.py');cmd('fetch',[sys.executable,'-B',t/'fetch.py'])
    samples=rd(d/'inputs.json');files={}
    for w in (32,64):
        files[w]=t/('putty-0.85-'+str(w)+'.text');assert sha(files[w])==samples['putty'+str(w)]['sha256']
    flags=['-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=OFF','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']
    flags+=['-DCAPSTONE_'+a+'_SUPPORT=ON'for a in ('X86',)]
    flags+=dict(full=[],noatt=['-DCAPSTONE_X86_ATT_DISABLE=ON'],diet=['-DCAPSTONE_BUILD_DIET=ON'],reduced=['-DCAPSTONE_X86_REDUCE=ON'])[profile]
    ports={};images={};libs={};units=['x86_buffer_bounds','x86_scan_batch','x86_reg_access','x86_x87_environment']if profile in ('full','noatt')else['x86_buffer_bounds','x86_scan_batch']
    for k in ('base',*stages):
        g('restore','--source','HEAD','--worktree','--staged','--','.')
        if k!='base':
            q=stages[k];assert g('rev-parse','HEAD')==q['parent']
            patch=t/'trial.patch';patch.write_bytes(sp.check_output(['git','-C',d.parent,'cat-file','blob','HEAD:portable-next/'+k+'.patch']));assert sha(patch)==q['sha256'];g('apply','--index',patch);assert g('write-tree')==q['tree']
        cmd('configure-'+k,['cmake','-G','Ninja','-S',project,'-B',b,*flags])
        cmd('build-'+k,['cmake','--build',b,'--parallel','4','--target','capstone_shared','checker',*units])
        cmd('unit-'+k,['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(units)+')$'])
        lib,=[f for f in b.rglob('*.dll' if win else '*.dylib')if 'capstone'in f.name.lower()and f.is_file()and not f.is_symlink()]
        ext='.dll'if win else'.dylib';path=t/(k+ext);shutil.copy2(lib,path);libs[k]=path;images[k]=sha(path)
        if k=='base':continue
        exe,=[f for f in b.rglob('checker'+('.exe'if win else''))if f.is_file()];results=ports[k]={}
        for w in (16,32,64):
            sample=64 if w==64 else 32
            args=[exe,libs['base'],path,files[sample],str(w),str(samples['putty'+str(sample)]['address'])]
            cmd(k+'-width-'+str(w),args);obs=[json.loads(l)for l in (out/(k+'-width-'+str(w)+'.log')).read_text().splitlines()];assert len(obs)==2 and obs[0]['width']==w and obs[0]['records']>0 and obs[1]['callback_events']>0 and obs[1]['reentrant_details'];results[str(w)]=obs
        save('checked',ports)
        if profile=='full':
            duplicate=t/('duplicate'+ext);shutil.copy2(libs['base'],duplicate);assert sha(duplicate)==images['base']
            timings={}
            for width in (32,64):
                for seed in range(18):
                    obs=sp.check_output([exe,libs['base'],duplicate,path,files[width],str(width),str(samples['putty'+str(width)]['address']),str(1260+seed)],text=True)
                    groups={}
                    for line in obs.splitlines():
                        m,it,stage,cpu,wall,records,checksum=map(int,line.split());groups.setdefault(str(width)+'/'+str(it)+'/'+str(m),{})[('base','copy','batch')[stage]]=[cpu,wall,records,checksum]
                    assert len(groups)==3 and all(len(v)==3 and len({tuple(a[2:])for a in v.values()})==1 for v in groups.values())
                    for panel,cycle in groups.items():timings.setdefault(panel,[]).append(cycle)
            save('timings-'+k,timings)
    assert set(ports)==set(stages);save('complete',dict(source=stages,profile=profile,images=images,records=ports,units=units))
finally:
    n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=n))
