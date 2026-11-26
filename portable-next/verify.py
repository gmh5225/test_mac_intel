from pathlib import Path
import hashlib,json,os,re,shutil,subprocess as sp,tempfile
p=Path(__file__).resolve().parent;s=p.parent/'source';e=p.parent/'evidence';e.mkdir(exist_ok=True)
t=Path(tempfile.mkdtemp());q=json.loads((p/'stages.json').read_text());profile=os.environ['SCAN_PROFILE']
def save(k,x):(e/(k+'.json')).write_text(json.dumps(x,indent=2)+'\n')
def git(*args):return sp.check_output(['git','-C',s,*args],text=True).strip()
def run(k,*args):
    with (e/(k+'.log')).open('wb')as f:rc=sp.run(args,stdout=f,stderr=sp.STDOUT)
    if rc.returncode:print((e/(k+'.log')).read_text(errors='replace')[-2500:],flush=True);rc.check_returncode()
try:
    pr=t/'project';pr.mkdir();b=t/'build';env=os.environ.copy()
    cm=['cmake_minimum_required(VERSION 3.22)','project(ArmRecords LANGUAGES C CXX)','enable_testing()',f'add_subdirectory("{s.as_posix()}" capstone)']
    for link in ('static','shared'):
        name='records_'+link;cm+= [f'add_executable({name} "{(p/"arm-record.cpp").as_posix()}")',f'target_compile_features({name} PRIVATE cxx_std_17)',f'target_link_libraries({name} PRIVATE capstone_{link})']
    (pr/'CMakeLists.txt').write_text('\n'.join(cm)+'\n')
    stream=bytearray()
    for f in sorted((s/'suite/MC/ARM').glob('*.s.cs')):
        for l in f.read_text().splitlines():
            x=l.partition('=')[0].strip()
            if re.fullmatch(r'0x[0-9a-fA-F]{2}(?:,\s*0x[0-9a-fA-F]{2}){3}',x):stream.extend(int(c,16) for c in x.split(','))
    assert len(stream)>256;data=t/'arm.bin';data.write_bytes(stream)
    flags=['-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_ARM_SUPPORT=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']
    if profile=='diet':flags.append('-DCAPSTONE_BUILD_DIET=ON')
    names=[] if profile=='diet' else ['arm_private_stream','arm_post_index','arm_reg_access']
    assert git('rev-parse','HEAD')==q['base']['commit'];results={}
    for k,z in q.items():
        git('restore','--source=HEAD','--staged','--worktree','--','.')
        if k!='base':
            patch=t/(k+'.patch')
            patch.write_bytes(sp.check_output(['git','-C',p.parent,'cat-file','blob','HEAD:portable-next/'+k+'.patch']))
            assert hashlib.sha256(patch.read_bytes()).hexdigest()==z['combined_sha256'];git('apply','--index',patch)
        assert git('write-tree')==z['tree']
        run(k+'-configure','cmake','-G','Ninja','-S',pr,'-B',b,*flags)
        run(k+'-build','cmake','--build',b,'--parallel','4','--target','records_static','records_shared',*names)
        if names:run(k+'-units','ctest','--test-dir',b,'--output-on-failure','--no-tests=error','-R','^unit_('+'|'.join(names)+')$')
        if os.name=='nt':
            dlls=list(b.rglob('capstone*.dll'));assert dlls;env['PATH']=os.pathsep.join(str(f.parent)for f in dlls)+os.pathsep+os.environ['PATH']
        records={}
        for link in ('static','shared'):
            exe,=[f for f in b.rglob('records_'+link+('.exe' if os.name=='nt'else ''))if f.is_file()]
            obs=sp.check_output([exe,data],text=True,env=env).splitlines();assert len(obs)==(8 if profile=='diet'else 16) and all(int(l.split()[3])>0 for l in obs);records[link]=obs
        assert records['static']==records['shared']
        if k!='base':assert records==results['base']
        results[k]=records;save('checked',results)
    save('complete',dict(complete=True,source=q,profile=profile,cases=len(stream)//4,digest=hashlib.sha256(stream).hexdigest(),views=results,units=names))
finally:
    n=sum(f.stat().st_size for f in t.rglob('*') if f.is_file()and not f.is_symlink());shutil.rmtree(t);save('cleanup',dict(bytes=n,removed=not t.exists()))
