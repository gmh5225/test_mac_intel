from pathlib import Path
import hashlib,io,json,os,shutil,subprocess as sp,sys,tarfile,tempfile
from corpus import elf_text
p=Path(__file__).resolve().parent
s=p.parent/'source'; e=p.parent/'evidence';e.mkdir(exist_ok=True)
rd=lambda f:json.loads(f.read_text())
sha=lambda data:hashlib.sha256(data).hexdigest()
t=Path(tempfile.mkdtemp()); profile=os.environ['SCAN_PROFILE'];q=rd(p/'stages.json')
def save(name, data):
    (e/(name+'.json')).write_text(json.dumps(data,indent=2)+'\n')
def git(*args):
    return sp.check_output(['git','-C',s,*args],text=True).strip()
def run(name,*args):
    with (e/(name+'.log')).open('wb')as f:rc=sp.run(args,stdout=f,stderr=sp.STDOUT)
    if rc.returncode:print((e/(name+'.log')).read_text(errors='replace')[-2200:]);rc.check_returncode()
try:
    project=t/'project';project.mkdir();b=t/'build';obs={};tests={};images={}
    (project/'CMakeLists.txt').write_text('\n'.join(['cmake_minimum_required(VERSION 3.22)','project(AArch64Verification LANGUAGES C CXX)','enable_testing()',f'add_subdirectory("{s.as_posix()}" capstone)',f'add_executable(records "{(p/"records.cpp").as_posix()}")','target_compile_features(records PRIVATE cxx_std_17)','target_link_libraries(records PRIVATE capstone_static)'])+'\n')
    corpus=rd(p/'inputs-a64.json')
    sample=next(iter(corpus.values()));package=t/'coreutils.deb'
    run('fetch','curl','-fsSL','--retry','3','--max-time','110',sample['url'],'-o',package)
    ar=package.read_bytes();assert ar[:8]==b'!<arch>\n' and all(sha(ar)==x['package_sha256'] for x in corpus.values())
    pos=8; payload=None
    while pos<len(ar):
        h=ar[pos:pos+60];assert h[58:]==b'\x60\n';n=int(h[48:58]);name=h[:16].rstrip(b' /')
        if name.startswith(b'data.tar'):assert payload is None;payload=ar[pos+60:pos+60+n]
        pos+=60+n+(n%2)
    assert pos==len(ar) and payload
    with tarfile.open(fileobj=io.BytesIO(payload),mode='r:*')as tar:
        for name,x in corpus.items():
            member,=[m for m in tar.getmembers()if m.name.lstrip('./')in ('usr/bin/'+x['command'],'bin/'+x['command']) and m.isfile()]
            body=elf_text(tar.extractfile(member).read());assert sha(body)==x['text_sha256'];(t/name).write_bytes(body)
    package.unlink()
    flags=['-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_AARCH64_SUPPORT=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_DIET='+('ON' if profile=='diet' else 'OFF')]
    names=['aarch64_scan','aarch64_postprocess']
    
    for k in ('base',*q):
        git('restore','--source','HEAD','--worktree','--staged','--','.')
        if k!='base':
            z=q[k];assert git('rev-parse','HEAD')==z['parent'];patch=t/'candidate.patch'
            patch.write_bytes(sp.check_output(['git','-C',p.parent,'cat-file','blob','HEAD:portable-next/'+k+'.patch']))
            assert sha(patch.read_bytes())==z['sha256'];git('apply','--index',patch);assert git('write-tree')==z['tree']
        run('configure-'+k,'cmake','-G','Ninja','-S',project,'-B',b,*flags)
        run('build-'+k,'cmake','--build',b,'--parallel','4','--target','records','capstone_shared',*names)
        run('unit-'+k,'ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(names)+')$')
        tests[k]=names
        exe,=[f for f in b.rglob('records.exe'if os.name=='nt'else'records')if f.is_file()];images[k]=sha(exe.read_bytes());rows=obs[k]={}
        for hooks in (0,1):
            cases=[('modes',[])]+[(name+'/'+str(mode),[t/name,str(z['ip']),str(mode)])for name,z in corpus.items()for mode in range(4)]
            for case,extra in cases:
                o=t/'result.json';log=t/'diagnostics.log'
                with log.open('wb')as f:sp.run([exe,o,str(hooks),*extra],stdout=f,stderr=sp.STDOUT,check=True)
                row=rd(o);row['diagnostics']=sha(log.read_bytes());rows[str(hooks)+'/'+case]=row
        if k!='base':assert rows==obs['base'],(k,[key for key in rows if rows[key]!=obs['base'][key]])
        assert rows['0/modes']['accepted']+rows['0/modes']['rejected']==51200 and rows['0/arm64-ls/3']['accepted']==23973
        assert rows['0/modes']['callbacks']==0 and rows['1/modes']['callbacks']==(376 if profile=='diet' else 31176)
        save('checked',obs)
    save('complete',dict(source=q,profile=profile,records=obs,units=tests,images=images))
finally:
    n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=n))
