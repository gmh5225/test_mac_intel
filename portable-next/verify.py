from pathlib import Path
import hashlib,json,os,platform,shutil,subprocess as sp,sys,tempfile
d=Path(__file__).resolve().parent;s=d.parent/'source';out=d.parent/'evidence';out.mkdir(exist_ok=True);t=Path(tempfile.mkdtemp());proj=t/'project';proj.mkdir();b=t/'build';stages=json.loads((d/'stages.json').read_text());profile=os.environ['SCAN_PROFILE']
def save(path,v):path.write_text(json.dumps(v,indent=2)+'\n')
def g(*a):return sp.check_output(['git','-C',s,*a],text=True).strip()
def cmd(path,args):
    with path.open('w')as log:rc=sp.run(args,stdout=log,stderr=sp.STDOUT).returncode
    if rc:print(path.read_text(errors='replace')[-2600:]);raise RuntimeError((args[0],rc))
try:
    lines=['cmake_minimum_required(VERSION 3.22)','project(VerifyOperands LANGUAGES C CXX)','enable_testing()',f'add_subdirectory("{s.as_posix()}" capstone)']
    lines += [f'add_executable(fields "{(d/"probe.c").as_posix()}")','target_link_libraries(fields PRIVATE capstone_static)',f'target_include_directories(fields PRIVATE "{s.as_posix()}" "{(s/"include").as_posix()}")']
    (proj/'CMakeLists.txt').write_text('\n'.join(lines)+'\n')
    cfg=['cmake','-S',proj,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']
    cfg+=dict(full=[],noatt=['-DCAPSTONE_X86_ATT_DISABLE=ON'],diet=['-DCAPSTONE_BUILD_DIET=ON'],reduced=['-DCAPSTONE_X86_REDUCE=ON'])[profile]
    win=os.name=='nt'
    if win:cfg+=['-DCMAKE_C_COMPILER=cl','-DCMAKE_CXX_COMPILER=cl','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=ON','-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded']
    for name,q in stages.items():
        v=out/name;v.mkdir();g('restore','--source','HEAD','--staged','--worktree','--','.')
        assert g('rev-parse','HEAD')==q['parent']
        patch=t/'source.patch';patch.write_bytes(sp.check_output(['git','-C',d.parent,'cat-file','blob','HEAD:portable-next/'+name+'.patch']))
        assert hashlib.sha256(patch.read_bytes()).hexdigest()==q['sha256'];
        if patch.stat().st_size:g('apply','--index',str(patch))
        assert g('write-tree')==q['tree']
        cmd(v/'configure.log',cfg)
        cmd(v/'build.log',['cmake','--build',b,'--parallel','4','--target','fields'])
        executable,=[f for f in b.rglob('fields.exe') if f.is_file()]
        cmd(v/'fields.log',[executable])
        if name in ('late','unsigned_late'):
            obj,=b.rglob('X86VectorFallback64.c.obj')
            cmd(v/'compare-disassembly.log',['dumpbin','/DISASM:NOBYTES',obj])
        fields=(v/'fields.log').read_bytes().decode('ascii','backslashreplace').splitlines();prefix,n,tag,total=fields[-1].split()
        assert prefix=='tested' and tag=='differences' and int(n)==9720 and len(fields)==2+int(total)
        save(v/'checked.json',dict(source=q,records=int(n),differences=int(total),abi=fields[0]))
finally:
    n=sum(f.stat().st_size for f in t.rglob('*') if f.is_file()and not f.is_symlink());shutil.rmtree(t);save(out/'cleanup.json',dict(removed=not t.exists(),bytes=n))
