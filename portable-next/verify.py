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
    for suffix in ('static','shared'):
        lines += [f'add_executable(probe_{suffix} "{(d/"registers.c").as_posix()}")',f'target_link_libraries(probe_{suffix} PRIVATE capstone_{suffix})',f'target_include_directories(probe_{suffix} PRIVATE "{(s/"include").as_posix()}")']
    lines += [f'add_executable(vector_rows "{(s/"suite/synctools/x86_vector_output.cpp").as_posix()}")','target_compile_features(vector_rows PRIVATE cxx_std_17)','target_link_libraries(vector_rows PRIVATE capstone_static)',f'target_include_directories(vector_rows PRIVATE "{(s/"include").as_posix()}")']
    (proj/'CMakeLists.txt').write_text('\n'.join(lines)+'\n')
    cfg=['cmake','-S',proj,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']
    cfg+=dict(full=[],noatt=['-DCAPSTONE_X86_ATT_DISABLE=ON'],diet=['-DCAPSTONE_BUILD_DIET=ON'],reduced=['-DCAPSTONE_X86_REDUCE=ON'])[profile]
    win=os.name=='nt'
    if win:cfg+=['-DCMAKE_C_COMPILER=cl','-DCMAKE_CXX_COMPILER=cl','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=ON','-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded']
    for name,q in stages.items():
        v=out/name;v.mkdir();g('restore','--source','HEAD','--staged','--worktree','--','.')
        assert g('rev-parse','HEAD')==q['parent']
        patch=t/'source.patch';patch.write_bytes(sp.check_output(['git','-C',d.parent,'cat-file','blob','HEAD:portable-next/'+name+'.patch']))
        assert hashlib.sha256(patch.read_bytes()).hexdigest()==q['sha256'];g('apply','--index',str(patch));assert g('write-tree')==q['tree']
        cmd(v/'configure.log',cfg)
        names={z['name']for z in json.loads(sp.check_output(['ctest','--test-dir',b,'-C','Release','--show-only=json-v1'],text=True))['tests']}
        possible=['x86_scan_batch','x86_simple_output','x86_reg_access','x86_buffer_bounds','x86_mapping_counts','x86_bound_access','x86_exchange_access','x86_encoding_accuracy','x86_evex_move_access','detail_option','text_option','x86_x87_environment']
        targets=[a for a in possible if 'unit_'+a in names]
        assert 'x86_scan_batch' in targets and 'x86_buffer_bounds' in targets and 'x86_mapping_counts'in targets
        full=profile in ('full','noatt')
        if full:assert 'x86_simple_output'in targets
        cmd(v/'build.log',['cmake','--build',b,'--parallel','4','--target','capstone_static','capstone_shared',*targets, *(['probe_static','probe_shared','vector_rows']if full else [])])
        cmd(v/'tests.log',['ctest','--test-dir',b,'-C','Release','--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(targets)+')$'])
        cmd(v/'mapping.log',[sys.executable,'-B',s/'suite/synctools/x86_mapping_counts.py','--check'])
        if full:
            dll_dirs=[str(p.parent)for p in b.rglob('*.dll')]
            env=dict(os.environ,PATH=os.pathsep.join(dll_dirs+[os.environ['PATH']]))
            exe,=[f for f in b.rglob('vector_rows'+('.exe' if win else ''))if f.is_file()]
            table=sp.check_output([exe],env=env).replace(b'\r\n',b'\n')
            assert table==(s/'arch/X86/X86GenVectorOutput.inc').read_bytes().replace(b'\r\n',b'\n')
            save(v/'table.json',dict(bytes=len(table),sha256=hashlib.sha256(table).hexdigest()))
            if name=='memory':
                table,filename=('--vex-base-memory','X86GenVexBaseMemory.inc') if name=='memory' else ('--integer-block-broadcast','X86GenIntegerBlockBroadcast.inc')
                bits=sp.check_output([exe,table],env=env).replace(b'\r\n',b'\n')
                assert bits==(s/'arch/X86'/filename).read_bytes().replace(b'\r\n',b'\n')
                save(v/'bits.json',dict(sha256=hashlib.sha256(bits).hexdigest(),bytes=len(bits)))
            rows=[]
            for suffix in ('static','shared'):
                exe,=[f for f in b.rglob('probe_'+suffix+('.exe' if win else '')) if f.is_file()]
                obs=[ln.split()for ln in sp.check_output([exe],text=True,env=env).splitlines()];assert len(obs)==12
                for bits,instr,vex,num,write,first,last in obs:
                    count=8 if name in ('repair','combined') and bits!='64' else 16
                    assert int(num)==int(write)==count and first=='ymm0' and last=='ymm'+str(count-1)
                rows.append(obs)
            assert rows[0]==rows[1];save(v/'vzero.json',rows[0])
        save(v/'checked.json',dict(complete=True,source=q,profile=profile,tests=targets,host=platform.machine(),full=full))
finally:
    n=sum(f.stat().st_size for f in t.rglob('*') if f.is_file()and not f.is_symlink());shutil.rmtree(t);save(out/'cleanup.json',dict(removed=not t.exists(),bytes=n))
