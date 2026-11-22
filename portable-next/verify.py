from pathlib import Path
import hashlib,json,sys,os,platform,shutil,subprocess as sp,tempfile
d=Path(__file__).resolve().parent;s=d.parent/'source';out=d.parent/'evidence';out.mkdir(exist_ok=True)
def g(*a):return sp.check_output(['git','-C',s,*a],text=True).strip()
def save(n,v):(out/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def cmd(n,args):
 with (out/(n+'.log')).open('w')as f:z=sp.run(args,stdout=f,stderr=sp.STDOUT)
 if z.returncode:print((out/(n+'.log')).read_text(errors='replace')[-2600:]);z.check_returncode()
stages=json.loads((d/'stages.json').read_text());profile=os.environ['SCAN_PROFILE'];win=os.name=='nt';t=Path(tempfile.mkdtemp());h=t/'project';b=t/'build';h.mkdir()
try:
 (h/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(OutputRecords LANGUAGES C CXX)\nenable_testing()\nadd_subdirectory("'+s.as_posix()+'" capstone)\nadd_executable(check-rows "'+(s/'suite/synctools/x86_vector_output.cpp').as_posix()+'")\ntarget_compile_features(check-rows PRIVATE cxx_std_17)\ntarget_include_directories(check-rows PRIVATE "'+(s/'include').as_posix()+'")\ntarget_link_libraries(check-rows capstone_static)\n')
 extra='''
add_executable(check-memory "SOURCE/suite/synctools/x86_simple_output.cpp")
target_compile_features(check-memory PRIVATE cxx_std_17)
target_include_directories(check-memory PRIVATE "SOURCE/include")
target_link_libraries(check-memory PRIVATE capstone_static)
add_library(observed OBJECT "INPUT/second.c")
target_compile_definitions(observed PRIVATE CAPSTONE_HAS_X86 CAPSTONE_USE_SYS_DYN_MEM)
target_include_directories(observed PRIVATE "SOURCE" "SOURCE/include")
target_link_libraries(observed PRIVATE capstone)
foreach(name IN ITEMS rounded shift mandatory vex3)
  add_executable(probe-${name} "INPUT/${name}.cpp" $<TARGET_OBJECTS:observed>)
  target_compile_features(probe-${name} PRIVATE cxx_std_17)
  target_include_directories(probe-${name} PRIVATE "SOURCE")
  target_link_libraries(probe-${name} PRIVATE capstone_static)
endforeach()

add_executable(check-vzero "INPUT/registers.c")
target_include_directories(check-vzero PRIVATE "SOURCE/include")
target_link_libraries(check-vzero PRIVATE capstone_static)

foreach(kind IN ITEMS plain legacy rip)
  add_library(check-${kind}-observed OBJECT "INPUT/${kind}.c")
  target_compile_definitions(check-${kind}-observed PRIVATE CAPSTONE_HAS_X86 CAPSTONE_USE_SYS_DYN_MEM)
  target_include_directories(check-${kind}-observed PRIVATE "SOURCE" "SOURCE/include")
  target_link_libraries(check-${kind}-observed PRIVATE capstone)
  add_executable(probe-${kind} "INPUT/${kind}.cpp" $<TARGET_OBJECTS:check-${kind}-observed>)
  target_compile_features(probe-${kind} PRIVATE cxx_std_17)
  target_include_directories(probe-${kind} PRIVATE "SOURCE" "SOURCE/include")
  target_link_libraries(probe-${kind} PRIVATE capstone_static)
endforeach()
'''.replace('SOURCE',s.as_posix()).replace('INPUT',d.as_posix())
 with (h/'CMakeLists.txt').open('a')as f:f.write(extra)
 cfg=['cmake','-S',h,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_AARCH64_SUPPORT=ON','-DCAPSTONE_ARM_SUPPORT=ON','-DCAPSTONE_MIPS_SUPPORT=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']
 cfg+={'full':[],'noatt':['-DCAPSTONE_X86_ATT_DISABLE=ON'],'diet':['-DCAPSTONE_BUILD_DIET=ON'],'reduced':['-DCAPSTONE_X86_REDUCE=ON']}[profile]
 if win:cfg+=['-DCMAKE_C_COMPILER=cl','-DCMAKE_CXX_COMPILER=cl','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=ON','-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded']
 root_out=out
 for label,q in stages.items():
    out=root_out/label;out.mkdir(exist_ok=True)
    g('restore','--source','HEAD','--staged','--worktree','--','.')
    assert g('rev-parse','HEAD')==q['parent'];patch=t/'source.patch';patch.write_bytes(sp.check_output(['git','-C',d.parent,'cat-file','blob','HEAD:portable-next/'+label+'.patch']));assert hashlib.sha256(patch.read_bytes()).hexdigest()==q['sha256']
    g('apply','--index',str(patch));assert g('write-tree')==q['tree']
    cmd('candidate-configure',cfg)
    names={x['name'] for x in json.loads(sp.check_output(['ctest','--test-dir',b,'-C','Release','--show-only=json-v1'],text=True))['tests']}
    suite=['x86_simple_output','x86_buffer_bounds','x86_packed_move_access','x86_reg_access','detail_option','text_option','x86_scan_batch','x86_mapping_counts','x86_evex_move_access','x86_bound_access','x86_exchange_access','x86_encoding_accuracy']
    suite.extend(['mips_single','mips_scan','mips16_frames','mips_msa_control','aarch64_scan','aarch64_postprocess'])
    tests=[n for n in suite if 'unit_'+n in names];full=profile in ('full','noatt')
    assert len(tests)>=4 and ('x86_simple_output' in tests or not full),(profile,tests)
    cmd('build',['cmake','--build',b,'--parallel','4','--target','capstone_static','capstone_shared',*tests,*(['check-rows','check-memory'] if full else []),*(['probe-mandatory','probe-vex3'] if full else []),*(['probe-rounded','probe-shift'] if full else [])])
    cmd('units',['ctest','--test-dir',b,'-C','Release','--output-on-failure','--no-tests=error','-R','^unit_('+'|'.join(tests)+')$'])
    if full:
       exe,=[f for f in b.rglob('check-rows.exe'if win else 'check-rows')if f.is_file()]
       data=sp.check_output([exe,'--vex32-memory']).replace(b'\r\n',b'\n');assert data==(s/'arch/X86/X86GenVex32MemoryOutput.inc').read_bytes().replace(b'\r\n',b'\n') and b'vex32_move_rows[2]'in data
       def check_table(target,flag,name):
           executable,=[p for p in b.rglob(target+('.exe' if win else ''))if p.is_file()]
           got=sp.check_output([executable,flag]).replace(b'\r\n',b'\n')
           assert got==(s/'arch/X86'/name).read_bytes().replace(b'\r\n',b'\n'),name
       def guard(name,expected):
           exe,=[f for f in b.rglob('probe-'+name+('.exe' if win else ''))if f.is_file()]
           actual=list(map(int,sp.check_output([exe]).split()))
           assert actual==expected,(name,actual)
           save('oracle-'+name,dict(counts=actual))
       for name,expected in [('mandatory',[13369344,6120742]),('vex3',[18874368,1074938])]:
           guard(name,expected)
       check_table('check-memory','--legacy-packed-memory','X86GenLegacyPackedMemory.inc')
       check_table('check-rows','--evex-shifts','X86GenEvexShiftOutput.inc')
       check_table('check-rows','--rounded-registers64','X86GenRoundedRegister64.inc')
       for name,expected in [('rounded',[12582912,40376]),('shift',[10485760,2160])]:
           guard(name,expected)
       check_table('check-rows','--evex-memory','X86GenEvexMemoryOutput.inc')
       check_table('check-rows','--vex-register-immediates','X86GenVexRegisterImmediates.inc')
       check_table('check-rows','--plain-evex-registers','X86GenPlainEvexRegisterOutput.inc')
       cmd('build-plain',['cmake','--build',b,'--target','probe-plain','--parallel','4'])
       guard('plain',[11337732,0,47444])
       check_table('check-rows','--evex-rip-memory','X86GenEvexRipMemory.inc')
       cmd('build-rip',['cmake','--build',b,'--target','probe-rip','--parallel','4'])
       guard('rip',[15532048,0,36310])
       if label=='combined':
           check_table('check-rows','--legacy-register-immediates','X86GenLegacyRegisterImmediates.inc')
           cmd('build-legacy',['cmake','--build',b,'--target','probe-legacy','--parallel','4'])
           guard('legacy',[3785220,0,1253376])
           check_table('check-memory','--test32-registers','X86GenTest32Registers.inc')
       cmd('build-vzero',['cmake','--build',b,'--target','check-vzero','--parallel','4'])
       vz,=[f for f in b.rglob('check-vzero.exe' if win else 'check-vzero')if f.is_file()]
       obs=[ln.split()for ln in sp.check_output([vz],text=True).splitlines()];assert len(obs)==12
       for bits,name,enc,num,nw,first,last in obs:
           expected=16
           assert int(num)==int(nw)==expected and first=='ymm0' and last=='ymm'+str(expected-1)
       save('vzero',obs)
    cmd('mapping-counts',[sys.executable,'-B',s/'suite/synctools/x86_mapping_counts.py','--check'])
    alias_check=(s/'suite/synctools/alias_pattern_rows.py').is_file()
    if alias_check:cmd('alias-table',[sys.executable,'-B',s/'suite/synctools/alias_pattern_rows.py','--check'])
    assert alias_check
    save('checked',dict(stage=label,complete=True,source=q,profile=profile,tests=tests,machine=platform.machine(),generator=bool(full),alias_check=alias_check))
finally:
 n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);out=d.parent/'evidence';save('cleanup',dict(removed=not t.exists(),bytes=n))
