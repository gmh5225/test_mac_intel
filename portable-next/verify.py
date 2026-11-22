from pathlib import Path
import hashlib,json,os,platform,shutil,subprocess as sp,tempfile
d=Path(__file__).resolve().parent;s=d.parent/'source';out=d.parent/'evidence';out.mkdir(exist_ok=True)
def g(*a):return sp.check_output(['git','-C',s,*a],text=True).strip()
def save(n,v):(out/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def cmd(n,args):
 with (out/(n+'.log')).open('w')as f:z=sp.run(args,stdout=f,stderr=sp.STDOUT)
 if z.returncode:print((out/(n+'.log')).read_text(errors='replace')[-2600:]);z.check_returncode()
q=json.loads((d/'tree.json').read_text());profile=os.environ['SCAN_PROFILE'];win=os.name=='nt';t=Path(tempfile.mkdtemp());h=t/'project';b=t/'build';h.mkdir()
try:
 assert g('rev-parse','HEAD')==q['parent'];patch=t/'source.patch';patch.write_bytes(sp.check_output(['git','-C',d.parent,'cat-file','blob','HEAD:portable-next/candidate.patch']));assert hashlib.sha256(patch.read_bytes()).hexdigest()==q['sha256']
 (h/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(OutputRecords LANGUAGES C CXX)\nenable_testing()\nadd_subdirectory("'+s.as_posix()+'" capstone)\nadd_executable(check-rows "'+(s/'suite/synctools/x86_vector_output.cpp').as_posix()+'")\ntarget_compile_features(check-rows PRIVATE cxx_std_17)\ntarget_include_directories(check-rows PRIVATE "'+(s/'include').as_posix()+'")\ntarget_link_libraries(check-rows capstone_static)\n')
 cfg=['cmake','-S',h,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']
 cfg+={'full':[],'noatt':['-DCAPSTONE_X86_ATT_DISABLE=ON'],'diet':['-DCAPSTONE_BUILD_DIET=ON'],'reduced':['-DCAPSTONE_X86_REDUCE=ON']}[profile]
 if win:cfg+=['-DCMAKE_C_COMPILER=cl','-DCMAKE_CXX_COMPILER=cl','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=ON','-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded']
 cmd('configure',cfg)
 if profile in ('diet','noatt'):
    cmd('baseline-build',['cmake','--build',b,'--parallel','4','--target','x86_exchange_access'])
    pre=sp.run(['ctest','--test-dir',b,'-C','Release','--output-on-failure','--no-tests=error','-R','^unit_x86_exchange_access$'],stdout=sp.PIPE,stderr=sp.STDOUT)
    (out/'baseline-units.log').write_bytes(pre.stdout)
    assert pre.returncode and b'exchange effects:' in pre.stdout and b'1 tests failed out of 1' in pre.stdout,pre.stdout[-800:]
 g('apply','--index',str(patch));assert g('write-tree')==q['tree']
 cmd('candidate-configure',cfg)
 names={x['name'] for x in json.loads(sp.check_output(['ctest','--test-dir',b,'-C','Release','--show-only=json-v1'],text=True))['tests']}
 suite=['x86_simple_output','x86_buffer_bounds','x86_packed_move_access','x86_reg_access','detail_option','text_option','x86_scan_batch','x86_mapping_counts','x86_evex_move_access','x86_bound_access','x86_exchange_access','x86_encoding_accuracy']
 tests=[n for n in suite if 'unit_'+n in names];full=profile in ('full','noatt')
 assert len(tests)>=4 and ('x86_simple_output' in tests or not full),(profile,tests)
 cmd('build',['cmake','--build',b,'--parallel','4','--target','capstone_static','capstone_shared',*tests,*(['check-rows'] if full else [])])
 cmd('units',['ctest','--test-dir',b,'-C','Release','--output-on-failure','--no-tests=error','-R','^unit_('+'|'.join(tests)+')$'])
 if full:
    exe,=[f for f in b.rglob('check-rows.exe'if win else 'check-rows')if f.is_file()]
    data=sp.check_output([exe,'--vex32-memory']).replace(b'\r\n',b'\n');assert data==(s/'arch/X86/X86GenVex32MemoryOutput.inc').read_bytes().replace(b'\r\n',b'\n') and b'vex32_move_rows[2]'in data
 save('checked',dict(complete=True,source=q,profile=profile,tests=tests,machine=platform.machine(),generator=bool(full)))
finally:
 n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=n))
