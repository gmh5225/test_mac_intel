from pathlib import Path
import hashlib,json,os,platform,shutil,subprocess as sp,tempfile
d=Path(__file__).resolve().parent;s=d.parent/'source';stage=os.environ['BATCH_STAGE'];out=d.parent/'evidence'/stage;out.mkdir(exist_ok=True,parents=True)
def g(*a):return sp.check_output(['git','-C',s,*a],text=True).strip()
def save(n,z):(out/(n+'.json')).write_text(json.dumps(z,indent=2)+'\n')
def run(n,args):
    with (out/(n+'.log')).open('w')as f:z=sp.run(list(map(str,args)),stdout=f,stderr=sp.STDOUT)
    if z.returncode:print((out/(n+'.log')).read_text(errors='replace')[-2500:],flush=True);z.check_returncode()
q=json.loads((d/'stages.json').read_text())[stage];assert g('rev-parse','HEAD')==q['checkout'];t=Path(tempfile.mkdtemp());win=os.name=='nt'
try:
    patch=t/'candidate.patch';patch.write_bytes(sp.check_output(['git','-C',d.parent,'cat-file','blob','HEAD:portable-next/'+stage+'.patch']));assert hashlib.sha256(patch.read_bytes()).hexdigest()==q['checkout_sha256'];g('apply','--index',str(patch));assert g('write-tree')==q['tree']
    h=t/'h';h.mkdir();shutil.copy2(d/'guard.cpp',h/'guard.cpp');shutil.copy2(d/'secondary.cpp',h/'secondary.cpp');shutil.copy2(d/'second.c',h/'second.c')
    cmake='''cmake_minimum_required(VERSION 3.22)
project(BatchGuard LANGUAGES C CXX)
enable_testing()
add_subdirectory("CAP_SRC" capstone)
add_executable(batchguard guard.cpp)
target_compile_features(batchguard PRIVATE cxx_std_17)
target_link_libraries(batchguard PRIVATE capstone_static)
target_include_directories(batchguard PRIVATE "CAP_SRC")
if(CHECK_SECONDARY)
  add_library(observed OBJECT second.c)
  target_compile_definitions(observed PRIVATE CAPSTONE_HAS_X86 CAPSTONE_USE_SYS_DYN_MEM)
  target_link_libraries(observed PRIVATE capstone)
  target_include_directories(observed PRIVATE "CAP_SRC" "CAP_SRC/include")
  add_executable(secondaryguard secondary.cpp $<TARGET_OBJECTS:observed>)
  target_compile_features(secondaryguard PRIVATE cxx_std_17)
  target_include_directories(secondaryguard PRIVATE "CAP_SRC")
  target_link_libraries(secondaryguard PRIVATE capstone_static)
endif()
if(CAPSTONE_X86_SCAN_ADAPTER)
  target_compile_definitions(batchguard PRIVATE CHECK_ADAPTER)
endif()
'''.replace('CAP_SRC',s.as_posix());(h/'CMakeLists.txt').write_text(cmake)
    profiles={'full':[],'adapter':['-DCAPSTONE_X86_SCAN_ADAPTER=ON'],'reduced':['-DCAPSTONE_X86_REDUCE=ON'],'diet':['-DCAPSTONE_BUILD_DIET=ON']}
    answers={}
    for prof,flags in profiles.items():
        if prof != os.environ['SCAN_PROFILE']:continue
        b=t/prof;units=['x86_scan_batch','x86_encoding_accuracy','text_option','detail_option']
        cmd=['cmake','-G','Ninja','-S',h,'-B',b,'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF',*flags]
        secondary=(stage=='private' and prof=='full')
        if secondary:cmd+=['-DCHECK_SECONDARY=ON']
        if win:cmd+=['-DCMAKE_C_COMPILER=cl','-DCMAKE_CXX_COMPILER=cl','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=ON','-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded']
        run('configure-'+prof,cmd);run('build-'+prof,['cmake','--build',b,'--parallel','4','--target','batchguard',*units]);run('units-'+prof,['ctest','--test-dir',b,'-C','Release','--output-on-failure','--no-tests=error','-R','^unit_('+'|'.join(units)+')$'])
        exe,=[x for x in b.rglob('batchguard.exe'if win else 'batchguard')if x.is_file()];run('guard-'+prof,[exe])
        if secondary:
            run('build-secondary',['cmake','--build',b,'--target','secondaryguard','--parallel','4'])
            oracle,=[x for x in b.rglob('secondaryguard.exe'if win else 'secondaryguard')if x.is_file()]
            run('secondary-oracle',[oracle]);assert (out/'secondary-oracle.log').read_text().split()==['13369344','7521547']
        counts=(out/('guard-'+prof+'.log')).read_text().split();assert int(counts[0])>10000000 and int(counts[1])>0
        answers[prof]=dict(states=int(counts[0]),accepted=int(counts[1]),digest=counts[2],tests=units);save('progress',answers);shutil.rmtree(b)
    save('checked',dict(complete=True,source=q,results=answers,host=platform.platform(),machine=platform.machine()))
finally:
    n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=n))
