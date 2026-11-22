from pathlib import Path
import hashlib,json,os,platform,shutil,subprocess as sp,tempfile
d=Path(__file__).resolve().parent;s=d.parent/'source';out=d.parent/'evidence';out.mkdir(exist_ok=True)
sha=lambda b:hashlib.sha256(b).hexdigest()
def g(*a):return sp.check_output(['git','-C',s,*a],text=True).strip()
def run(n,args):
    with (out/(n+'.log')).open('w')as f:z=sp.run(list(map(str,args)),stdout=f,stderr=sp.STDOUT)
    if z.returncode:print((out/(n+'.log')).read_text(errors='replace')[-2200:],flush=True);z.check_returncode()
def save(n,z):(out/(n+'.json')).write_text(json.dumps(z,indent=2)+'\n')
m=json.loads((d/'revisions.json').read_text());assert g('rev-parse','HEAD')==m['candidate']['parent']
t=Path(tempfile.mkdtemp());windows=os.name=='nt';profiles={'full':[], 'no-att':['-DCAPSTONE_X86_ATT_DISABLE=ON'], 'reduced':['-DCAPSTONE_X86_REDUCE=ON'], 'diet':['-DCAPSTONE_BUILD_DIET=ON']}
try:
    harness=t/'harness';harness.mkdir();shutil.copy2(d/'mapper.c',harness/'mapper.c')
    cmake='''cmake_minimum_required(VERSION 3.22)
project(PortableMapper LANGUAGES C CXX)
enable_testing()
add_subdirectory("CAP_SRC" capstone)
add_executable(mapper mapper.c)
target_link_libraries(mapper PRIVATE capstone_static)
target_compile_definitions(mapper PRIVATE CAPSTONE_HAS_X86)
target_include_directories(mapper PRIVATE "CAP_SRC")
if(CAPSTONE_X86_REDUCE)
  target_compile_definitions(mapper PRIVATE CAPSTONE_X86_REDUCE)
endif()
if(CAPSTONE_BUILD_DIET)
  target_compile_definitions(mapper PRIVATE CAPSTONE_DIET)
endif()
'''.replace('CAP_SRC',s.as_posix());(harness/'CMakeLists.txt').write_text(cmake)
    answers={};records={}
    for stage in ('oracle','candidate'):
        g('restore','--source','HEAD','--staged','--worktree','--','.')
        # These two generated headers do not exist at the released revision. git restore above removes newly staged files.
        data=sp.check_output(['git','-C',d.parent,'cat-file','blob','HEAD:portable-next/'+stage+'.patch'])
        assert sha(data)==m[stage]['sha256'];patch=t/'input.patch';patch.write_bytes(data)
        g('apply','--index',str(patch));assert g('write-tree')==m[stage]['tree']
        for profile,flags in profiles.items():
            if profile != os.environ['SCAN_PROFILE']:continue
            b=t/profile;units=['x86_mapping_counts','x86_scan_batch','x86_reg_access','x86_encoding_accuracy']
            if profile in ('full','no-att'):units+=['x86_evex_detail','x86_buffer_bounds']
            if stage=='oracle':
                cmd=['cmake','-G','Ninja','-S',harness,'-B',b,'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF',*flags]
                if windows:cmd+=['-DCMAKE_C_COMPILER=cl','-DCMAKE_CXX_COMPILER=cl','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=ON','-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded']
                run('configure-'+profile,cmd)
            tag=stage+'-'+profile;run('build-'+tag,['cmake','--build',b,'--parallel','4','--target','mapper',*units]);run('units-'+tag,['ctest','--test-dir',b,'-C','Release','--output-on-failure','--no-tests=error','-R','^unit_('+'|'.join(units)+')$'])
            exe,=[p for p in b.rglob('mapper.exe' if windows else 'mapper')if p.is_file()]
            h=hashlib.sha256();n=0
            with (out/('records-'+tag+'.log')).open('w')as log,sp.Popen([exe],stdout=sp.PIPE,stderr=log)as proc:
                while data:=proc.stdout.read(4*1024*1024):n+=len(data);h.update(data)
                assert proc.wait()==0
            msg=(out/('records-'+tag+'.log')).read_text().strip();count=int(msg.split()[0]);assert count>0 and int(msg.split()[4])*count==n
            rec=dict(sha256=h.hexdigest(),bytes=n,count=count,record=msg,tests=units)
            if stage=='oracle':records[profile]=rec
            else:assert records[profile]==rec
            answers[tag]=rec;save('progress',answers)
    save('checked',dict(complete=True,source=m,results=answers,host=platform.platform(),machine=platform.machine(),compiler=os.environ.get('VSCMD_ARG_TGT_ARCH','clang')))
finally:
    n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=n))
