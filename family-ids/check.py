from pathlib import Path
import hashlib, json, os, platform, shutil, statistics, subprocess as sp, sys, tempfile
r=Path(__file__).resolve().parent;s=r.parent/'source';out=r.parent/'evidence';out.mkdir(exist_ok=True)
m=json.loads((r/'tree.json').read_text()); arch=os.environ['TARGET']; flavor=os.environ['FLAVOR']
win=os.name=='nt';diet=flavor=='diet';reduced=flavor=='reduce'
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def write(n,obj):(out/(n+'.json')).write_text(json.dumps(obj,indent=2)+'\n')
def run(args,label,cwd=None,env=None):
    args=list(map(str,args))
    with (out/(label+'.log')).open('w') as fd:
        x=sp.run(args,stdout=fd,stderr=sp.STDOUT,cwd=cwd,env=env)
    if x.returncode:print((out/(label+'.log')).read_text(errors='replace')[-3000:],flush=True);x.check_returncode()
def git(*a):return sp.check_output(['git','-C',s,*a],text=True).strip()
assert git('rev-parse','HEAD')==m['parent'] and sha(r/'candidate.patch')==m['sha256']
if win:
    git('config','core.autocrlf','false')
    git('checkout-index','--force','--all')
t=Path(tempfile.mkdtemp());b=t/'build';driver=t/'reader';driver.mkdir();reader_build=t/'reader-build'
try:
    shutil.copyfile(r/'fetch.py',t/'fetch.py')
    run([sys.executable,'-B',t/'fetch.py'],'puTTY')
    corpus=json.loads((t/'corpus.json').read_text());write('corpus',corpus)
    if win:
        configure=['-G','Visual Studio 17 2022','-A',arch]
        opts=['-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON']
        run(['cmake','-S',s,'-B',b,*configure,*opts,'-DCAPSTONE_X86_REDUCE='+('ON' if reduced else 'OFF'),'-DCAPSTONE_BUILD_DIET='+('ON' if diet else 'OFF')],'configure')
    else:
        configure=['-G','Ninja']
        make=['make','-j4','CAPSTONE_ARCHS=x86','CAPSTONE_SHARED=yes','CAPSTONE_STATIC=no','CAPSTONE_BUILD_CORE_ONLY=yes','CAPSTONE_DIET='+('yes' if diet else 'no'),'CAPSTONE_X86_REDUCE='+('yes' if reduced else 'no')]
    libs={}
    for label in ('base','candidate'):
        if label=='candidate':
            git('apply','--cached',str(r/'candidate.patch'))
            assert git('write-tree')==m['tree']
            for name in git('diff','--cached','--name-only',m['parent']).splitlines():
                data=sp.check_output(['git','-C',s,'cat-file','blob',':'+name])
                (s/name).write_bytes(data)
            write('candidate-source',dict(tree=git('write-tree'),changes=git('diff','--cached','--name-only',m['parent']).splitlines()))
        if win:
            run(['cmake','--build',b,'--config','Release','--parallel','4','--target','capstone_shared'],'build-'+label)
            lib,=b.rglob('capstone.dll')
        else:
            run(make,'make-'+label,cwd=s);lib,=[f for f in s.glob('libcapstone.so.*') if not f.is_symlink()]
        libs[label]=t/(label+lib.suffix);shutil.copyfile(lib,libs[label])
    run([sys.executable,'-B',s/'suite/synctools/x86_operand_access.py','--check'],'generator')
    units=['text_option','detail_option','x86_scan_batch']
    if not reduced:units.append('x86_kmask_width')
    if not diet and not reduced:units+=['x86_bound_access','x86_exchange_access','x86_reg_access']
    if win:
        run(['cmake','--build',b,'--config','Release','--parallel','4','--target',*units],'build-units')
        run(['ctest','--test-dir',b,'-C','Release','--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join([*units,'x86_operand_access_generator'])+')$'],'units',env=dict(os.environ,PATH=str(lib.parent)+os.pathsep+os.environ['PATH']))
    cm=['cmake_minimum_required(VERSION 3.16)','project(probe LANGUAGES CXX)','set(CMAKE_CXX_STANDARD 17)','include_directories("'+(s/'include').as_posix()+'")','add_executable(records records.cpp)','target_link_libraries(records PRIVATE '+('kernel32' if win else 'dl')+')']
    shutil.copyfile(r/'win-records.cpp' if win else r/'records.cpp',driver/'records.cpp')
    if flavor=='full':
        if win:implib=lib.with_suffix('.lib');assert implib.is_file()
        else:implib=lib
        shutil.copyfile(r/('win-time.cpp' if win else 'time.cpp'),driver/'time.cpp')
        cm+=['add_executable(timing time.cpp)','target_link_libraries(timing PRIVATE "'+implib.as_posix()+'")']
    (driver/'CMakeLists.txt').write_text('\n'.join(cm)+'\n')
    run(['cmake','-S',driver,'-B',reader_build,*configure,'-DCMAKE_BUILD_TYPE=Release'],'configure-reader')
    run(['cmake','--build',reader_build,'--config','Release','--parallel','4'],'build-reader')
    exe=next(reader_build.rglob('records.exe' if win else 'records'))
    observations=[]
    for sample in corpus:
        bits=sample['bits'];ip=sample['section_rva']+(0x400000 if bits==32 else 0x140000000)
        for syntax in range(1 if diet else 2):
            for row in sp.check_output(list(map(str,[exe,libs['base'],libs['candidate'],bits,t/sample['path'],ip,syntax,int(diet)])),text=True).splitlines():
                bit,flags,att,calls,valid,changes=map(int,row.split())
                assert bit==bits and att==syntax and calls>=valid>0 and changes==0
                observations.append(dict(bits=bits,option=flags,syntax=syntax,calls=calls,valid=valid))
    write('records',observations)
    clocks=[]
    if flavor=='full':
        timing=next(reader_build.rglob('timing.exe' if win else 'timing'))
        # Hold the loader pathname and executable constant for all three variants.
        selection=timing.parent/lib.name
        env=os.environ.copy();env['LD_LIBRARY_PATH']=str(timing.parent)
        if not win and hasattr(os,'sched_setaffinity'):os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
        def measure(label,sample,mode,reps):
            shutil.copyfile(libs[label if label!='copy' else 'base'],selection)
            bits=sample['bits'];ip=sample['section_rva']+(0x400000 if bits==32 else 0x140000000)
            cmd=list(map(str,[timing,bits,mode,t/sample['path'],ip,reps]))
            cpu,wall,signature=map(int,sp.check_output(cmd,text=True,env=env).split())
            assert wall>0 and signature>0
            return cpu,wall,signature
        for sample in corpus:
            for mode in range(4):
                _,cal,sig=measure('base',sample,mode,1);reps=max(1,min(256,round(90_000_000/cal)))
                row=dict(bits=sample['bits'],mode=mode,reps=reps,signature=sig,pairs=[])
                labels=['base','candidate','copy']
                for i in range(7):
                    order=labels[i%3:]+labels[:i%3];times={k:[] for k in labels}
                    for key in order+order[::-1]:
                        cpu,wall,signature=measure(key,sample,mode,reps);assert signature==sig
                        times[key].append([cpu,wall])
                    row['pairs'].append(times)
                clocks.append(row);write('timings',clocks)
    write('complete',dict(tree=m['tree'],parent=m['parent'],system=platform.platform(),arch=arch,flavor=flavor,build='MSVC CMake' if win else 'GNU Make',runtime={k:sha(v)for k,v in libs.items()},observations=sum(x['calls']for x in observations),units=units if win else [],times=len(clocks)))
finally:
    size=sum(f.stat().st_size for f in t.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(t);write('cleanup',dict(removed=not t.exists(),bytes=size))
