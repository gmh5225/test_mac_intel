"""Time the AMD64 writer on each compiler profile where lifting it into a shared header changed machine code."""
import hashlib,json,math,os,platform,random,shutil,subprocess as sp,tempfile
from pathlib import Path
from fixtures import fixtures,sha
r=Path(__file__).resolve().parent;root=r.parent;source=root/'source';e=root/'evidence';e.mkdir(exist_ok=True)
def read(f):return json.loads(f.read_bytes())
def save(k,v):(e/(k+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def run(*args):sp.run(args,check=True)
def get(*args):return sp.check_output(args,text=True).strip()
kind=os.environ['PROBE_CONFIG'];q=read(r/'source.json');meta=read(r/'experiment.json')
if platform.system()=='Linux':os.environ.update(CC='clang',CXX='clang++')
w=Path(tempfile.mkdtemp()).resolve();project=w/'project';build=w/'build';sources={};ident={};records={};timings={}
try:
    assert kind in ('standalone','product','mixed') and platform.machine()=='x86_64'
    assert get('git','-C',source,'rev-parse','HEAD')==q['base']['commit']
    project.mkdir();normal=(r/'CMakeLists.txt').read_text();a=normal.index('add_subdirectory');b=normal.index('foreach(linkage static shared)')
    fragment=normal[a:b]
    if kind=='product':
        fragment=(r/'product.cmake').read_text().replace('add_subdirectory(third_party/capstone)',fragment.strip())
        (project/'cmake').mkdir();shutil.copyfile(r/'compiler-options.inc',project/'cmake/NeverDCapstoneCompilerOptions.inc')
    targets=normal[b:].replace('    add_executable','    if(NOT TARGET capstone_\u0024{linkage})\n        continue()\n    endif()\n    add_executable',1)
    (project/'CMakeLists.txt').write_text(normal[:a]+fragment+targets+'\nadd_executable(probe_native probe.cpp)\ntarget_compile_features(probe_native PRIVATE cxx_std_17)\ntarget_compile_definitions(probe_native PRIVATE REQUEST_NATIVE)\ntarget_link_libraries(probe_native PRIVATE capstone_static \u0024{CMAKE_DL_LIBS})\n')
    shutil.copyfile(r/'probe.cpp',project/'probe.cpp')
    targets=['probe_static','probe_native']+([] if kind=='product' else ['probe_shared'])
    flags=['-G','Ninja','-S',project,'-B',build,'-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCAPSTONE_SOURCE='+str(source),'-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON']
    if kind=='mixed':flags+=['-DCAPSTONE_'+isa+'_SUPPORT=ON'for isa in ('ARM','AARCH64','MIPS','PPC','RISCV')]
    for stage in ('base','candidate'):
        if stage=='candidate':
            patch=r/'candidate.patch';assert sha(patch.read_bytes())==q[stage]['sha256'];run('git','-C',source,'apply','--index',patch)
        assert get('git','-C',source,'write-tree')==q[stage]['tree']
        run('cmake',*flags);run('cmake','--build',build,'--parallel','4','--target',*targets)
        assert all('X86_VEX_CLEAR_OUTPUT32' not in v['command'] and 'X86_ACCUMULATOR_OUTPUT32' not in v['command'] for v in read(build/'compile_commands.json'))
        sources[stage]={str(f.relative_to(build)):sha(f.read_bytes())for f in (build/'capstone').rglob('*.c.o')}
        dest=w/stage;dest.mkdir()
        for name in targets:shutil.copy2(build/name,dest/name)
        for f in (build/'capstone').rglob('libcapstone*'):
            if f.is_file() and f.suffix!='.a':shutil.copy2(f,dest/f.name)
        ident[stage]={f.name:sha(f.read_bytes())for f in dest.iterdir()}
    changes=[Path(k).name for k,h in sources['base'].items()if h!=sources['candidate'][k]];assert changes==['X86Sse64Output.c.o'],changes
    save('code',dict(source=q,objects=sources,changed=changes));assert ident['base'].keys()==ident['candidate'].keys()
    for name,old in [('copy','base'),('candidate_copy','candidate')]:
        shutil.copytree(w/old,w/name);ident[name]={f.name:sha(f.read_bytes())for f in (w/name).iterdir()};assert ident[name]==ident[old]
    for name in targets:
        for stage in ident:
            actual=Path(get(w/stage/name,'--library')).resolve();assert actual.parent==w/stage and (actual==w/stage/name)==(name!='probe_shared'),(name,actual,w/stage)
    save('images',ident)
    if hasattr(os,'sched_setaffinity'):os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    for prog,bits,code,ext in fixtures(r,w,meta):
        for name in targets:
            private=name=='probe_native';modes=[('intel',1),('intel',2),('att',1),('att',2)]
            if not private:modes.insert(0,('intel',0))
            for syntax,mode in modes:
                engine=('private' if private else 'capstone') if syntax=='intel' else ('private-att' if private else 'public-att')
                key='/'.join((name,syntax,prog,str(mode)))
                def bench(stage,reps):return list(map(int,get(w/stage/name,engine,str(mode),str(reps),code,ext,str(bits)).split()))
                once=bench('base',1);assert len(once)==6 and once[2]>0
                assert all(bench(t,1)[2:]==once[2:]for t in ident);records[key]=once[2:]
                loaded=name if name!='probe_shared' else next(k for k in ident['base']if(k.endswith('.dylib') or '.so' in k))
                if ident['base'][loaded]==ident['candidate'][loaded]:
                    timings[key]=dict(identical=True);continue
                reps=max(1,math.ceil(24e6/once[1]));exp=bench('base',reps)[2:];labels=list(ident);blocks=[];rng=random.Random(key)
                for _ in range(17):
                    rng.shuffle(labels);v={t:[]for t in labels}
                    for t in labels+labels[::-1]:
                        sample=bench(t,reps);assert sample[2:]==exp;v[t].append(sample[:2])
                    blocks.append({t:[sum(x[c]for x in v[t])for c in (0,1)]for t in v})
                timings[key]=dict(reps=reps,blocks=blocks);save('timings',timings)
    assert len(records)==6*(9 if kind=='product' else 14)
    save('timings',timings);save('complete',dict(complete=True,records=records,source=q,config=kind,profile=os.environ['SCAN_PROFILE'],machine=platform.machine(),platform=platform.system(),compiler=get('clang','--version').splitlines()[0]))
finally:
    used=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(bytes=used,removed=not w.exists()))
