from pathlib import Path
import hashlib, json, os, platform, shutil, statistics, struct, subprocess as sp, sys, tempfile, urllib.request
here=Path(__file__).resolve().parent;out=Path.cwd()/'call-evidence';out.mkdir(exist_ok=True);win=os.name=='nt'
def write(name,value): (out/(name+'.json')).write_text(json.dumps(value,indent=2)+'\n')
def run(cmd,cwd=None):sp.run(list(map(str,cmd)),cwd=cwd,check=True)
def digest(b):return hashlib.sha256(b).hexdigest()
def pe_section(blob,bits):
    pe=struct.unpack_from('<I',blob,60)[0];machine,count=struct.unpack_from('<HH',blob,pe+4);assert machine=={32:0x14c,64:0x8664}[bits];ofs=pe+24+struct.unpack_from('<H',blob,pe+20)[0]
    for i in range(count):
        at=ofs+i*40
        if blob[at:at+8].rstrip(b'\x00')==b'.text':
            virtual,_,raw,start=struct.unpack_from('<IIII',blob,at+8);return blob[start:start+min(virtual,raw)]
    raise RuntimeError('missing .text')
def main(tmp):
    if hasattr(os,'sched_setaffinity'):os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    bodies=[];cases=json.loads((here/'corpus.json').read_text())
    for c in cases:
        with urllib.request.urlopen(c['source'],timeout=60) as f:blob=f.read()
        assert digest(blob)==c['executable_sha256'];code=pe_section(blob,c['bits']);assert digest(code)==c['sha256'];bodies.append((c['name'],c['bits'],code))
    if win:
        for bits,folder in [(32,'SysWOW64'),(64,'System32')]:
            for name in ('cmd','reg'):
                bodies.append((name+'-'+str(bits),bits,pe_section((Path(os.environ['SystemRoot'])/folder/(name+'.exe')).read_bytes(),bits)))
    if sys.platform.startswith('linux'):
        for name in ('ls','sort'):
            data=tmp/(name+'.text');run(['objcopy','--dump-section','.text='+str(data),'/usr/bin/'+name,tmp/(name+'-copy')]);bodies.append((name,64,data.read_bytes()))
    write('corpus',[dict(name=n,bits=b,bytes=len(data),sha256=digest(data)) for n,b,data in bodies]);write('host',dict(system=platform.platform(),machine=platform.machine(),processor=platform.processor()))
    base='f2f50b8fab856b374daf0e76dc3054f25de65ac9';patch=here/'release.patch';assert digest(patch.read_bytes())==(here/'release.sha256').read_text().strip();write('inputs',dict(base=base,patch=digest(patch.read_bytes()),revision=(here/'capstone-revision.txt').read_text().strip()))
    programs={}
    for kind in ('base','candidate'):
        root=tmp/kind;root.mkdir();src=root/'capstone';src.mkdir();run(['git','init','-q'],src);run(['git','config','core.autocrlf','false'],src);run(['git','fetch','-q','--depth=1','https://github.com/NeverSight/capstone.git',base],src);run(['git','checkout','-q','--detach','FETCH_HEAD'],src)
        if kind=='candidate':run(['git','apply','--check',patch],src);run(['git','apply',patch],src)
        shutil.copyfile(here/'calls.cpp',root/'calls.cpp');(root/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.20)\nproject(CallProbe LANGUAGES C CXX)\nenable_testing()\nadd_subdirectory(capstone)\nadd_executable(callbench calls.cpp)\ntarget_compile_features(callbench PRIVATE cxx_std_17)\ntarget_include_directories(callbench PRIVATE capstone)\ntarget_link_libraries(callbench PRIVATE capstone_static)\n');build=root/'build'
        gen=['-G','Visual Studio 17 2022','-A','x64'] if win else ['-G','Ninja']
        flags=['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in ('ARM','AARCH64','MIPS','X86')];run(['cmake','-S',root,'-B',build,*gen,'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF',*flags]);units=['x86_scan_batch','x86_call_target','x86_buffer_bounds','x86_encoding_accuracy'];run(['cmake','--build',build,'--config','Release','--parallel','3','--target','callbench',*units]);run(['ctest','--test-dir',build,'--no-tests=error','--output-on-failure','-C','Release','-R','^unit_('+'|'.join(units)+')$']);programs[kind]=build/('Release/callbench.exe' if win else 'callbench')
    modes={'old-full':('base',0),'old-compact':('base',1),'new-compact':('candidate',1)};records=[]
    for n,bits,code in bodies:
        data=tmp/(n+'.input');data.write_bytes(code)
        for linear in (0,1):
            reps=(40 if not linear else 9)*max(1,round(0.9e6/len(code)));pairs=[];oracle=None
            for cycle in range(9):
                labels=list(modes);offset=cycle%3;labels=labels[offset:]+labels[:offset]
                if cycle%2:labels.reverse()
                times={k:[] for k in labels}
                for k in labels+labels[::-1]:
                    kind,query=modes[k];raw=sp.check_output(list(map(str,[programs[kind],data,bits,linear,query,reps])),text=True).split();ticks,*rest=map(int,raw);assert len(rest)==7 and rest[-1]==reps and ticks>0
                    if oracle is None:oracle=rest
                    assert rest==oracle;times[k].append(ticks)
                avg={k:statistics.mean(v)for k,v in times.items()};pairs.append(dict(raw=times,adoption=avg['old-full']/avg['new-compact'],reader=avg['old-compact']/avg['new-compact']))
            records.append(dict(case=n,linear=bool(linear),oracle=oracle,pairs=pairs,medians={k:statistics.median(x[k] for x in pairs)for k in ('reader','adoption')}));write('measurements',records);print(n,'walk' if linear else 'queries',records[-1]['medians'],flush=True)
    write('complete',dict(complete=True,cells=len(records)))
with tempfile.TemporaryDirectory(dir=os.environ.get('RUNNER_TEMP')) as tmp:
    root=Path(tmp)
    try:main(root)
    finally: size=sum(f.stat().st_size for f in root.rglob('*') if f.is_file())
write('cleanup',dict(removed=not root.exists(),bytes=size))
