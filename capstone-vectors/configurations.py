"""Check compact scan and output on the exact PowerPC-rebased tree and compare all public records."""
from pathlib import Path
import hashlib,json,os,platform,shutil,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;s=r.parent/'source';out=r.parent/'evidence';out.mkdir()
cc=os.environ['CC'];cfg=os.environ['CS_PROFILE']
assert platform.machine()=='x86_64'
options={'diet':['-DCAPSTONE_BUILD_DIET=ON'],'reduced':['-DCAPSTONE_X86_REDUCE=ON'],
         'intel':['-DCAPSTONE_X86_ATT_DISABLE=ON'],'custom':['-DCAPSTONE_USE_DEFAULT_ALLOC=OFF'],
         'adapter':['-DCAPSTONE_X86_SCAN_ADAPTER=ON'],'standard':[]}
def run(tag,args,cwd=None):
    log=out/(tag+'.log')
    with log.open('wb') as stream:rc=sp.run(list(map(str,args)),cwd=cwd,stdout=stream,stderr=sp.STDOUT).returncode
    if rc:raise RuntimeError(f'{tag}: {rc}\n'+log.read_text(errors='replace')[-2400:])
def save(name,x):(out/(name+'.json')).write_text(json.dumps(x,indent=2)+'\n')
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def git(*args):return sp.check_output(['git','-C',s,*args],text=True).strip()
inputs=json.loads((r/'experiment.json').read_text());base=inputs['baseline_commit'];v=inputs['variants']['vector']
assert git('rev-parse','HEAD')==base and sha(r/'vector.patch')==v['sha256']
with tempfile.TemporaryDirectory() as temp:
    t=Path(temp);b=t/'build';objects={};trees={};results={}
    try:
        flags='-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'
        run('configure',['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCMAKE_C_FLAGS='+flags,'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF',*options[cfg]])
        for label in ('base','candidate'):
            if label=='candidate':run('apply',['git','apply','--index',r/'vector.patch'],s)
            trees[label]=git('write-tree');assert trees[label]==(v['tree'] if label=='candidate' else inputs['baseline_tree'])
            units=['utils','mcinst','instruction_bytes','text_option','detail_option'] if cfg!='custom' else []
            if cfg in ('intel','adapter','standard'):units+=['x86_encoding_accuracy','x86_simple_output','x86_buffer_bounds','x86_scan_batch']
            if cfg=='adapter':units.append('x86_scan_adapter')
            run('build-'+label,['cmake','--build',b,'--target','capstone_shared','capstone_static',*units,'--parallel','4'])
            if units:run('units-'+label,['ctest','--test-dir',b,'--output-on-failure','--no-tests=error','-R','^unit_('+'|'.join(units)+')$'])
            shutil.copyfile(b/'libcapstone.so',t/(label+'.so'))
            obj=b/'CMakeFiles/capstone.dir'
            members=sp.check_output(['ar','t',b/'libcapstone.a'],text=True).splitlines()
            files={str(f.relative_to(obj)):f for f in obj.rglob('*.o') if f.name in members}
            assert len(files)==len(members)
            objects[label]={name:sha(f) for name,f in files.items()}
        changed=sorted(k for k,vv in objects['base'].items() if objects['candidate'][k]!=vv)
        added=set(objects['candidate'])-set(objects['base'])
        assert added=={'arch/X86/X86Vex32Output.c.o','arch/X86/X86VexScan.c.o'}
        active=cc=='clang' and cfg not in ('custom','diet','reduced')
        if active:
            required={'arch/X86/X86OutputIterator.c.o','arch/X86/X86DisassemblerDecoder.c.o'}
            assert required<=set(changed)<=required|{'arch/X86/X86VectorOutput.c.o'},changed
        else:
            assert not changed,(cfg,changed)
            for name in added:assert not sp.check_output(['nm','-g','--defined-only',files[name]]).strip()
        name='vex-scan-diff'
        src=(r/(name+'.cpp')).read_text()
        if cfg=='custom':
            mark='throw std::runtime_error("missing API");';assert src.count(mark)==1
            src=src.replace(mark,mark+'''
  cs_opt_mem allocation{std::malloc,std::calloc,std::realloc,std::free,std::vsnprintf};
  if(option(0,CS_OPT_MEM,reinterpret_cast<size_t>(&allocation))) throw std::runtime_error("allocator");''')
        (t/'probe.cpp').write_text(src)
        run('link-'+name,['clang++','-std=c++17','-O2','-I',s/'include',t/'probe.cpp','-ldl','-o',t/name])
        run(name,[t/name,t/'base.so',t/'candidate.so'])
        results[name]=(out/(name+'.log')).read_text().strip();assert '72286208 inputs' in results[name]
        if cfg=='adapter':
            run('link-adapter',[cc,'-O2','-I',s/'include','-I',s/'arch/X86',r/'adapter-precedence.c',b/'libcapstone.a','-lm','-o',t/'adapter'])
            run('adapter',[t/'adapter']);assert '168 cases passed' in (out/'adapter.log').read_text()
        save('complete',dict(trees=trees,objects=objects,added=sorted(added),active=active,changed=changed,profile=cfg,
                             cc=sp.check_output([cc,'--version'],text=True),options=options[cfg],results=results,units=units))
    finally:
        amount=sum(f.stat().st_size for f in t.rglob('*') if f.is_file());shutil.rmtree(t);save('cleanup',dict(bytes=amount,removed=not t.exists()))
