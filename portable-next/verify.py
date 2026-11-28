from pathlib import Path
import hashlib,io,json,os,platform,shutil,subprocess as sp,tarfile,tempfile
import corpus
d=Path(__file__).resolve().parent;s=d.parent/'source';out=d.parent/'evidence';out.mkdir(exist_ok=True);profile=os.environ['SCAN_PROFILE'];q=json.loads((d/'tree.json').read_text());source=json.loads((d/'sample.json').read_text());win=os.name=='nt';t=Path(tempfile.mkdtemp())
sha=lambda raw:hashlib.sha256(raw).hexdigest()
def save(n,v):(out/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def cmd(label,argv,env=None):
    with (out/(label+'.log')).open('w')as f:z=sp.run(argv,stdout=f,stderr=sp.STDOUT,env=env)
    if z.returncode:print((out/(label+'.log')).read_text(errors='replace')[-2000:]);z.check_returncode()
def g(*args):return sp.check_output(['git','-C',s,*args],text=True).strip()
def extract(pkg):
    assert pkg[:8]==b'!<arch>\n';pos=8
    while pos+60<=len(pkg):
        head=pkg[pos:pos+60];size=int(head[48:58]);assert head[58:60]==b'\x60\n'
        if head[:16].strip().rstrip(b'/').startswith(b'data.tar'):
            with tarfile.open(fileobj=io.BytesIO(pkg[pos+60:pos+60+size]),mode='r:*')as ar:
                return {name:ar.extractfile(next(z for z in ar.getmembers() if z.isfile() and z.name.lstrip('./') in ('bin/'+name,'usr/bin/'+name))).read() for name in source['programs']}
        pos+=60+size+(size%2)
    raise ValueError('missing package member')
try:
    assert g('rev-parse','HEAD')==q['parent']
    pkg=t/'sample.deb';cmd('download',['curl','--retry','3','--retry-all-errors','-fsSL',source['url'],'-o',pkg]);data=pkg.read_bytes();assert sha(data)==source['package_sha256']
    texts={}
    for name,elf in extract(data).items():
        fields=source['programs'][name];raw=corpus.elf_text(elf);assert sha(elf)==fields['elf_sha256'] and sha(raw)==fields['section_sha256']
        text=t/(name+'.text');text.write_bytes(raw);texts[name]=text
    project=t/'project';project.mkdir();b=t/'build'
    lines=['cmake_minimum_required(VERSION 3.22)','project(SparcRecords LANGUAGES C CXX)','enable_testing()',f'add_subdirectory("{s.as_posix()}" capstone)']
    for suffix in ('static','shared'):
        lines.extend([f'add_executable(records_{suffix} "{(d/"raw.cpp").as_posix()}")',f'target_compile_features(records_{suffix} PRIVATE cxx_std_17)',f'target_link_libraries(records_{suffix} PRIVATE capstone_{suffix})'])
    (project/'CMakeLists.txt').write_text('\n'.join(lines)+'\n')
    cfg=['cmake','-G','Ninja','-S',project,'-B',b,'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_SPARC_SUPPORT=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON']
    if win:cfg+=['-DCMAKE_C_COMPILER=cl','-DCMAKE_CXX_COMPILER=cl','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=ON','-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded']
    if platform.system()=='Linux':cfg+=['-DCMAKE_C_COMPILER=gcc','-DCMAKE_CXX_COMPILER=g++','-DCAPSTONE_PPC_SUPPORT=ON']
    if profile=='diet':cfg.append('-DCAPSTONE_BUILD_DIET=ON')
    variants={}
    for stage in ('base','candidate'):
        if stage=='candidate':
            patch=t/'source.patch';patch.write_bytes(sp.check_output(['git','-C',d.parent,'cat-file','blob','HEAD:portable-next/candidate.patch']));assert sha(patch.read_bytes())==q['sha256'];g('apply','--index',str(patch));assert g('write-tree')==q['tree']
        units=[]if profile=='diet'else ['register_descriptors','mcinst']
        if stage=='candidate':units.append('sparc_mapping_index')
        cmd('configure-'+stage,cfg);cmd('build-'+stage,['cmake','--build',b,'--parallel','4','--target','records_static','records_shared',*units])
        if units:cmd('units-'+stage,['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(units)+')$'])
        env=dict(os.environ)
        if win:
            dll,=[f for f in b.rglob('*.dll')if 'capstone' in f.name.lower()];env['PATH']=str(dll.parent)+os.pathsep+env['PATH']
        outputs={}
        for suffix in ('static','shared'):
            exe,=[f for f in b.rglob('records_'+suffix+('.exe'if win else'')) if f.is_file()]
            rows={}
            for name,path in texts.items():
                for opt in range(5):
                    v=list(map(int,sp.check_output([exe,'106',path,str(opt)],text=True,env=env).split()));assert v[0]>0
                    rows[name+'/'+str(opt)]=v
            outputs[suffix]=rows
        assert outputs['static']==outputs['shared']
        variants[stage]=outputs
    assert variants['base']==variants['candidate'];save('complete',dict(complete=True,source=q,profile=profile,platform=platform.platform(),records=variants['candidate']['static'],programs=source['programs'],linkages=2))
finally:
    size=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=size))
