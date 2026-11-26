from pathlib import Path
import hashlib,json,math,os,platform,random,shutil,subprocess as sp,tempfile
from fixtures import fixtures,sha
r=Path(__file__).resolve().parent;root=r.parent;src=root/'source';e=root/'evidence';e.mkdir(exist_ok=True)
rd=lambda f:json.loads(f.read_text());m=rd(r/'experiment.json');q=rd(r/'source.json')
profile=os.environ['SCAN_PROFILE'];win=os.name=='nt';host=platform.system()
gcc=profile=='gcc';clang=profile in ('clang','clang14')
if gcc:os.environ.update(CC='gcc',CXX='g++')
if clang:os.environ.update(CC='clang',CXX='clang++')
eligible=(host=='Linux' and profile=='clang') or host=='Darwin'
os.environ['ZERO_AR_DATE']='1'
def save(name,value):(e/(name+'.json')).write_text(json.dumps(value,indent=2)+'\n')
def get(*a):return sp.check_output(a,text=True).strip()
def run(*a):sp.run(a,check=True)
def git(*a):return get('git','-C',src,*a)
if win:
    from preprocess_win import verify
    verify(r)
    raise SystemExit(0)
w=Path(tempfile.mkdtemp()).resolve();build=w/'build';project=w/'project';project.mkdir()
try:
    assert git('rev-parse','HEAD')==q['base']['commit']
    for f in ('probe.cpp','CMakeLists.txt'):shutil.copyfile(r/f,project/f)
    flags=['-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_SOURCE='+str(src),'-DCAPSTONE_BUILD_MACOS_THIN=ON',
           '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_CSTEST=OFF',
           '-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON']
    if profile=='diet':flags.append('-DCAPSTONE_BUILD_DIET=ON')
    if profile=='noatt':flags.append('-DCAPSTONE_X86_ATT_DISABLE=ON')
    if profile=='reduced':flags.append('-DCAPSTONE_X86_REDUCE=ON')
    if win:flags+=['-DCMAKE_'+k+'=/Brepro' for k in ('C_FLAGS','CXX_FLAGS','EXE_LINKER_FLAGS','SHARED_LINKER_FLAGS','STATIC_LINKER_FLAGS')]
    suffix='.exe'if win else '';images={};objects={};selected={};checks={};expected='direct' if eligible else 'base'
    stages=['base','direct','candidate']if eligible else ['base','candidate']
    for stage in stages:
        if stage!='base':
            git('restore','--source=HEAD','--staged','--worktree','--','.')
            content=sp.check_output(['git','-C',root,'cat-file','blob','HEAD:portable-next/'+stage+'.patch'])
            assert sha(content)==q[stage]['sha256']
            patch=w/'candidate.patch';patch.write_bytes(content);git('apply','--index',patch)
        assert git('write-tree')==q[stage]['tree']
        run('cmake','-G','Ninja','-S',project,'-B',build,*flags)
        run('cmake','--build',build,'--parallel','4','--target','probe_static','probe_shared')
        dest=w/stage;dest.mkdir()
        for kind in ('static','shared'):
            name='probe_'+kind+suffix;exe,=build.rglob(name);shutil.copy2(exe,dest/name)
        libs=[f for f in (build/'capstone').rglob('*')if f.is_file() and (f.name.startswith('libcapstone.so') or f.suffix.lower() in ('.dylib','.dll','.lib','.a'))]
        assert libs
        for f in libs:shutil.copy2(f,dest/f.name)
        images[stage]={f.name:sha(f.read_bytes())for f in dest.iterdir()}
        objects[stage]={str(f.relative_to(build)):sha(f.read_bytes())for f in (build/'capstone').rglob('*') if f.is_file() and f.suffix in ('.obj','.o')}
        assert len(objects[stage])>20
        selected[stage]={}
        for kind in ('static','shared'):
            exe=dest/('probe_'+kind+suffix);f=Path(get(exe,'--library')).resolve();assert f.parent==dest and (f==exe)==(kind=='static')
            selected[stage][kind]=f.name
        save('identities',dict(images=images,objects=objects,loaded=selected,expected=expected))
    assert objects['candidate']==objects[expected],[(k,v,objects[expected].get(k)) for k,v in objects['candidate'].items()if v!=objects[expected].get(k)]
    if win:
        # MSVC import archive metadata is independent of the executable images.
        loaded=set(selected['candidate'].values())|{'probe_shared.exe'}
        assert all(images['candidate'][k]==images[expected][k]for k in loaded),(images,loaded)
    else:assert images['candidate']==images[expected],images
    if eligible:assert images['candidate']!=images['base']
    samples=list(fixtures(r,w,m));assert len(samples)==6
    for name,bits,file,spans in samples:
        for syntax,mode in [('intel',0),('intel',1),('intel',2),('att',1),('att',2)]:
            if (profile=='diet' and mode) or (profile=='noatt' and syntax=='att'):continue
            for kind in ('static','shared'):
                def read(stage,reps):
                    exe=w/stage/('probe_'+kind+suffix)
                    return list(map(int,get(exe,'public-att' if syntax=='att' else 'capstone',str(mode),str(reps),file,spans,str(bits)).split()))
                key='/'.join((kind,syntax,name,str(mode)));row=read('base',1)
                assert all(read(stage,1)[2:]==row[2:] for stage in stages[1:])
                checks[key]=row[2:]
    assert checks;save('checks',checks)
    save('complete',dict(complete=True,source=q,os=platform.platform(),host=host,profile=profile,eligible=eligible,expected=expected,checks=len(checks),
                         objects=len(objects[expected]),images=images,loaded=selected,compiler=get('clang','--version').splitlines()[0] if clang else None))
finally:
    size=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=size))
