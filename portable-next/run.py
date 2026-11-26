from pathlib import Path
import hashlib,json,math,os,platform,random,shutil,subprocess as sp,tempfile
from fixtures import fixtures,sha
r=Path(__file__).resolve().parent;p=r.parent;src=p/'source';e=p/'evidence';e.mkdir(exist_ok=True)
rd=lambda f:json.loads(f.read_text());m=rd(r/'experiment.json');q=rd(r/'source.json');win=os.name=='nt'
def save(n,v):(e/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def get(*args,**kw):return sp.check_output(args,text=True,**kw).strip()
def run(*args,**kw):sp.run(args,check=True,**kw)
if os.environ.get('SCAN_PROFILE')=='gcc':os.environ.update(CC='gcc',CXX='g++')
if os.environ.get('SCAN_PROFILE')=='clang':os.environ.update(CC='clang',CXX='clang++')
w=Path(tempfile.mkdtemp())
try:
    git=lambda *args:get('git','-C',src,*args)
    assert git('rev-parse','HEAD')==q['base']['commit']
    project=w/'project';project.mkdir();build=w/'build'
    for name in ('CMakeLists.txt','probe.cpp'):shutil.copyfile(r/name,project/name)
    suffix='.exe' if win else '';ident={};exes={}
    tables={};layouts={}
    for stage in ('base','candidate','outlined'):
        if stage!='base':
            run('git','-C',src,'restore','--source','HEAD','--staged','--worktree','.')
            patch=sp.check_output(['git','-C',p,'cat-file','blob','HEAD:portable-next/'+stage+'.patch'])
            assert sha(patch)==q[stage]['sha256']
            patchfile=w/'update.patch';patchfile.write_bytes(patch);run('git','-C',src,'apply','--index',patchfile)
        assert git('write-tree')==q[stage]['tree']
        run('cmake','-G','Ninja','-S',project,'-B',build,'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_SOURCE='+str(src),
            '-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_CSTEST=OFF',
            '-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON')
        run('cmake','--build',build,'--parallel','4','--target','probe_static','probe_shared')
        dest=w/stage;dest.mkdir()
        for kind in ('static','shared'):
            name='probe_'+kind+suffix;exe,=build.rglob(name)
            target=dest/name;shutil.copy2(exe,target);exes[stage,kind]=target
        libs=[f for f in (build/'capstone').rglob('*') if f.is_file() and (f.name.endswith('.dylib') or f.name.startswith('libcapstone.so') or f.suffix.lower()=='.dll')]
        assert libs
        for f in libs:shutil.copy2(f,dest/f.name)
        ident[stage]={f.name:sha(f.read_bytes()) for f in dest.iterdir()}
        save('images',ident)
        exe=exes[stage,'static'];listing=get('nm','-S','--defined-only','--format=posix',exe).splitlines()
        tables[stage]=sorted(int(c[3],16)for l in listing if len(c:=l.split())==4 and c[0]=='x86_simple_outputs')
        widths={'base':88,'candidate':72,'outlined':64}
        assert 335*widths[stage] in tables[stage],tables
        chosen=[c[0] for l in listing if len(c:=l.split())==4 and any(a in c[0]for a in ('X86_disasmIterText','X86_disasmIter32','X86_disasmIter64','X86_trySimpleOutput','X86_writeSimpleDetail'))]
        layouts[stage]=[l for l in listing if l.split() and l.split()[0] in chosen]
        (e/(stage+'-readers.s')).write_text(''.join(get('objdump','-d','--disassemble='+sym,exe)+'\\n' for sym in sorted(set(chosen))))
    save('images',dict(digests=ident,tables=tables,readers=layouts,compiler=get(os.environ['CC'],'--version').splitlines()[0]))
    samples=list(fixtures(r,w,m));rows={}
    targets={'putty-32-0.85':2,'putty-64-0.85':2,'libmvec-amd64':1}
    from costs import profile
    invoke=['setarch',os.uname().machine,'-R']
    for name,bits,input_file,spans in samples:
        if name not in targets:continue
        mode=targets[name];record={}
        for stage in ('base','candidate','outlined'):
            exe=exes[stage,'static']
            record[stage]={str(i):profile(w,invoke,[exe,'capstone',str(mode),str(i),input_file,spans,str(bits)]) for i in (1,2)}
        for i in ('1','2'):assert record['base'][i]['records']==record['candidate'][i]['records']==record['outlined'][i]['records']
        rows[name+'/'+str(mode)]=record;save('counts',rows)
    assert len(rows)==3
    save('complete',dict(complete=True,source=q,machine=platform.machine(),profile=os.environ['SCAN_PROFILE'],compiler=get(os.environ['CC'],'--version').splitlines()[0]))
finally:
    size=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink())
    shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=size))
