from pathlib import Path
import hashlib,json,os,platform,shutil,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;ci=bool(os.environ.get('GITHUB_ACTIONS'));d=lambda n:next(r.parent.glob(f'round{n}-*'));rd=lambda f:json.loads(f.read_text())
t=rd((r if ci else d(3565))/'tree.json');profile=os.environ.get('SCAN_PROFILE','full')
e=r.parent/'evidence' if ci else r/('local-'+profile);e.mkdir(exist_ok=True)
def save(n,v):(e/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
w=Path(tempfile.mkdtemp(dir=None if ci else r))
def run(*args):sp.run(args,cwd=w,check=True)
def get(*args):return sp.check_output(args,cwd=w,text=True).strip()
try:
    if ci:s=r.parent/'source'
    else:
        s=w/'source';run('git','clone','-q','--shared','--no-checkout',d(579)/'source',s);run('git','-C',s,'checkout','-q','--detach',t['parent'])
    assert get('git','-C',s,'rev-parse','HEAD')==t['parent']
    raw=sp.check_output(['git','-C',r.parent,'cat-file','blob','HEAD:portable-next/candidate.patch']) if ci else (d(3565)/'candidate.patch').read_bytes()
    assert hashlib.sha256(raw).hexdigest()==t['sha256']
    patch=w/'raw.patch';patch.write_bytes(raw)
    win=os.name=='nt'
    if win:
        os.environ['CL']=os.environ.get('CL','')+' /Brepro';os.environ['LINK']=os.environ.get('LINK','')+' /Brepro'
    flags=['-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_WASM_SUPPORT=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']
    if profile=='diet':flags+=['-DCAPSTONE_BUILD_DIET=ON']
    build=w/'build';run('cmake','-G','Ninja','-S',s,'-B',build,*flags)
    rows={}
    for tag in ('base','candidate'):
        if tag=='candidate':
            run('git','-C',s,'apply','--index',patch);assert get('git','-C',s,'write-tree')==t['tree']
        run('cmake','--build',build,'--parallel','4','--target','wasm_brtable_size','capstone_shared','capstone_static')
        run('ctest','--test-dir',build,'--no-tests=error','--output-on-failure','-R','^unit_wasm_brtable_size$')
        path=r/'wide.c';exe=w/('check.exe' if win else 'check')
        if win:
            rt='/MT' if 'CAPSTONE_BUILD_STATIC_MSVC_RUNTIME:BOOL=ON' in (build/'CMakeCache.txt').read_text() else '/MD'
            run('cl','/nologo','/std:c11','/O2',rt,'/I'+str(s/'include'),path,build/'capstone_static.lib','/Fe:'+str(exe))
        else:run(os.environ.get('CC','cc'),'-std=c11','-O2','-I'+str(s/'include'),path,build/'libcapstone.a','-o',exe)
        row=list(map(int,get(exe).split()));assert row[0]==704
        if profile=='diet':assert row[1:]==[0,0],(tag,row)
        elif tag=='candidate':assert row[1]==0 and row[2]==rows['base'][2],(tag,row)
        else:assert row[2]>0 and (row[1]>0)==win,(tag,row)
        rows[tag]=row
    print(profile,rows,flush=True);save('complete',dict(complete=True,profile=profile,platform=platform.platform(),source=t,rows=rows))
finally:
    size=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(bytes=size,removed=not w.exists()))
