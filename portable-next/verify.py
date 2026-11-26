from pathlib import Path
import hashlib,json,os,shutil,subprocess as sp,tempfile
p=Path(__file__).resolve().parent;s=p.parent/'source';e=p.parent/'evidence';e.mkdir(exist_ok=True)
t=json.loads((p/'tree.json').read_text());profile=os.environ['SCAN_PROFILE']
w=Path(tempfile.mkdtemp());b=w/'build'
def run(*args):sp.run(args,cwd=w,check=True)
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
try:
    assert sp.check_output(['git','-C',s,'rev-parse','HEAD'],text=True).strip()==t['parent']
    orig=w/'WASMReference.c';orig.write_bytes((s/'arch/WASM/WASMInstPrinter.c').read_bytes())
    flags=['-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_WASM_SUPPORT=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']
    if profile=='diet':flags+=['-DCAPSTONE_BUILD_DIET=ON']
    run('cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release',*flags)
    rows={}
    for label in ('base','candidate'):
        if label=='candidate':
            assert sha(p/'candidate.patch')==t['sha256'];run('git','-C',s,'apply','--index',p/'candidate.patch')
            assert sp.check_output(['git','-C',s,'write-tree'],text=True).strip()==t['tree']
        run('cmake','--build',b,'--parallel','3','--target','wasm_brtable_size','capstone_static','capstone_shared')
        run('ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_wasm_brtable_size$')
        objs=list(b.rglob('WASMInstPrinter.c.obj'));assert objs
        row={'objects':{str(f.relative_to(b)):sha(f)for f in objs},'static':sha(b/'capstone_static.lib'),'shared':sha(b/'capstone.dll')}
        if profile=='full':
            rt='/MT' if 'CAPSTONE_BUILD_STATIC_MSVC_RUNTIME:BOOL=ON' in (b/'CMakeCache.txt').read_text() else '/MD'
            options=['/nologo','/O2',rt,'/std:c11','/DCAPSTONE_USE_SYS_DYN_MEM','/DCAPSTONE_HAS_WASM','/I'+str(s),'/I'+str(s/'include'),'/I'+str(s/'arch/WASM')]
            run('cl',*options,'/DWASM_printInst=wasm_reference','/c',orig,'/Fo:'+str(w/'reference.obj'))
            run('cl',*options,p/'verify-stream.c',w/'reference.obj',b/'capstone_static.lib','/Fo:'+str(w/'check.obj'),'/Fe:'+str(w/'test.exe'))
            row['streams']=int(sp.check_output([w/'test.exe'],cwd=w,text=True));assert row['streams']==792576
        rows[label]=row
    if profile=='diet':
        assert rows['base']['objects']==rows['candidate']['objects']
    (e/'complete.json').write_text(json.dumps(dict(complete=True,source=t,profile=profile,rows=rows),indent=2)+'\n')
finally:
    size=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(w);(e/'cleanup.json').write_text(json.dumps(dict(bytes=size,removed=not w.exists()))+'\n')
