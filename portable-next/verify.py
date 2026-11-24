from pathlib import Path
import hashlib,json,os,shutil,subprocess as sp,sys,tempfile
r=Path(__file__).resolve().parent;s=r.parent/'source';e=r.parent/'evidence';e.mkdir(exist_ok=True);t=Path(tempfile.mkdtemp())
rd=lambda p:json.loads(p.read_text());profile=os.environ['SCAN_PROFILE']
def put(n,v):(e/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def git(*args):return sp.check_output(['git','-C',s,*args],text=True).strip()
def run(n,*args):
    with (e/(n+'.log')).open('w')as o:z=sp.run(args,cwd=t,stdout=o,stderr=sp.STDOUT)
    text=(e/(n+'.log')).read_text(errors='replace')
    if z.returncode:print(text[-5000:]);z.check_returncode()
    return text.strip()
def stage(name,q):
    patch=t/(name+'.patch')
    patch.write_bytes(sp.check_output(['git','-C',r.parent,'cat-file','blob','HEAD:portable-next/'+name+'.patch']))
    assert hashlib.sha256(patch.read_bytes()).hexdigest()==q['sha256'];git('apply','--index',patch);assert git('write-tree')==q['tree']
try:
    q=rd(r/'tree.json');assert git('rev-parse','HEAD')==q['parent']
    results={};units=['api','mcinst','sstream','instruction_bytes'];b=t/'build';sample=t/'op.bin';sample.write_bytes(bytes((0,0)))
    for k in ('base','candidate'):
        if k=='candidate':
            stage(k,q);run('generated',sys.executable,s/'suite/synctools/xcore_literal_operands.py','--check')
        flags=['-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_XCORE_SUPPORT=ON','-DCAPSTONE_BUILD_DIET='+('ON'if profile=='diet' else 'OFF')]
        put('complete',dict(source=q,units=units,profile=profile,static=True,shared=True,official_fixture=fixture_target,rows=results))
finally:
    n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);put('cleanup',dict(removed=not t.exists(),bytes=n))
