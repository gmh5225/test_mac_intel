from pathlib import Path
import hashlib,json,os,platform,shlex,shutil,subprocess as sp,sys,tempfile
r=Path(__file__).resolve().parent
local=r.name.startswith('round3867-') and (r.parent/'round3866-make-cstool-library').is_dir()
if local:
    d=lambda n:next(r.parent.glob(f'round{n}-*'))
    q=json.loads((d(3866)/'tree.json').read_text())
    patch=d(3866)/'candidate.patch';seed=d(579)/'source';e=r
else:
    q=json.loads((r/'source.json').read_text());patch=r/'candidate.patch';seed=r.parent/'source';e=r.parent/'evidence';e.mkdir(exist_ok=True)
def save(name,value):(e/(name+'.json')).write_text(json.dumps(value,indent=2)+'\n')
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def git(p,*cmd):return sp.check_output(['git','-C',p,*cmd],text=True).strip()
def log_run(cmd,path,environment=None):
    z=sp.run(cmd,stdout=sp.PIPE,stderr=sp.STDOUT,text=True,env=environment)
    (e/(path+'.log')).write_text(z.stdout)
    return z
assert sha(patch)==q['sha256']
osname=platform.system();assert osname in ('Linux','Darwin')
zz=Path(tempfile.mkdtemp(dir=r if local else None));nbytes=0;data={}
try:
    for name,static,shared,out in [('shared',False,True,False),('shared-output-dir',False,True,True),('static',True,False,False),('both-output-dir',True,True,True)]:
        s=zz/name;sp.run(['git','clone','-q','--no-checkout','--shared',seed,s],check=True)
        git(s,'checkout','-q','--detach',q['parent'])
        build=zz/('artifacts-'+name) if out else s
        tool=s/'cstool/cstool';args=['make','-C',str(s),'-j4','CAPSTONE_ARCHS=riscv','CC=clang','V=1','CAPSTONE_STATIC='+('yes'if static else'no'),'CAPSTONE_SHARED='+('yes'if shared else'no')]
        if out:args+=['BUILDDIR='+str(build)]
        so=build/('libcapstone.6.dylib' if osname=='Darwin' else 'libcapstone.so.6');ar=build/'libcapstone.a'
        oldhash=None
        if name=='shared':
            result=log_run(args+['all'],'base-shared')
            failures=[l for l in result.stdout.splitlines()if 'No rule to make target' in l and 'libcapstone.a' in l and 'cstool' in l]
            assert result.returncode and failures and so.is_file() and not ar.is_file() and not tool.exists(),result.stdout[-1400:]
            oldhash=sha(so)
            save('baseline',dict(commit=q['parent'],library=so.name,sha256=oldhash,error=failures))
        git(s,'apply','--index',str(patch.resolve()));assert git(s,'write-tree')==q['tree']
        result=log_run(args+['all'],'candidate-'+name)
        assert result.returncode==0,result.stdout[-1600:]
        assert ar.exists()==static and so.exists()==shared and tool.is_file()
        expected=ar if static else so
        if oldhash:assert sha(so)!=oldhash
        link=[l for l in result.stdout.splitlines()if l.strip().endswith(' -o cstool')]
        assert len(link)==1 and [Path(t).resolve() for t in shlex.split(link[0]) if Path(t).name==expected.name]==[expected.resolve()],link
        env=dict(os.environ)
        if shared:env['DYLD_LIBRARY_PATH' if osname=='Darwin' else 'LD_LIBRARY_PATH']=str(build)
        libraries=sp.check_output((['otool','-L',tool] if osname=='Darwin' else ['ldd',tool]),text=True,env=env)
        assert (so.name in libraries)==(not static),libraries
        if osname=='Linux' and not static:assert str(so) in libraries
        output=sp.check_output([tool,'riscv64','13051500'],text=True,env=env)
        assert 'addi' in output and 'a0' in output,output
        details={}
        for encoding,spelling in ((0x300,'mstatus'),(0x7cb,'0x7cb')):
            word=(encoding<<20)|(11<<15)|(1<<12)|(10<<7)|0x73
            text=sp.check_output([tool,'-d','riscv64',word.to_bytes(4,'little').hex()],env=env,text=True)
            assert any(line.endswith('CSR = '+spelling) for line in text.splitlines()),text
            details[hex(encoding)]=text
        bad=sp.run([tool,'riscv64','13051500','bad!'],env=env,text=True,capture_output=True)
        assert bad.returncode==254 and 'invalid address' in bad.stderr
        stamp=tool.stat().st_mtime_ns
        again=log_run(args+['all'],'repeat-'+name)
        assert again.returncode==0 and tool.stat().st_mtime_ns==stamp
        if name=='static':
            tool.unlink()
            independent=log_run(['make','-C',str(s/'cstool'),'V=1','CC=clang'],'standalone')
            assert independent.returncode==0 and sp.check_output([tool,'riscv64','13051500'],text=True)==output
        data[name]=dict(static=static,shared=shared,custom_directory=out,dependency=expected.name,csr=details,command=link[0],runtime=libraries,decoded=output,archive=sha(ar)if static else None,dso=sha(so)if shared else None)
        save('profiles',data)
        for p in ([s,build] if out else [s]):
            nbytes+=sum(f.stat().st_size for f in p.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(p)
    assert len({v['decoded'] for v in data.values()})==1
    save('complete',dict(complete=True,source=q,os=osname,arch=platform.machine(),profiles=data))
finally:
    nbytes+=sum(f.stat().st_size for f in zz.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(zz);save('cleanup',dict(removed=not zz.exists(),bytes=nbytes))
