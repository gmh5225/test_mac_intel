from pathlib import Path
import json,os,platform,shutil,subprocess as sp,tempfile
r=Path(__file__).resolve().parent
local=(r.parent/'round3866-make-cstool-library').is_dir()
if local:
    d=lambda n:next(r.parent.glob(f'round{n}-*'))
    src=d(579)/'source';q=json.loads((d(3866)/'tree.json').read_text());patch=d(3866)/'candidate.patch';e=r
else:
    src=r.parent/'source';q=json.loads((r/'source.json').read_text());patch=r/'candidate.patch';e=r.parent/'evidence';e.mkdir(exist_ok=True)
def save(n,v):(e/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def run(*a,**kw):sp.run(a,check=True,**kw)
def get(*a):return sp.check_output(a,text=True)
def csr(v):return ((v<<20)|(11<<15)|(1<<12)|(10<<7)|0x73).to_bytes(4,'little').hex()
w=Path(tempfile.mkdtemp(dir=r if local else None));source=w/'source';proof={};nbytes=0
try:
    run('git','clone','-q','--no-checkout','--shared',src,source);run('git','-C',source,'checkout','--detach','-q',q['parent'])
    run('git','-C',source,'apply','--index',patch.resolve());assert get('git','-C',source,'write-tree').strip()==q['tree']
    for key,arch,shared,alloc,diet in [('shared','RISCV',True,True,False),('static','RISCV',False,True,False),('allocator-off','RISCV',True,False,False),('diet','RISCV',True,True,True),('riscv-disabled','ARM',True,True,False)]:
        b=w/key;on=lambda v:'ON' if v else 'OFF'
        args=['-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_CSTOOL=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_'+arch+'_SUPPORT=ON','-DCAPSTONE_BUILD_STATIC_LIBS='+on(not shared),'-DCAPSTONE_BUILD_SHARED_LIBS='+on(shared),'-DCAPSTONE_BUILD_DIET='+on(diet),'-DCAPSTONE_USE_DEFAULT_ALLOC='+on(alloc)]
        if platform.system()=='Darwin':args.append('-DCAPSTONE_BUILD_MACOS_THIN=ON')
        if platform.system()!='Windows':args+=['-G','Ninja']
        run('cmake','-S',source,'-B',b,*args)
        run('cmake','--build',b,'--config','Release','--target','cstool','capstone_shared' if shared else 'capstone_static','--parallel','4')
        tool,=[f for f in b.rglob('cstool.exe' if os.name=='nt' else 'cstool') if f.is_file()]
        probe=sp.run([tool,'riscv64' if arch=='RISCV' else 'arm','13051500' if arch=='RISCV' else '0000a0e1'],text=True,capture_output=True)
        if not alloc:
            assert (probe.returncode&255)==253 and 'allocators are not defined' in probe.stderr,probe
        else:
            assert probe.returncode==0,probe
            if not diet:assert ('addi' if arch=='RISCV' else 'mov') in probe.stdout,probe
        details={}
        if arch=='RISCV' and alloc and not diet:
            for v,name in ((0x300,'mstatus'),(0x7cb,'0x7cb')):
                detail=get(tool,'-d','riscv64',csr(v));assert any(l.endswith('CSR = '+name) for l in detail.splitlines()),detail
                details[hex(v)]=detail
        proof[key]=dict(arch=arch,shared=shared,alloc=alloc,diet=diet,returncode=probe.returncode,output=probe.stdout,error=probe.stderr,csrs=details)
        nbytes+=sum(f.stat().st_size for f in b.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(b)
    save('cmake-complete',dict(complete=True,source=q,os=platform.system(),arch=platform.machine(),profiles=proof))
finally:
    nbytes+=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(w);save('cmake-cleanup',dict(removed=not w.exists(),bytes=nbytes))
