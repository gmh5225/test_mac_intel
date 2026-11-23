from pathlib import Path
import hashlib,json,os,platform,shutil,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;s=r.parent/'source';out=r.parent/'evidence';out.mkdir(exist_ok=True)
load=lambda f:json.loads(f.read_text())
def save(name,value):(out/(name+'.json')).write_text(json.dumps(value,indent=2)+'\n')
def git(*args):return sp.check_output(['git','-C',s,*args],text=True).strip()
def digest(data):return hashlib.sha256(data).hexdigest()
def run(name,args):
    f=out/(name+'.log')
    with f.open('w')as w:p=sp.run(args,stdout=w,stderr=sp.STDOUT)
    if p.returncode:print(f.read_text(errors='replace')[-3000:],flush=True);p.check_returncode()
q=load(r/'comparison.json');cc=os.environ['CC'];tmp=Path(tempfile.mkdtemp());results={}
try:
    assert git('rev-parse','HEAD')==q['parent']
    for name,opts in {'static':[], 'dual':['CAPSTONE_SHARED=yes'], 'diet':['CAPSTONE_DIET=yes'], 'reduced':['CAPSTONE_X86_REDUCE=yes'], 'custom-allocator':['CAPSTONE_USE_SYS_DYN_MEM=no']}.items():
        rows={}
        for stage in ('base','candidate'):
            git('restore','--source','HEAD','--staged','--worktree','--','.')
            if stage=='candidate':
                patch=r/'candidate.patch';assert digest(patch.read_bytes())==q['sha256']
                git('apply','--index',str(patch));assert git('write-tree')==q['tree']
            b=tmp/'build';b.mkdir()
            args=['make','-j4','-C',s,'all','BUILDDIR='+str(b),'CC='+cc,'CAPSTONE_ARCHS=x86 aarch64','CAPSTONE_BUILD_CORE_ONLY=yes','CAPSTONE_STATIC=yes']
            if name!='dual':args.append('CAPSTONE_SHARED=no')
            run('make-'+name+'-'+stage,args+opts)
            lib=b/'libcapstone.a'
            members=[f for f in sp.check_output(['ar','t',lib],text=True).splitlines() if f and not f.startswith('__.SYMDEF')]
            assert len(members)>20 and len(members)==len(set(members))
            objs={f:digest(sp.check_output(['ar','p',lib,f])) for f in members}
            libs={f.name:digest(f.read_bytes()) for f in b.glob('libcapstone.*') if f.is_file() and not f.is_symlink() and ('.so' in f.name or '.dylib' in f.name)}
            assert bool(libs)==(name=='dual')
            exe=tmp/'probe';run('link-'+name+'-'+stage,[cc,'-std=c99','-O2','-I',s/'include',r/'identity-probe.c',lib,'-lm','-o',exe])
            result=sp.check_output([exe],text=True).strip();assert len(result)==16
            exists=any(x.split()[-1].lstrip('_')=='X86_decodePublicRecord' for x in sp.check_output(['nm',exe],text=True).splitlines() if x.split())
            assert exists==(stage=='candidate' and name=='static'),(name,stage,exists)
            rows[stage]=dict(objects=objs,members=members,shared=libs,executable=digest(exe.read_bytes()),output=result,linked=exists)
            shutil.rmtree(b)
        a,z=rows.values()
        assert a['output']==z['output'] and a['shared']==z['shared']
        changes=sorted(k for k in a['objects'].keys()|z['objects'].keys() if a['objects'].get(k)!=z['objects'].get(k))
        if name in ('dual','diet','reduced'):assert a==z,(name,changes)
        if name=='custom-allocator':
            assert changes==['X86PublicOutput.o'] and a['executable']==z['executable'],(name,changes)
        if name=='static':assert 'X86PublicOutput.o' in changes and a['executable']!=z['executable']
        results[name]=dict(differences=changes,base=a['executable'],candidate=z['executable'],records=z['output'],linked=z['linked'],shared=z['shared']);save('profiles',results)
    save('complete',dict(complete=True,source=q,profiles=results,cc=cc,host=platform.platform()))
finally:
    used=sum(f.stat().st_size for f in tmp.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(tmp);save('cleanup',dict(bytes=used,removed=not tmp.exists()))
