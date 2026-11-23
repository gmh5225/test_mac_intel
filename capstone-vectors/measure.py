from pathlib import Path
import hashlib,json,os,platform,shutil,subprocess as sp,tempfile
d=Path(__file__).resolve().parent;s=d.parent/'source';nd=d.parent/'neverd-config';out=d.parent/'evidence';out.mkdir(exist_ok=True);m=json.loads((d/'comparison.json').read_text());t=Path(tempfile.mkdtemp())
sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
def g(*a):return sp.check_output(['git','-C',s,*a],text=True).strip()
def run(k,args):
    with (out/(k+'.log')).open('w')as f:z=sp.run(args,stdout=f,stderr=sp.STDOUT)
    if z.returncode:print((out/(k+'.log')).read_text(errors='replace')[-3000:]);z.check_returncode()
def save(n,v):(out/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
try:
    assert g('rev-parse','HEAD')==m['original'] and sp.check_output(['git','-C',nd,'rev-parse','HEAD'],text=True).strip()==m['neverd']
    flow=(nd/'CMakeLists.txt').read_text();i=flow.index('# --- Capstone (our fork');j=flow.index('# --- NeverD CMake helpers',i)
    project=t/'project';(project/'third_party').mkdir(parents=True);(project/'third_party/capstone').symlink_to(s,target_is_directory=True);(project/'cmake').mkdir()
    shutil.copy2(nd/'cmake/NeverDCapstoneCompilerOptions.inc',project/'cmake');(project/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(Profile LANGUAGES C CXX)\n'+flow[i:j])
    public_test=d/'identity-probe.c'
    profiles={}
    for profile in ('project','nine','dual','mixed-diet','mixed-reduced'):
        b=t/('build-'+profile);receipts={}
        for stage,info in m['stages'].items():
            if profile!='project' and stage!='base':continue
            pair=[]
            for public in (False,True):
                label=profile+'-'+stage+('-after' if public else '-before')
                g('restore','--source','HEAD','--staged','--worktree','--','.')
                for nm in (['public'] if public else [])+([stage] if stage!='base' else []):
                    p=d/('receipt-'+nm+'.patch');assert sha(p)==m['patches'][nm];g('apply','--index',str(p))
                tree=g('write-tree');assert tree==info['after'if public else 'before']['tree']
                cfg=['cmake','-G','Ninja','-S',project if profile=='project'else s,'-B',b,'-DCMAKE_C_COMPILER=clang','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON']
                if profile!='project':
                    cfg+=['-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']
                    arches=('ARM','AARCH64','MIPS','LOONGARCH','SYSTEMZ','RISCV','POWERPC','SPARC') if profile=='nine' else ('MIPS',)
                    cfg+=['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in arches]
                    if profile=='mixed-diet':cfg+=['-DCAPSTONE_BUILD_DIET=ON']
                    if profile=='mixed-reduced':cfg+=['-DCAPSTONE_X86_REDUCE=ON']
                run('configure-'+label,cfg);run('build-'+label,['cmake','--build',b,'--parallel','4','--target','capstone_static',*(['capstone_shared']if profile!='project'else [])])
                lib,=b.rglob('libcapstone.a');objects={str(f.relative_to(b)):sha(f)for f in b.rglob('*.c.o')};assert any('LoongArch' in name for name in objects)==(profile=='nine')
                members=[n for n in sp.check_output(['ar','t',lib],text=True).splitlines()if not n.startswith('__.SYMDEF')]
                assert len(members)==len(set(members))>10
                digests=[hashlib.sha256(sp.check_output(['ar','p',lib,n])).hexdigest()for n in members]
                shared=[sha(f)for f in b.rglob('libcapstone.*')if f.name!='libcapstone.a' and not f.is_symlink() and ('.so' in f.name or f.suffix=='.dylib')]
                p=t/'public-probe';link_flags=(['-Wl,-u,_X86_disasmIter32','-Wl,-u,_X86_disasmIterText'] if platform.system()=='Darwin' else ['-Wl,--undefined=X86_disasmIter32','-Wl,--undefined=X86_disasmIterText']) if profile=='project' else [];run('link-'+label,['clang','-std=c99','-O2','-I',s/'include',public_test,*link_flags,lib,'-lm','-o',p]);res=sp.check_output([p],text=True).strip();assert res=='verified'
                y=dict(tree=tree,objects=objects,members=list(zip(members,digests)),shared=shared,probe=sha(p))
                pair.append(y)
            aa,bb=pair;assert all(aa[k]==bb[k] for k in ('objects','members','shared','probe')),(stage,profile)
            receipts[stage]=dict(before=aa['tree'],after=bb['tree'],objects=len(aa['objects']),members=len(aa['members']),shared=aa['shared'],probe=aa['probe'],member_sha256=hashlib.sha256(json.dumps(aa['members']).encode()).hexdigest())
        profiles[profile]=receipts;save('profiles',profiles)
    save('complete',dict(complete=True,source=m,profiles=profiles,machine=platform.machine(),platform=platform.platform()))
finally:
    n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=n))
