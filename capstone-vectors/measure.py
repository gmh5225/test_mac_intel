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
    for profile in ('project','ten','dual','pure','mixed-diet','mixed-reduced','pure-noatt'):
        b=t/('build-'+profile);receipts={}
        expected='reference' if profile.startswith('pure') else 'base'
        variants=('base','reference','candidate') if expected=='reference' else ('base','candidate')
        pair={}
        for stage in variants:
                label=profile+'-'+stage
                g('restore','--source','HEAD','--staged','--worktree','--','.')
                tree=m[stage]['tree']
                if stage!='base':
                    patch=d/(stage+'.patch');assert sha(patch)==m[stage]['sha256'];g('apply','--index',str(patch))
                assert g('write-tree')==tree
                cfg=['cmake','-G','Ninja','-S',project if profile=='project'else s,'-B',b,'-DCMAKE_C_COMPILER='+os.environ['CC'],'-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if os.environ['CC']=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),'-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON']
                if profile!='project':
                    cfg+=['-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']
                    arches=('ARM','AARCH64','MIPS','LOONGARCH','SYSTEMZ','RISCV','PPC','SPARC','XTENSA') if profile=='ten' else (() if profile.startswith('pure') else ('MIPS',))
                    if profile=='pure-noatt':cfg+=['-DCAPSTONE_X86_ATT_DISABLE=ON']
                    cfg+=['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in arches]
                    if profile=='mixed-diet':cfg+=['-DCAPSTONE_BUILD_DIET=ON']
                    if profile=='mixed-reduced':cfg+=['-DCAPSTONE_X86_REDUCE=ON']
                run('configure-'+label,cfg);run('build-'+label,['cmake','--build',b,'--parallel','4','--target','capstone_static',*(['capstone_shared']if profile!='project'else [])])
                lib,=b.rglob('libcapstone.a');objects={str(f.relative_to(b)):sha(f)for f in b.rglob('*.c.o')};assert any('LoongArch' in name for name in objects)==(profile=='ten')
                members=[n for n in sp.check_output(['ar','t',lib],text=True).splitlines()if not n.startswith('__.SYMDEF')]
                assert len(members)==len(set(members))>10
                digests=[hashlib.sha256(sp.check_output(['ar','p',lib,n])).hexdigest()for n in members]
                shared=[sha(f)for f in b.rglob('libcapstone.*')if f.name!='libcapstone.a' and not f.is_symlink() and ('.so' in f.name or f.suffix=='.dylib')]
                assert ('CAPSTONE_X86_ONLY' in (b/'compile_commands.json').read_text())==profile.startswith('pure')
                if profile=='ten':assert all(any(n in f for f in objects)for n in ('PPCMapping','XtensaMapping'))
                p=t/'public-probe'
                force=(['-Wl,-u,_X86_disasmIter32','-Wl,-u,_X86_disasmIterText','-Wl,-u,_X86_scanNativeBatch'] if platform.system()=='Darwin' else ['-Wl,--undefined=X86_disasmIter32','-Wl,--undefined=X86_disasmIterText','-Wl,--undefined=X86_scanNativeBatch'])
                executables={}
                for name,flags in [('normal',[]),('private',force)]:
                    run('link-'+label+'-'+name,['clang','-std=c99','-O2','-I',s/'include',public_test,*flags,lib,'-lm','-o',p])
                    assert sp.check_output([p],text=True).strip()=='verified'
                    executables[name]=sha(p)
                pair[stage]=dict(objects=objects,members=list(zip(members,digests)),shared=shared,probes=executables)
        prior=pair[expected];current=pair['candidate']
        diffs={f:[prior['objects'].get(f),current['objects'].get(f)]for f in prior['objects'].keys()|current['objects'].keys() if prior['objects'].get(f)!=current['objects'].get(f)}
        save('changes-'+profile,dict(expected=expected,objects=diffs,shared=[prior['shared'],current['shared']],probes=[prior['probes'],current['probes']]))
        assert prior==current,(profile,expected,list(diffs))
        a,z=pair['base'],pair['candidate']
        changed=sorted(k for k in z['objects'] if z['objects'][k]!=a['objects'].get(k))
        names={Path(f).name for f in changed}
        if expected=='reference':
            assert names=={'X86RegisterFallback32.c.o'} and a['shared']!=z['shared'],(profile,names)
        else:assert not changed and a==z,profile
        receipts=dict(expected=expected,changed=changed,trees={k:m[k]['tree'] for k in variants},objects=len(a['objects']),members=len(a['members']),shared=z['shared'],probes=z['probes'],member_sha256=hashlib.sha256(json.dumps(z['members']).encode()).hexdigest())
        profiles[profile]=receipts;save('profiles',profiles)
    make_checks={}
    for form in ('static','shared'):
        active=platform.system()=='Linux' and form=='shared'
        chunks={}
        for variant in ('base','candidate'):
            label='make-'+form+'-'+variant
            g('restore','--source','HEAD','--staged','--worktree','--','.')
            if variant!='base':g('apply','--index',str(d/(variant+'.patch')))
            assert g('write-tree')==m[variant]['tree']
            b=t/'make-output'
            if b.exists():shutil.rmtree(b)
            b.mkdir()
            args=['make','-C',s,'-j4','all','BUILDDIR='+str(b),'CC='+os.environ['CC'],'CAPSTONE_ARCHS=x86 aarch64','CAPSTONE_BUILD_CORE_ONLY=yes','CAPSTONE_STATIC=yes','CAPSTONE_SHARED='+('yes' if form=='shared' else 'no')]
            run(label,args)
            lib=b/'libcapstone.a';members=[n for n in sp.check_output(['ar','t',lib],text=True).splitlines() if n and not n.startswith('__.SYMDEF')]
            assert len(members)>20 and len(members)==len(set(members)),members
            objects={n:hashlib.sha256(sp.check_output(['ar','p',lib,n])).hexdigest()for n in members}
            images=sorted(sha(f)for f in b.glob('libcapstone.*') if f.is_file() and not f.is_symlink() and ('.so' in f.name or '.dylib' in f.name))
            assert bool(images)==(form=='shared') and ('X86PostPrinter.o' in objects)==active
            exe=t/'make-public-probe'
            run('make-link-'+form+'-'+variant,[os.environ['CC'],'-O2','-I',s/'include',public_test,lib,'-lm','-o',exe])
            assert sp.check_output([exe],text=True).strip()=='verified'
            chunks[variant]=dict(members=members,objects=objects,shared=images,probe=sha(exe))
        assert len(chunks)==2 and len(set(json.dumps(z,sort_keys=True) for z in chunks.values()))==1,(form,active)
        make_checks[form]=dict(active=active,objects=len(members),images=images,probe=sha(exe))
    save('make',make_checks)
    save('complete',dict(complete=True,source=m,profiles=profiles,machine=platform.machine(),platform=platform.platform()))
finally:
    n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=n))
