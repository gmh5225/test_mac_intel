from pathlib import Path
import hashlib,json,os,platform,shutil,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;root=Path(os.environ['GITHUB_WORKSPACE']);source=root/'source';output=root/'evidence';output.mkdir(exist_ok=True)
def read(p):return json.loads(p.read_text())
def save(name,z):(output/(name+'.json')).write_text(json.dumps(z,indent=2)+'\n')
def get(*a,**kw):return sp.check_output(a,text=True,**kw).strip()
def run(*a,**kw):sp.run(a,check=True,**kw)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
q=read(r/'tree.json');assert get('git','-C',source,'rev-parse','HEAD')==q['parent']
cc=os.environ['CC'];os.environ['ZERO_AR_DATE']='1';w=Path(tempfile.mkdtemp());s=w/'src';check={}
try:
    run('git','clone','--quiet','--shared','--no-checkout',source,s);run('git','-C',s,'checkout','--quiet','--detach',q['parent'])
    for group,arches in [('six',['X86','ARM','AARCH64','PPC','MIPS','RISCV']),('seven',['X86','ARM','AARCH64','PPC','MIPS','RISCV','WASM']),('make-wasm',['WASM']),('wasm',['WASM']),('wasm-diet',['WASM'])]:
        b=w/group;rows={};is_make=group.startswith('make')
        dedicated=(arches==['WASM'])
        active=dedicated and platform.system()=='Linux' and platform.machine()=='x86_64' and 'clang' in get(cc,'--version').lower()
        for stage in ('base','candidate'):
            run('git','-C',s,'restore','--source=HEAD','--staged','--worktree','--','.')
            if stage=='candidate':
                patch=r/'candidate.patch';assert sha(patch)==q['sha256'];run('git','-C',s,'apply','--index',patch);assert get('git','-C',s,'write-tree')==q['tree']
            if is_make:
                # The Makefile resolves BLDIR relative to the source directory.
                b.mkdir(exist_ok=True);args=['make','-j3','CAPSTONE_ARCHS=wasm','CAPSTONE_BUILD_CORE_ONLY=yes','CAPSTONE_SHARED=no','CAPSTONE_STATIC=yes','CAPSTONE_BUILD_MACOS_THIN=yes','BUILDDIR='+str(b),'CC='+cc]
                run(*args,cwd=s);paths=list(b.rglob('libcapstone.a'));assert len(paths)==1,paths
                lib=paths[0];source_obj={p.name:sha(p)for p in b.rglob('*.o')};assert 'WASMDisassembler.o' in source_obj,source_obj
                run(cc,'-O2','-std=c11','-I'+str(s/'include'),s/'tests/unit/wasm_brtable_size.c',lib,'-o',w/'check-table')
                run(w/'check-table')
            else:
                options=['-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON']
                if group=='wasm-diet':options.append('-DCAPSTONE_BUILD_DIET=ON')
                run('cmake','-G','Ninja','-S',s,'-B',b,*options,*['-DCAPSTONE_'+a+'_SUPPORT=ON'for a in arches])
                run('cmake','--build',b,'--target','capstone_static','capstone_shared','--parallel','4')
                source_obj={str(p.relative_to(b)):sha(p)for p in b.rglob('*.c.o')};assert len(source_obj)>=(12 if dedicated else 50)
                assert any('CAPSTONE_WASM_DEDICATED_DECODER' in line['command'] for line in read(b/'compile_commands.json'))==(dedicated and stage=='candidate')
                lib,=b.rglob('libcapstone.a')
            libraries={p.name:sha(p)for p in lib.parent.glob('libcapstone*')if p.is_file() and not p.is_symlink()}
            asmtests={}
            if dedicated and not is_make:
                run(cc,'-O2','-std=c11','-I'+str(s/'include'),s/'tests/unit/wasm_brtable_size.c',lib,'-o',w/'check-table')
                run(w/'check-table')
            if group!='six':
                run(cc,'-O2','-std=c11','-I'+str(s/'include'),r/'wide.c',lib,'-o',w/'check')
                asmtests=get(w/'check').split();assert asmtests==['704','0','0' if group=='wasm-diet' else '220'],asmtests
            rows[stage]=dict(objects=source_obj,libraries=libraries,records=asmtests)
        old=rows['base'];new=rows['candidate'];assert old['objects'].keys()==new['objects'].keys()
        changed=[k for k,v in old['objects'].items()if v!=new['objects'][k]]
        assert [Path(x).name for x in changed]==([('WASMDisassembler.o' if is_make else 'WASMDisassembler.c.o')] if active else []),(group,changed)
        assert (old['libraries']==new['libraries'])==(not active),(group,old['libraries'],new['libraries'])
        check[group]=dict(active=active,objects=len(old['objects']),changed=changed,records=new['records'],libraries={k:v['libraries']for k,v in rows.items()});save('configurations',check)
        shutil.rmtree(b)
    save('complete',dict(complete=True,source=q,host=platform.platform(),system=platform.system(),machine=platform.machine(),compiler=get(cc,'--version').splitlines()[0],configurations=check))
finally:
    total=sum(p.stat().st_size for p in w.rglob('*')if p.is_file() and not p.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=total))
