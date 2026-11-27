from pathlib import Path
import hashlib,json,math,os,platform,random,shutil,statistics,subprocess as sp,sys,tempfile
r=Path(__file__).resolve().parent
ci=bool(os.environ.get('GITHUB_ACTIONS'))
out=Path(os.environ['GITHUB_WORKSPACE'])/'evidence' if ci else r
out.mkdir(exist_ok=True)
def save(name,data):
    (out/(name+'.json')).write_text(json.dumps(data,indent=2)+'\n')
def read(p):return json.loads(p.read_text())
def run(*args):sp.run(args,check=True)
def get(*args):return sp.check_output(args,text=True).strip()
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def disk(p):return sum(x.stat().st_size for x in p.rglob('*')if x.is_file() and not x.is_symlink())
d=lambda n:next(r.parent.glob(f'round{n}-*'))
if ci: baseline=Path(os.environ['GITHUB_WORKSPACE'])/'source';tree=read(r/'tree.json')
else: baseline=d(579)/'source';tree=read(d(3473)/'tree.json')
temp=Path(tempfile.mkdtemp(dir=r));receipt={}
try:
    src=temp/'capstone';build=temp/'build';run('git','clone','--shared','--quiet','--no-checkout',baseline,src)
    run('git','-C',src,'checkout','--quiet','--detach',tree['parent'])
    original=temp/'original.c'
    original.write_bytes((src/'arch/WASM/WASMInstPrinter.c').read_bytes())
    cc=os.environ.get('CC','clang');cxx=os.environ.get('CXX','clang++')
    run('cmake','-G','Ninja','-S',src,'-B',build,'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_WASM_SUPPORT=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON')
    inc=['-I',src,'-I',src/'include','-I',src/'arch/WASM']
    run(cc,'-O2',*inc,'-DCAPSTONE_HAS_WASM','-DCAPSTONE_USE_SYS_DYN_MEM','-DWASM_printInst=wasm_reference','-c',original,'-o',temp/'ref.o')
    hi=temp/'reference-high.c';original_code=original.read_text()
    call='SStream_concat(O, "0x%x", MI->wasm_data.brtable.address);'
    assert original_code.count(call)==1
    hi.write_text(original_code.replace(call,'SStream_concat(O, "0x%" PRIx64, MI->wasm_data.brtable.address);'))
    run(cc,'-O2',*inc,'-DCAPSTONE_HAS_WASM','-DCAPSTONE_USE_SYS_DYN_MEM','-DWASM_printInst=wasm_reference','-c',hi,'-o',temp/'high-ref.o')
    run(cxx,'-O2','-std=c++17',*inc,'-c',r/'measure.cpp','-o',temp/'driver.o')
    by={};libs={};objects={}
    for label in ('base','candidate'):
        if label=='candidate':
            if ci:
                patch=r/'candidate.patch';assert sha(patch)==tree['sha256'];run('git','-C',src,'apply','--index',patch)
                assert get('git','-C',src,'write-tree')==tree['tree']
            else:run('git','-C',src,'checkout','--quiet','--detach',tree['commit'])
        run('cmake','--build',build,'--target','capstone_static','capstone_shared','wasm_brtable_size','--parallel','3')
        run('ctest','--test-dir',build,'--no-tests=error','-R','^unit_wasm_brtable_size$','--output-on-failure')
        lib,=build.rglob('libcapstone.a')
        shared=[f for f in build.rglob('libcapstone*') if f.is_file() and not f.is_symlink() and ('.so' in f.suffixes or '.dylib' in f.suffixes)]
        assert len(shared)==1,shared
        run(cc,'-O2','-DCAPSTONE_HAS_WASM','-DCAPSTONE_USE_SYS_DYN_MEM',*inc,r/'verify-stream.c',temp/'ref.o',lib,'-o',temp/'stream')
        if label=='candidate':
            run(cc,'-O2','-DCAPSTONE_HAS_WASM','-DCAPSTONE_USE_SYS_DYN_MEM',*inc,r/'high.c',temp/'high-ref.o',lib,'-o',temp/'high')
            high=int(get(temp/'high'));assert high==172*9*16*4;save('high-stream',dict(cases=high,source=tree))
        by[label]=int(get(temp/'stream'));assert by[label]==172*8*9*16*4,by
        run(cxx,temp/'driver.o',lib,'-o',temp/label)
        exe=temp/(label+'-shared');run(cxx,temp/'driver.o',shared[0],'-Wl,-rpath,'+str(shared[0].parent),'-o',exe)
        target=temp/(label+'-dynamic');target.mkdir();shutil.copy2(shared[0],target/shared[0].name)
        for link in shared[0].parent.glob('libcapstone*'):
            if link.is_symlink() and link.resolve()==shared[0]:(target/link.name).symlink_to(shared[0].name)
        libs[label]={'static':sha(lib),'shared':sha(shared[0]),'driver':sha(temp/label)}
        objects[label]={str(f.relative_to(build)):sha(f)for f in build.rglob('*.c.o')}
    assert by['base']==by['candidate']
    changed=[f for f,x in objects['base'].items() if x!=objects['candidate'][f]]
    added=set(objects['candidate'])-set(objects['base'])
    assert {Path(f).name for f in added}=={'WASMTablePrinter.c.o'}
    assert {Path(f).name for f in changed}=={'WASMInstPrinter.c.o','wasm_brtable_size.c.o'},changed
    save('build',dict(complete=True,source=tree,streams=by,libraries=libs,changed=changed,compiler=get(cc,'--version').splitlines()[0],host=platform.platform(),machine=platform.machine()))
    inputs=temp/'inputs' if ci else r/'inputs'
    if ci:run(sys.executable,'-B',r/'corpus.py',inputs)
    cover=read(inputs/'manifest.json');save('corpus',cover);results={}
    path=temp/'active';shutil.copyfile(temp/'base',path);path.chmod(0o755);inode=path.stat().st_ino
    bins={t:(temp/t).read_bytes() for t in ('base','candidate')};bins['duplicate']=bins['base']
    current=None
    immutable=sys.platform=='darwin'
    if immutable:
        shutil.copy2(temp/'base',temp/'duplicate')
    selections={tag:0 for tag in bins}
    def select(tag):
        global current
        if current!=tag:
            if immutable:
                # A mapped Mach-O must retain its contents. Atomically select
                # another verified file at the common execution path.
                fresh=temp/'selected-next'
                os.link(temp/tag,fresh)
                os.replace(fresh,path)
            else:
                path.write_bytes(bins[tag])
            current=tag
        assert path.stat().st_ino==((temp/tag).stat().st_ino if immutable else inode)
        selections[tag]+=1
    for name,spec in cover.items():
        if name=='wabt':continue
        raw=inputs/(name+'.wasm');ranges=inputs/(name+'.ranges');assert sha(raw)==spec['sha256'] and sha(ranges)==spec['ranges_sha256']
        for detail in (0,1):
            args=[raw,ranges,str(detail)]
            def invoke(exe,verify,reps,env=None):
                return list(map(int,sp.check_output([exe,*args,str(verify),str(reps)],env=env,text=True).split()))
            gold=None
            for label in ('base','candidate'):
                select(label);g=invoke(path,1,1)[2:]
                header='DYLD_LIBRARY_PATH' if sys.platform=='darwin' else 'LD_LIBRARY_PATH'
                dy_env={**os.environ,header:str(temp/(label+'-dynamic'))}
                assert invoke(temp/(label+'-shared'),1,1,dy_env)[2:]==g
                if gold is not None:assert g==gold
                gold=g
            assert sum(gold[:3])==spec['operators'] and gold[0]>0
            reps=max(1,math.ceil(120e6/invoke(path,0,1)[0]));expected=invoke(path,0,reps)[2:];pairs=[];rng=random.Random(name+'/'+str(detail))
            for _ in range(35 if ci else 7):
                order=list(bins);rng.shuffle(order);row={}
                for label in order:
                    select(label);v=invoke(path,0,reps);assert v[2:]==expected;row[label]=v[:2]
                pairs.append(row)
            result={}
            for ctrl in ('base','duplicate'):
                result[ctrl]=[]
                for j in (0,1):
                    ratios=sorted(v[ctrl][j]/v['candidate'][j]for v in pairs)
                    result[ctrl].append([statistics.median(ratios),ratios[11 if ci else 1],ratios[-12 if ci else -2]])
            results[name+'/'+str(detail)]=dict(oracle=gold,ratios=result,pairs=pairs,repeats=reps)
            save('observations',results);print(name,detail,gold,result,flush=True)
    checks={t:hashlib.sha256(buf).hexdigest()for t,buf in bins.items()}
    assert checks['base']==checks['duplicate']!=checks['candidate']
    if immutable:
        assert all(sha(temp/t)==v for t,v in checks.items())
    save('selection',dict(complete=True,immutable=immutable,source=tree,selections=selections,sha256=checks))
    save('decision',dict(complete=True,source=tree,corpus=cover,host=platform.platform(),results=results,streams=by,changed=changed))
finally:
    receipt['build']=disk(temp);shutil.rmtree(temp);receipt['removed']=not temp.exists()
    if not ci and (out/'decision.json').is_file():
        inputs=r/'inputs';receipt['corpus']=disk(inputs);shutil.rmtree(inputs);receipt['removed'] &= not inputs.exists()
    save('cleanup',dict(**receipt,bytes=sum(x for k,x in receipt.items()if k!='removed')))
