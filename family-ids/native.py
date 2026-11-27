from pathlib import Path
import hashlib,json,math,os,platform,random,shutil,subprocess as sp,tempfile
import corpus
r=Path(__file__).resolve().parent;src=r.parent/'source';e=r.parent/'evidence';e.mkdir();q=json.loads((r/'tree.json').read_text())
def sha(f):
    result=hashlib.sha256()
    with f.open('rb') as stream:
        while part:=stream.read(1024*1024):result.update(part)
    return result.hexdigest()
def save(k,z):(e/(k+'.json')).write_text(json.dumps(z,indent=2)+'\n')
def run(*args):sp.run(args,check=True)
def get(*args):return sp.check_output(args,text=True).strip()
def git(*args):return get('git','-C',src,*args)
assert git('rev-parse','HEAD')==q['parent'] and sha(r/'candidate.patch')==q['sha256']
cc=os.environ['CC'];flavor=os.environ['FLAVOR'];ccflags='-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'
t=Path(tempfile.mkdtemp());manifest=json.loads((r/'manifest.json').read_text())['inputs']
try:
 panels={};all_images={};raw={};inputs={};fixed={}
 for arch,sel,prefix in [('PPC',104,'ppc64el'),('MIPS',103,'mips64el'),('RISCV',105,'riscv64')]:
    info=next(v for v in manifest if v['name']==prefix+'-ls');pkg=t/(arch+'.deb')
    run('curl','--retry','3','-fsSL',info['url'],'-o',pkg);assert sha(pkg)==info['package_sha256']
    for name in ('ls','sort','cp','cat'):
        image=corpus.deb_binary(pkg,name);f=t/(prefix+'-'+name+'.text');f.write_bytes(corpus.elf_text(image));inputs[f.stem]=dict(sha256=sha(f),bytes=f.stat().st_size,package=sha(pkg))
        if name=='ls':assert sha(f)==info['text_sha256']
    pkg.unlink()
 profiles=[('ppc',['PPC'],False)] if flavor=='first' else [('neverd',['ARM','AARCH64','MIPS','X86'],False),('mixed',['MIPS','PPC','RISCV'],False),('ppc-diet',['PPC'],True)]
 for key,arches,diet in profiles:
    b=t/key;variants={};libraries={}
    for label in ('base','candidate'):
        git('restore','--source','HEAD','--staged','--worktree','--','.')
        if label=='candidate':
            git('apply','--index',str(r/'candidate.patch'));assert git('write-tree')==q['tree']
        run('cmake','-S',src,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_DIET='+('ON' if diet else 'OFF'),'-DCMAKE_C_COMPILER='+cc,'-DCMAKE_C_FLAGS='+ccflags,'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON',*['-DCAPSTONE_'+a+'_SUPPORT=ON'for a in arches])
        run('cmake','--build',b,'--parallel','4','--target','capstone_shared','capstone_static')
        so,=[f for f in b.glob('libcapstone.so.*')if not f.is_symlink()]
        variants[label]=dict(shared=sha(so),archive=sha(b/'libcapstone.a'),objects={str(f.relative_to(b)):sha(f)for f in b.rglob('*.c.o')})
        libraries[label]=t/(key+'-'+label+'.so');shutil.copyfile(so,libraries[label])
    all_images[key]=variants
    before,after=variants['base'],variants['candidate'];assert set(before['objects'])==set(after['objects'])
    changed=[Path(f).name for f,a in before['objects'].items()if after['objects'][f]!=a]
    if 'PPC' not in arches:
        assert before==after;shutil.rmtree(b);continue
    if diet:
        assert before==after, key
    else:
        assert changed==['PPCInstPrinter.c.o'] and before['shared']!=after['shared'],(key,changed)
    run('c++','-std=c++17','-O2','-I',src/'include',r/'ppc-states.cpp','-ldl','-o',t/'ppc-states')
    state_check=get(t/'ppc-states',libraries['base'],libraries['candidate'],'4096')
    save('state-'+key,dict(result=state_check))
    if before==after:shutil.rmtree(b);continue
    run('ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_alias_mnemonic')
    sel,prefix=(103,'mips64el') if key=='mips' else (104,'ppc64el');lib=t/'libcapstone.so';lib.write_bytes(libraries['base'].read_bytes())
    import re
    target=re.search(r"\(SONAME\).*\[(.*?)\]",get("readelf","-d",lib))[1]
    alias=t/target
    if alias!=lib and not alias.exists():alias.symlink_to(lib.name)
    for tool in ('raw','time'):run('c++','-std=c++17','-O3','-I',src/'include',r/(tool+'.cpp'),'-L'+str(t),'-Wl,-rpath,'+str(t),'-lcapstone','-o',t/tool)
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))});cmd=['setarch',platform.machine(),'-R']
    images={k:f.read_bytes()for k,f in libraries.items()};n=max(map(len,images.values()));images={k:v+bytes(n-len(v))for k,v in images.items()};images['copy']=images['base'];lib.write_bytes(images['base'])
    inode=lib.stat().st_ino;offsets=[i for i in range(0,n,4096)if images['base'][i:i+4096]!=images['candidate'][i:i+4096]];verified={}
    def select(k):
        with lib.open('r+b',buffering=0)as f:
            for i in offsets:f.seek(i);assert f.write(images[k][i:i+4096])==len(images[k][i:i+4096])
        assert lib.stat().st_size==n and lib.stat().st_ino==inode
        if k not in verified:verified[k]=sha(lib);assert verified[k]==hashlib.sha256(images[k]).hexdigest()
    fixtures=[(104,'ppc64el',n)for n in ('ls','cat','sort','cp')]
    if key=='mixed':fixtures.extend([(103,'mips64el','ls'),(105,'riscv64','ls')])
    for sel,prefix,name in fixtures:
        f=t/(prefix+'-'+name+'.text')
        for opt in range(5):
            values=[]
            for label in libraries:
                select(label);values.append(get(*cmd,t/'raw',str(sel),f,str(opt)))
            assert values[0]==values[1] and int(values[0].split()[0])>0;raw[key+'/'+f.stem+'/'+str(opt)]=values[0]
        def sample(k,mode,reps):
            select(k);return list(map(int,get(*cmd,t/'time',str(sel),str(mode),f,'1048576',str(reps)).split()))
        for mode in (0,1,2):
            reps=max(1,math.ceil(40e6/sample('base',mode,1)[0]));rng=random.Random(f.stem+'/'+str(mode));cycles=[];labels=list(images)
            for i in range(17):
                rng.shuffle(labels);times={k:[] for k in labels}
                for k in labels+labels[::-1]:
                    z=sample(k,mode,reps);times[k].append(z[:2])
                    if not i and k==labels[0]:expected=z[2:]
                    assert z[2:]==expected
                cycles.append({k:[sum(v[x]for v in obs)/2 for x in (0,1)]for k,obs in times.items()})
            panels[key+'/'+f.stem+'/'+str(mode)]=dict(reps=reps,checksum=expected,cycles=cycles)
    fixed[key]=dict(inode=inode,verified=verified,blocks=len(offsets));shutil.rmtree(b)
 save('raw',raw);save('timings',panels);save('images',all_images);save('fixed',fixed);save('complete',dict(source=q,host=platform.platform(),profiles=list(all_images),inputs=inputs,cpu=get('lscpu')))
finally:
 size=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);save('cleanup',dict(bytes=size,removed=not t.exists()))
