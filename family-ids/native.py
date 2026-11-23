from pathlib import Path
from statistics import median
from math import ceil
import hashlib, json, os, platform, random, shutil, subprocess as sp, tempfile
import corpus
r=Path(__file__).resolve().parent; source=r.parent/'source'; out=r.parent/'evidence';out.mkdir()
rd=lambda f:json.loads(f.read_text());meta=rd(r/'tree.json');stages=rd(r/'stages.json')
cc=os.environ['CC']; flavor=os.environ['FLAVOR']; mixed=flavor=='second'
def save(name,data):(out/(name+'.json')).write_text(json.dumps(data,indent=2)+'\n')
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def git(*args):return sp.check_output(['git','-C',source,*args],text=True).strip()
def run(name,args):
    with (out/(name+'.log')).open('w') as log:q=sp.run(args,stdout=log,stderr=sp.STDOUT)
    if q.returncode: print((out/(name+'.log')).read_text(errors='replace')[-1800:]);q.check_returncode()
def measure(t):
    assert git('rev-parse','HEAD')==meta['parent']
    manifest=rd(r/'manifest.json')['inputs']; inputs={}
    def load_input(key,info,binary):
        pkg=t/(info['package_sha256']+'.deb')
        if not pkg.exists():run('fetch-'+key,['curl','--retry','2','-fsSL',info['url'],'-o',pkg])
        assert sha(pkg)==info['package_sha256'];image=corpus.deb_binary(pkg,binary)
        path=t/(key+'.text');path.write_bytes(corpus.elf_text(image))
        if 'text_sha256' in info and info['name']==key:assert sha(path)==info['text_sha256']
        inputs[key]=dict(text=sha(path),binary=hashlib.sha256(image).hexdigest(),bytes=path.stat().st_size,package=sha(pkg))
    riscv=next(z for z in manifest if z['name']=='riscv64-ls')
    for n in ('ls','cat','sort','cp'):load_input('riscv64-'+n,riscv,n)
    checks=rd(r/'checks.json')
    assert all(inputs['riscv64-'+n]==v for n,v in checks['real'].items())
    cases={n:105 for n in inputs}
    if mixed:
        for key,code in [('arm64-ls',102),('mips64el-ls',103)]:
            info=next(z for z in manifest if z['name']==key);load_input(key,info,'ls');cases[key]=code
    save('inputs',inputs)
    run('guard-link',['c++','-std=c++17','-O2','-I',source/'include',r/'guard.cpp','-ldl','-o',t/'guard'])
    flags='-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'
    def config(b,arch,extra):
        return ['cmake','-S',source,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCMAKE_C_FLAGS='+flags,'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF',*['-DCAPSTONE_'+n+'_SUPPORT=ON' for n in arch],*extra]
    arches=['RISCV']+(['ARM','AARCH64','MIPS','X86']if mixed else [])
    info={};libs={};units=checks['tests']
    for profile,arch,extra in [('full',arches,[]),('diet',['RISCV'],['-DCAPSTONE_BUILD_DIET=ON']),('neverd',['ARM','AARCH64','MIPS','X86'],[])]:
        b=t/profile;variants={}
        for k in (('base','lazy','width') if profile=='full' else ('base','width')):
            git('restore','--source','HEAD','--worktree','--staged','--','.')
            if k!='base':
                patch=r/(k+'.patch');assert sha(patch)==stages[k]['sha256'];git('apply','--index',str(patch));assert git('write-tree')==stages[k]['tree']
            run(profile+k+'-config',config(b,arch,extra))
            run(profile+k+'-build',['cmake','--build',b,'--parallel','4','--target','capstone_shared','capstone_static',*(units if profile=='full' else []),*(['riscv_scan_options'] if profile=='full' else [])])
            if profile=='full' and k=='width':run('fixed-len-generator',['python3','-B',source/'suite/synctools/fixed_len_decoder.py','--check']);run('generated-aliases',[source/'suite/synctools/alias_pattern_rows.py','--check'])
            if profile=='full':run(profile+k+'-test',['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_riscv_'])
            files={str(f.relative_to(b)):sha(f) for f in b.rglob('*.c.o') if '/tests/' not in str(f)}
            so,=[v for v in b.glob('libcapstone.so.*')if not v.is_symlink()]
            variants[k]=dict(so=sha(so),archive=sha(b/'libcapstone.a'),objects=files)
            if profile=='full':libs[k]=t/(k+'.so');shutil.copy2(so,libs[k])
        if profile=='neverd':assert variants['base']==variants['width']
        else:
            for k,row in variants.items():
                assert set(row['objects'])==set(variants['base']['objects'])
                changed=[f for f,v in row['objects'].items() if v!=variants['base']['objects'][f]]
                actual={Path(f).name for f in changed}
                allowed={'RISCVDisassembler.c.o'} if k!='base' and (profile=='diet' or not mixed) else set()
                assert actual<=allowed and (profile!='full' or actual==allowed),(profile,k,actual,allowed)
                if profile=='full' and mixed:assert row==variants['base']
        info[profile]=variants;shutil.rmtree(b)
    save('profiles',info)
    for k in ('lazy','width'):
        proof=list(map(int,sp.check_output([t/'guard',libs['base'],libs[k]]).split()))
        assert proof[0]==checks['guards'][k][0] and all(proof);save('guard-'+k,proof)
    run('scan-guard-build',['c++','-std=c++17','-O2','-I',source/'include',r/'scan-guard.cpp','-ldl','-o',t/'scan-guard'])
    for k in ('width','lazy'):
        counts=list(map(int,sp.check_output([t/'scan-guard',libs['base'],libs[k]]).split()))
        assert counts==[1489920,338432,1151488],counts
        save('scan-proof-'+k,counts)
    run('detail-guard-build',['c++','-std=c++17','-O2','-I',source/'include',r/'detail-guard.cpp','-ldl','-o',t/'detail-guard'])
    for k in ('lazy','width'):
        counts=list(map(int,sp.check_output([t/'detail-guard',libs['base'],libs[k]]).split()));assert counts[0]==2*7*65536*3 and counts[1]+counts[2]==counts[0];save('detail-compressed-'+k,counts)
    run('compressed-guard-build',['c++','-std=c++17','-O2','-I',source/'include',r/'compressed-guard.cpp','-ldl','-o',t/'compressed-guard'])
    for k in ('lazy','width'):
        counts=list(map(int,sp.check_output([t/'compressed-guard',libs['base'],libs[k]]).split()))
        assert counts[0]==2*7*65536*3 and counts[1]+counts[2]==counts[0] and min(counts)>0
        save('compressed-'+k,counts)
    lib=t/'libcapstone.so.6';(t/'libcapstone.so').symlink_to(lib.name)
    images={k:f.read_bytes() for k,f in libs.items()};length=max(map(len,images.values()));images={k:v+bytes(length-len(v))for k,v in images.items()};images['copy']=images['base'];lib.write_bytes(images['base'])
    for f in ('time','raw'):run(f,['c++','-O3','-std=c++17','-I',source/'include',r/(f+'.cpp'),'-L',t,'-Wl,-rpath,'+str(t),'-lcapstone','-o',t/f])
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    run('fixed',['setarch',platform.machine(),'-R','true'])
    current=None
    def select(k):
        nonlocal current
        if current!=k:
            with lib.open('r+b')as f:assert f.write(images[k])==length
            current=k
    run('census',['c++','-O2','-std=c++17','-I',source/'include',r/'scan-census.cpp','-L',t,'-Wl,-rpath,'+str(t),'-lcapstone','-o',t/'census'])
    census={}
    for name in cases:
        if not name.startswith('riscv64-'):continue
        data=[]
        for k in ('base','width'):
            select(k);data.append(list(map(int,sp.check_output([t/'census',t/(name+'.text')]).split())))
        assert data[0]==data[1] and sum(data[0][2:])>0
        census[name]=data[0]
    save('scan-census',census)
    signatures={}
    for name,bits in cases.items():
        f=t/(name+'.text')
        for opt in range(5):
            data=[]
            for k in libs:
                select(k);data.append(sp.check_output([t/'raw',str(bits),f,str(opt)],text=True).strip())
            assert len(set(data))==1;signatures[name+'/'+str(opt)]=data[0]
    save('raw',signatures);rows={};rng=random.Random('riscv-combined-field-2325-'+flavor)
    del images['lazy']
    images['candidate_copy']=images['width']
    for name,bits in cases.items():
        def sample(k,mode,reps):
            select(k);return list(map(int,sp.check_output(['setarch',platform.machine(),'-R',t/'time',str(bits),str(mode),t/(name+'.text'),'1048576',str(reps)]).split()))
        for mode in (0,1,2):
            v=sample('base',mode,1);reps=max(1,ceil(40e6/max(1,v[0])));cycles=[];keys=list(images)
            for _ in range(17):
                rng.shuffle(keys);obs=[(k,sample(k,mode,reps))for k in keys+keys[::-1]];assert len(set(y[2]for _,y in obs))==1
                cycles.append({k:[sum(a[i]for n,a in obs if n==k)for i in (0,1)]for k in keys})
            rows[name+'/'+str(mode)]=dict(cycles=cycles,reps=reps,checksum=obs[0][1][2]);save('timings',rows)
    save('complete',dict(source=meta,mixed=mixed,cases=cases,cc=cc,clock=platform.platform(),cpu=sp.check_output(['lscpu'],text=True),fixed_inode=lib.stat().st_ino))
t=Path(tempfile.mkdtemp())
try:measure(t)
finally:
    size=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);save('cleanup',dict(bytes=size,removed=not t.exists()))
