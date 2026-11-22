from pathlib import Path
import hashlib,json,os,platform,shutil,statistics,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;root=r.parent;s=root/'source';obs=root/'evidence';obs.mkdir(exist_ok=True)
def write(f,x):(obs/(f+'.json')).write_text(json.dumps(x,indent=2)+'\n')
def run(args,name,cwd=None):
    with (obs/(name+'.log')).open('w') as f:sp.run(args,cwd=cwd,stdout=f,stderr=sp.STDOUT,check=True)
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
meta=json.loads((r/'tree.json').read_text())
git=lambda *a:sp.check_output(['git','-C',s,*a],text=True).strip()
assert git('rev-parse','HEAD')==meta['parent'] and sha(r/'candidate.patch')==meta['sha256']
units=['x86_scan_batch','x86_evex_vpcmp_id','x86_evex_vpcmp_mask_size','x86_evex_detail','x86_buffer_bounds','x86_simple_output','text_option','detail_option','x86_kmask_width']
conf=os.environ.get('FLAVOR','full');cc=os.environ['CC'];diet=conf=='diet';reduce=conf=='reduce';att=conf!='intel'
tmp=Path(tempfile.mkdtemp());b=tmp/'build';fixed=tmp/'selected';fixed.mkdir()
try:
    opts=['-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers')]
    if conf=='full':opts.extend('-DCAPSTONE_'+arch+'_SUPPORT=ON' for arch in ('ARM','AARCH64','MIPS','RISCV','PPC'))
    if diet:opts.append('-DCAPSTONE_BUILD_DIET=ON')
    if reduce:opts.append('-DCAPSTONE_X86_REDUCE=ON')
    if not att:opts.append('-DCAPSTONE_X86_ATT_DISABLE=ON')
    run(['cmake','-S',s,'-B',b,*opts],'configure');libs={}
    objects={}
    for variant in ('base','candidate'):
        if variant=='candidate':
            git('apply','--index',str(r/'candidate.patch'));assert git('write-tree')==meta['tree']
        run(['cmake','--build',b,'--parallel','4','--target','capstone_shared'],'build-'+variant)
        path=next(f for f in b.glob('libcapstone.so.*') if not f.is_symlink())
        libs[variant]=tmp/(variant+'.so');shutil.copy2(path,libs[variant])
        objects[variant]={str(p.relative_to(b)):sha(p)for p in (b/'CMakeFiles/capstone.dir').rglob('*.o')}
    changed=[k for k,v in objects['base'].items()if v!=objects['candidate'][k]]
    assert len(objects['base'])>5 and objects['base'].keys()==objects['candidate'].keys() and ([Path(k).name for k in changed]==['RISCVDisassembler.c.o'] if conf=='full' else not changed)
    write('member-changes',dict(changed=changed,total=len(objects['base'])))
    if reduce:panels=[]
    else:panels=[('matrix32',32,'matrix',0),('matrix64',64,'matrix',0)]
    if conf=='full':
        shutil.copy(r/'extract.py',tmp);shutil.copy(r/'fetch.py',tmp)
        run(['python3','-B',tmp/'extract.py'],'debian');run(['python3','-B',tmp/'fetch.py'],'putty')
        for n in (32,64):
            panels.append(('putty'+str(n),n,tmp/('putty-0.85-'+str(n)+'.text'),0x401000 if n==32 else 0x140001000))
        panels.append(('openssl',64,tmp/'libcrypto.text',json.loads((tmp/'openssl.json').read_text())['address']))
    if conf=='full':
        shutil.copy(r/'libmvec.py',tmp);shutil.copy(r/'libmvec.json',tmp)
        run(['python3','-B',tmp/'libmvec.py'],'glibc-libmvec')
        libm=json.loads((tmp/'libmvec.json').read_text());panels.append(('libmvec',64,tmp/'libmvec.text',libm['address']))
    other_cases=[]
    if conf=='full':
        import corpus
        raw=corpus.prepare(r,tmp,obs,run)
        names={'arm-cp','arm64-ls','mips64el-ls','ppc64el-ls','riscv64-ls','riscv64-cp','riscv64-sort'}
        maps={'arm-cp':101,'arm64-ls':102,'mips64el-ls':103,'ppc64el-ls':104,'riscv64-ls':105,'riscv64-cp':105,'riscv64-sort':105}
        other_cases=[(c['name'],maps[c['name']],Path(c['path']),0x100000) for c in raw if c['name'] in names]
        assert len(other_cases)==len(names)
        target=fixed/'libcapstone.so.6'
        target.write_bytes(libs['base'].read_bytes());(fixed/'libcapstone.so').symlink_to(target.name)
        run(['c++','-O3','-std=c++17','-I',s/'include',r/'time.cpp','-L',fixed,'-Wl,-rpath,'+str(fixed),'-lcapstone','-o',tmp/'time'],'compile-time')
        bind=['setarch',platform.machine(),'-R'];sp.run([*bind,'/bin/true'],check=True)
        os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
        inputs={k:v.read_bytes() for k,v in libs.items()};inputs['copy']=inputs['base']
        size=max(map(len,inputs.values()));inputs={k:v+bytes(size-len(v)) for k,v in inputs.items()}
        def invoke(k,bits,mode,path,ip,reps):
            with target.open('wb') as o:o.write(inputs[k])
            return list(map(int,sp.check_output([*bind,tmp/'time',str(bits),str(mode),path,str(ip),str(reps)],text=True).split()))
        timing=[]
        for name,bits,path,ip in panels[2:]+other_cases:
            if name not in {'putty32','putty64','libmvec','ppc64el-ls','riscv64-ls','riscv64-cp','riscv64-sort'}:continue
            for mode in ((2,3) if bits in (32,64) else (0,1,2)):
                first=invoke('base',bits,mode,path,ip,1);n=max(1,round(85e6/first[0]));cycles=[]
                for i in range(25):
                    keys=['base','copy','candidate'];o=keys[i%3:]+keys[:i%3];cyc={k:[] for k in keys}
                    for k in o+o[::-1]:
                        v=invoke(k,bits,mode,path,ip,n);assert v[2]==first[2];cyc[k].append(v[:2])
                    cycles.append(cyc)
                timing.append(dict(sample=name,mode=mode,cycles=cycles,check=first[2],reps=n))
                write('timings',timing)
    if cc=='clang' and platform.machine()=='x86_64':
        run(['python3','-B',r/'identity.py'],'shipping-identity')
    write('complete',dict(source=meta,panels=len(timing),compiler=sp.check_output([cc,'--version'],text=True),host=platform.platform(),arch=platform.machine()))
finally:
    size=sum(f.stat().st_size for f in tmp.rglob('*') if f.is_file());shutil.rmtree(tmp);write('cleanup',dict(bytes=size,removed=not tmp.exists()))
