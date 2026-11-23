from pathlib import Path
import hashlib,json,os,platform,random,shutil,statistics,subprocess as sp,tempfile
import corpus
d=Path(__file__).resolve().parent;s=d.parent/'source';out=d.parent/'evidence';out.mkdir(exist_ok=True)
meta=json.loads((d/'tree.json').read_text());cc=os.environ['CC'];t=Path(tempfile.mkdtemp());mixed=('ARM','AARCH64','MIPS','RISCV','PPC','SYSTEMZ','LOONGARCH','SPARC','XTENSA','X86')
def save(k,data):(out/(k+'.json')).write_text(json.dumps(data,indent=2)+'\n')
def cmd(n,args):
    with (out/(n+'.log')).open('w')as f:z=sp.run(args,stdout=f,stderr=sp.STDOUT)
    if z.returncode:print((out/(n+'.log')).read_text(errors='replace')[-2000:]);z.check_returncode()
def g(*args):return sp.check_output(['git','-C',s,*args],text=True).strip()
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
assert g('rev-parse','HEAD')==meta['parent']
try:
    images={};profiles={}
    for profile,architectures in [('mixed',mixed),('diet',['LOONGARCH']),('pure',['LOONGARCH'])]:
        b=t/profile;variants={}
        for k in ('base','candidate'):
            g('restore','--source','HEAD','--staged','--worktree','--','.')
            if k=='candidate':
                assert sha(d/'candidate.patch')==meta['sha256'];g('apply','--index',str(d/'candidate.patch'));assert g('write-tree')==meta['tree']
            config=['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),*['-DCAPSTONE_'+a+'_SUPPORT=ON'for a in architectures]]
            if profile=='diet':config.append('-DCAPSTONE_BUILD_DIET=ON')
            cmd(profile+'-config-'+k,config)
            cmd(profile+'-build-'+k,['cmake','--build',b,'--parallel','4','--target','capstone_static','capstone_shared',*(['register_descriptors']if profile!='diet'else [])])
            if profile!='diet':cmd(profile+'-test-'+k,['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_register_descriptors$'])
            so,=[f for f in b.glob('libcapstone.so.*')if not f.is_symlink()]
            variants[k]=dict(shared=sha(so),objects={str(f.relative_to(b)):sha(f)for f in b.rglob('*.c.o')},archive=sha(b/'libcapstone.a'))
            if profile=='pure':
                images[k]=so.read_bytes()
                source=s/'arch/LoongArch/LoongArchInstPrinter.c';observed=t/'printer.c';observed.write_text(source.read_text()+'\nvoid observed_loong_name(MCInst *m,SStream *o,MCRegister reg){printRegName(m,o,reg);}\n')
                flags=['-DNDEBUG','-O2','-DCAPSTONE_HAS_LOONGARCH','-DCAPSTONE_USE_SYS_DYN_MEM','-DCAPSTONE_LOONGARCH_DEDICATED_MAPPING','-I',s,'-I',s/'arch/LoongArch','-I',s/'include']
                cmd('spans-build-'+k,[cc,*flags,observed,d/'loong-streams.c',b/'libcapstone.a','-o',t/'spans'])
                assert int(sp.check_output([t/'spans']))==28160
                if k=='candidate':
                    cmd('emit',[cc,'-O2',s/'suite/synctools/loongarch_register_spellings.c',b/'libcapstone.a','-o',t/'emit'])
                    assert sp.check_output([t/'emit'])==(s/'arch/LoongArch/LoongArchGenRegisterSpellings.inc').read_bytes()
        a,bv=variants['base'],variants['candidate'];assert a['objects'].keys()==bv['objects'].keys()
        changed=[p for p in a['objects']if a['objects'][p]!=bv['objects'][p]]
        if profile=='pure':assert len(changed)==1 and changed[0].endswith('/LoongArchInstPrinter.c.o'),changed
        else:assert a==bv,(profile,changed,a['shared'],bv['shared'])
        profiles[profile]=dict(changed=changed,variants=variants)
    save('profiles',profiles)
    # The package digest binds every extracted member. Check the established ls digest as well.
    manifest=json.loads((d/'manifest.json').read_text());ls,=[x for x in manifest['inputs']if x['name']=='loong64-ls']
    pkg=t/'coreutils.deb';cmd('download',['curl','--retry','2','-fsSL',ls['url'],'-o',pkg]);assert sha(pkg)==ls['package_sha256']
    samples={}
    for name in ('ls','cat','sort','cp'):
        binary=corpus.deb_binary(pkg,name);data=corpus.elf_text(binary);f=t/(name+'.text');f.write_bytes(data)
        samples[name]=dict(package_sha256=sha(pkg),elf_sha256=hashlib.sha256(binary).hexdigest(),section_sha256=sha(f),bytes=len(data));assert len(data)>1024 and len(data)%4==0
    assert samples['ls']['section_sha256']==ls['text_sha256'];save('samples',samples)
    sz=max(map(len,images.values()));images={k:v+bytes(sz-len(v))for k,v in images.items()};images['aa']=images['base']
    slot=t/'fixed';slot.mkdir();target=slot/'libcapstone.so.6';target.write_bytes(images['base']);(slot/'libcapstone.so').symlink_to(target.name)
    for name,src in [('time','time.cpp'),('raw','raw.cpp')]:cmd('compile-'+name,['c++','-std=c++17','-O3','-I',s/'include',d/src,'-L',slot,'-Wl,-rpath,'+str(slot),'-lcapstone','-o',t/name])
    signatures={}
    for name in samples:
        for opt in range(5):
            observed=[]
            for k in ('base','candidate'):
                target.write_bytes(images[k]);observed.append(list(map(int,sp.check_output([t/'raw','108',t/(name+'.text'),str(opt)]).split())))
            assert observed[0]==observed[1] and observed[0][0]>0
            signatures[name+'/'+str(opt)]=observed[0]
    save('raw',signatures);rng=random.Random(2044);rows=[];os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    def sample(k,name,mode,n):
        target.write_bytes(images[k]);return list(map(int,sp.check_output(['setarch',platform.machine(),'-R',t/'time','108',str(mode),t/(name+'.text'),'1048576',str(n)]).split()))
    for name in samples:
        for mode in range(3):
            one=sample('base',name,mode,1);n=max(1,round(65e6/one[0]));cycles=[]
            for _ in range(17):
                keys=list(images);rng.shuffle(keys);observed={k:[]for k in keys}
                for k in keys+keys[::-1]:
                    v=sample(k,name,mode,n);assert v[2]==one[2];observed[k].append(v[0])
                cycles.append(observed)
            rows.append(dict(case=name,mode=mode,pairs=cycles))
    save('timings',rows);save('complete',dict(done=True,source=meta,cc=cc,host=platform.machine(),platform=platform.platform(),tests=20,spans=28160,panels=len(rows)))
finally:
    amount=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=amount))
