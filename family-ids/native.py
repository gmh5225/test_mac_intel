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
assert g('rev-parse','HEAD')==meta['parent'];baseline=g('rev-parse','HEAD^{tree}')

try:
    images={};profiles={}
    cmd('guard-link',['c++','-O2','-std=c++17','-I',s/'include',d/'guard.cpp','-ldl','-o',t/'guard'])
    for profile,architectures in [('mixed',mixed),('diet',['MIPS']),('systemz',['SYSTEMZ']),('loongarch',['LOONGARCH']),('sparc',['SPARC']),('pure',['MIPS'])]:
        b=t/profile;variants={}
        for k in ('base','storage','candidate'):
            g('restore','--source',baseline,'--staged','--worktree','--','.')
            if k!='base':
                target=meta if k=='candidate' else json.loads((d/'active-tree.json').read_text())
                patch=d/(k+'.patch');assert sha(patch)==target['sha256'];g('apply','--index',str(patch));assert g('write-tree')==target['tree']
            config=['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),*['-DCAPSTONE_'+a+'_SUPPORT=ON'for a in architectures]]
            if profile=='diet':config.append('-DCAPSTONE_BUILD_DIET=ON')
            cmd(profile+'-config-'+k,config)
            cmd(profile+'-build-'+k,['cmake','--build',b,'--parallel','4','--target','capstone_static','capstone_shared',*((['register_descriptors','mcinst','mips_scan','mips_single'] if profile=='pure' else ['register_descriptors','mcinst'])if profile!='diet'else [])])
            if profile!='diet':cmd(profile+'-test-'+k,['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_(register_descriptors|mcinst|mips_scan|mips_single)$' if profile=='pure' else '^unit_(register_descriptors|mcinst)$'])
            so,=[f for f in b.glob('libcapstone.so.*')if not f.is_symlink()]
            variants[k]=dict(shared=sha(so),objects={str(f.relative_to(b/'CMakeFiles/capstone.dir')):sha(f)for f in (b/'CMakeFiles/capstone.dir').rglob('*.c.o')},archive=sha(b/'libcapstone.a'))
            target=t/(profile+'-'+k+'.so');shutil.copy2(so,target)
            if k!='base' and profile not in ('systemz','loongarch','sparc'):
                cmd('boundary-'+profile+'-'+k,[t/'guard',t/(profile+'-base.so'),target])
                modes,trials,accepted=map(int,(out/('boundary-'+profile+'-'+k+'.log')).read_text().split())
                assert modes==44 and trials==114688*modes and accepted>0
            if profile=='pure':
                images[k]=so.read_bytes()
                cmd('symbols-'+k,['nm','-S','-n','--defined-only',so])
                for sym in ('cs_decode_full_insn','cs_disasm_iter','Mips_printer'):
                    cmd('code-'+k+'-'+sym,['objdump','-d','--disassemble='+sym,so])
                cmd('callback-build-'+k,['c++','-std=c++17','-O2','-I',s/'include',d/'callback.cpp','-ldl','-o',t/'callbacks'])
                if k!='base':cmd('callbacks-'+k,[t/'callbacks',t/'pure-base.so',target])
                if k=='candidate':
                    original=(s/'cs.c').read_text();line="if (known_length) {\n\t\t\t\tss.buffer[0] = '\\0';";assert original.count(line)==1
                    for pattern in (0xa5,0x5a):
                        test=line+' memset(ss.buffer + 1, '+str(pattern)+', sizeof(ss.buffer) - 1);'
                        (s/'cs.c').write_text(original.replace(line,test))
                        cmd('poison-build-'+str(pattern),['cmake','--build',b,'--parallel','4','--target','capstone_shared'])
                        cmd('poison-boundary-'+str(pattern),[t/'guard',t/'pure-base.so',so])
                        cmd('poison-callbacks-'+str(pattern),[t/'callbacks',t/'pure-base.so',so])
                        shutil.copy2(so,t/('poison-'+str(pattern)+'.so'))
                    (s/'cs.c').write_text(original)
        a,bv=variants['storage'],variants['candidate'];assert a['objects'].keys()==bv['objects'].keys()
        changed=[p for p in a['objects']if a['objects'][p]!=bv['objects'][p]]
        if profile=='pure':
            for name in ('storage','candidate'):
                diff=[f for f,v in variants['base']['objects'].items() if variants[name]['objects'][f]!=v]
                assert diff==['cs.c.o'],(profile,name,diff)
        else:
            assert variants['base']==variants['storage']==variants['candidate'],profile

        profiles[profile]=dict(changed=changed,variants=variants)
    save('profiles',profiles)
    # The package digest binds every extracted member. Check the established ls digest as well.
    manifest=json.loads((d/'manifest.json').read_text());ls,=[x for x in manifest['inputs']if x['name']=='mips64el-ls']
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
            for k in ('base','storage','candidate'):
                target.write_bytes(images[k]);observed.append(list(map(int,sp.check_output([t/'raw','103',t/(name+'.text'),str(opt)]).split())))
            assert observed[0]==observed[1]==observed[2] and observed[0][0]>0
            for pattern in (0xa5,0x5a):
                img=(t/('poison-'+str(pattern)+'.so')).read_bytes()
                target.write_bytes(img)
                result=list(map(int,sp.check_output([t/'raw','103',t/(name+'.text'),str(opt)]).split()))
                assert result==observed[0]
            signatures[name+'/'+str(opt)]=observed[0]
    save('raw',signatures);rng=random.Random(2044);rows=[];os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    def sample(k,name,mode,n):
        target.write_bytes(images[k]);return list(map(int,sp.check_output(['setarch',platform.machine(),'-R',t/'time','103',str(mode),t/(name+'.text'),'1048576',str(n)]).split()))
    for name in samples:
        for mode in range(3):
            one=sample('base',name,mode,1);n=max(1,round(65e6/one[0]));cycles=[]
            for _ in range(17):
                keys=list(images);rng.shuffle(keys);observed={k:[]for k in keys}
                for k in keys+keys[::-1]:
                    v=sample(k,name,mode,n);assert v[2]==one[2];observed[k].append(v[0])
                cycles.append(observed)
            rows.append(dict(case=name,mode=mode,pairs=cycles))
    save('timings',rows);save('complete',dict(done=True,source=meta,cc=cc,host=platform.machine(),platform=platform.platform(),tests=20,poison_patterns=[165,90],callbacks=192,panels=len(rows)))
finally:
    amount=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=amount))
