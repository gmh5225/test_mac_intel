from pathlib import Path
import json,hashlib,os,platform,shutil,struct,subprocess as sp,tempfile
import corpus
r=Path(__file__).resolve().parent;s=r.parent/'source';out=r.parent/'evidence';out.mkdir(exist_ok=True);rd=lambda f:json.loads(f.read_text());q=rd(r/'stages.json');m=rd(r/'metadata.json');darwin=platform.system()=='Darwin';t=Path(tempfile.mkdtemp())
def put(n,v):(out/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def get(*a):return sp.check_output(a,text=True).strip()
def run(label,*a):
    with (out/(label+'.log')).open('w')as f:z=sp.run(a,stdout=f,stderr=sp.STDOUT)
    if z.returncode:print((out/(label+'.log')).read_text(errors='replace')[-1200:]);z.check_returncode()
def apply(k):
    get('git','-C',s,'restore','--source','HEAD','--staged','--worktree','--','.')
    if k!='base':
        assert sha(r/(k+'.patch'))==q[k]['sha256'];get('git','-C',s,'apply','--index',r/(k+'.patch'));assert get('git','-C',s,'write-tree')==q[k]['tree']
try:
    assert get('git','-C',s,'rev-parse','HEAD')==m['checkout'] and all(v['parent']==m['checkout']for v in q.values())
    arch=['X86','ARM','AARCH64','MIPS','PPC','RISCV']
    flags=['-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCMAKE_C_FLAGS=-Wno-error=incompatible-pointer-types-discards-qualifiers','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=OFF','-DCAPSTONE_BUILD_SHARED_LIBS=ON',*['-DCAPSTONE_'+a+'_SUPPORT=ON'for a in arch]]
    libs={};images={}
    for k in ('base',*q):
        apply(k);b=t/'build'
        run('cmake-'+k,'cmake','-G','Ninja','-S',s,'-B',b,*flags)
        units=['aarch64_scan','aarch64_postprocess','mapping','mcinst','sstream','text_option']
        run('build-'+k,'cmake','--build',b,'--parallel','4','--target','capstone_shared',*units)
        run('unit-'+k,'ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(units)+')$')
        lib=next(f for f in b.glob('libcapstone*')if f.is_file()and not f.is_symlink()and ('.dylib' in f.name or '.so.'in f.name))
        path=t/(k+lib.suffix);shutil.copy2(lib,path);libs[k]=path
        images[k]=dict(shared=sha(path),static=(b/'libcapstone.a').is_file(),bytes=path.stat().st_size,
                       object={a:sha(next(b.rglob(a)))for a in('cs.c.o','MipsInstPrinter.c.o','AArch64InstPrinter.c.o','X86OutputIterator.c.o','X86DisassemblerDecoder.c.o','MipsDisassembler.c.o','MipsMapping.c.o','AArch64Disassembler.c.o','AArch64Mapping.c.o')})
    for k in q:
        changes={n for n,v in images['base']['object'].items()if images[k]['object'][n]!=v}
        assert not images[k]['static'] and not images['base']['static']
        expected={'mips':{'MipsInstPrinter.c.o'},'a64':{'AArch64InstPrinter.c.o','AArch64Mapping.c.o'},'both':{'MipsInstPrinter.c.o','AArch64InstPrinter.c.o'}}[k]
        assert changes==expected,(k,changes,expected)
    assert all(images[k]['shared']!=images['base']['shared']for k in q);put('images',images)
    shutil.rmtree(b);driver=t/'measure';run('driver','clang++','-O3','-std=c++17','-I',s/'include',r/'compare.cpp','-ldl','-o',driver)
    for f in ('fetch.py','libmvec.py','libmvec.json'):shutil.copy2(r/f,t/f)
    for f in ('fetch.py','libmvec.py'):run(f,'python3','-B',t/f)
    cases={}
    for n,v in m['inputs'].items():
        f=t/('libmvec.text'if n.startswith('libmvec')else'putty-0.85-'+str(v['bits'])+'.text');assert sha(f)==v['sha256']
        cases[n]=(f,str(v['bits']),v['address'])
    manifest=rd(r/'corpus-manifest.json')
    for n,arch in [(arch+'-'+cmd,arch)for arch in ('mips64el','arm64')for cmd in ('ls','cp','sort')]:
        v,=[e for e in manifest['inputs']if e['name']==n];deb=t/(n+'.deb');run('download-'+n,'curl','-fsSL','--retry','3','--max-time','100',v['url'],'-o',deb);assert sha(deb)==v['package_sha256']
        if n=='arm64-ls':
            raw_cat=corpus.deb_binary(deb,'cat');cat=t/'arm64-cat.text';cat.write_bytes(corpus.elf_text(raw_cat))
            assert sha(cat)==rd(r/'coverage.json')['arm64-cat']['text']
            hdr=struct.unpack_from('<16sHHIQQQIHHHHHH',raw_cat);ss=[struct.unpack_from('<IIQQQQIIQQ',raw_cat,hdr[6]+j*hdr[11])for j in range(hdr[12])]
            sc,=[v for v in ss if v[5]==cat.stat().st_size and raw_cat[v[4]:v[4]+v[5]]==cat.read_bytes()]
            cases['arm64-cat']=(cat,arch,sc[3])
        raw=corpus.deb_binary(deb,v['command'],v.get('member'));body=corpus.elf_text(raw);f=t/(n+'.text');f.write_bytes(body);assert sha(f)==v['text_sha256'];deb.unlink()
        hdr=struct.unpack_from('<16sHHIQQQIHHHHHH',raw);secs=[struct.unpack_from('<IIQQQQIIQQ',raw,hdr[6]+i*hdr[11])for i in range(hdr[12])];sect,=[v for v in secs if v[5]==len(body)and raw[v[4]:v[4]+v[5]]==body]
        cases[n]=(f,arch,sect[3])
    from collections import Counter
    alias_bytes=bytearray()
    for name,v in rd(r/'coverage.json').items():
        text=cases[name][0].read_bytes();kinds=Counter()
        for (op,) in struct.iter_unpack('<I',text):
            prefix=op&0xffc00000
            if prefix not in (0x13000000,0x93400000,0x53000000,0xd3400000):continue
            wide=bool(op>>31);signed=not bool(op&(1<<30));limit=63 if wide else 31
            immr=(op>>16)&63;imms=(op>>10)&63
            if immr>limit or imms>limit:continue
            if immr==0 and imms in (7,15) and (signed or not wide):
                alias=('s' if signed else 'u')+'xt'+('b' if imms==7 else 'h')
            elif not immr and imms==31 and wide and signed:alias='sxtw'
            elif not signed and imms!=limit and imms+1==immr:alias='lsl'
            elif imms==limit:alias='asr' if signed else 'lsr'
            else:continue
            kinds[alias]+=1;alias_bytes.extend(struct.pack('<I',op))
        assert dict(kinds)==v['forms']
    assert len(alias_bytes)==382*4
    alias_path=t/'aliases.text';alias_path.write_bytes(alias_bytes);cases['arm64-alias-records']=(alias_path,'arm64',4096)
    put('inputs',{n:dict(hash=sha(f),arch=arch,ip=ip,bytes=f.stat().st_size)for n,(f,arch,ip) in cases.items()})
    verify={}
    for k in q:
        args=[driver,libs['base'],libs[k]];snapshot=verify[k]={}
        snapshot['options']=json.loads(get(*args,'options'))
        dest=t/(k+'-foreign.json')
        with (t/'foreign-output').open('wb')as log:sp.run([*args,'foreign',dest],check=True,stdout=log)
        messages=(t/'foreign-output').read_bytes().splitlines()
        from collections import Counter
        observed=Counter(a.decode()for a in messages)
        snapshot['foreign']=rd(dest)
        snapshot['foreign']['diagnostics']=dict(observed)
        assert snapshot['foreign']['records']==917504 and snapshot['foreign']['accepted']>0
        if k!=next(iter(q)):assert snapshot['foreign']==verify[next(iter(q))]['foreign']
        for n,(f,arch,ip) in cases.items():snapshot[n]=json.loads(get(*args,'verify',f,arch,str(ip)))
        put('verified',verify)
    if not darwin:os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    launch=[]if darwin else['setarch',platform.machine(),'-R'];timings={}
    import random,math
    image=t/('timed.dylib' if darwin else 'timed.so')
    images={k:f.read_bytes()for k,f in libs.items()};maxlen=max(map(len,images.values()))
    if not darwin:
        # Every process maps the same pathname, inode, length and load base.
        loads={};spans={}
        for k,v in images.items():
            assert v[:6]==bytes((127,69,76,70,2,1))
            phoff=struct.unpack_from('<Q',v,32)[0];ent,num=struct.unpack_from('<HH',v,54)
            last=max((struct.unpack_from('<IIQQQQQQ',v,pos)[3],pos)for pos in range(phoff,phoff+ent*num,ent)if struct.unpack_from('<I',v,pos)[0]==1)[1]
            pva,psize=struct.unpack_from('<Q',v,last+16)[0],struct.unpack_from('<Q',v,last+40)[0]
            loads[k]=(last,pva,psize);spans[k]=(pva+psize+4095)//4096
        data={};pad={}
        for k,v in images.items():
            buf=bytearray(v+bytes(maxlen-len(v)));off,va,sz=loads[k]
            extra=(max(spans.values())-spans[k])*4096
            if extra:struct.pack_into('<Q',buf,off+40,sz+extra)
            data[k]=buf;pad[k]=extra
        put('load-spans',dict(pages=spans,extra_zero_fill=pad))
        image.write_bytes(data['base']);image.chmod(0o755)
    curr=None;addresses={};offsets={}
    def take(stage,args,reps):
        global curr
        src='base'if stage=='copy'else stage
        if src!=curr:
            if darwin:
                if image.is_symlink():image.unlink()
                image.symlink_to(libs[src])
            else:
                with image.open('r+b')as out_file:assert out_file.write(data[src])==maxlen
            curr=src
        vals=list(map(int,get(*launch,driver,image,'single',*args,str(reps)).split()))
        assert len(vals)==6 and min(vals[0:3])>0
        addresses.setdefault(src,set()).add(vals[4]);assert offsets.setdefault(src,vals[5])==vals[5]
        if not darwin:assert len(set.union(*addresses.values()))==1,addresses
        return vals[:4]
    for n,(f,arch,ip) in cases.items():
        for mode in (0,1,2):
            for api in ('time','iter'):
                key='/'.join((n,api,str(mode)));args=[f,arch,str(ip),api,str(mode)]
                t0=take('base',args,1);reps=max(1,math.ceil(35e6/t0[0]));cycles=[];keys=['base','copy',*q];rng=random.Random(key)
                for _ in range(17):
                    rng.shuffle(keys);obs=[(k,take(k,args,reps))for k in keys+keys[::-1]]
                    assert all(v[2:]==t0[2:]for k,v in obs)
                    cycles.append({k:[sum(o[i]for l,o in obs if k==l)for i in (0,1)]for k in keys})
                timings[key]=dict(cycles=cycles,reps=reps,records=t0[2],value=t0[3]);put('timings',timings)
        put('mappings',dict(sets={k:sorted(v)for k,v in addresses.items()},offsets=offsets,fixed=not darwin,inode=image.stat().st_ino if not darwin else None))
    put('complete',dict(source=q,panels=len(timings),compiler=get('clang','--version'),cpu=get('sysctl','-n','machdep.cpu.brand_string')if darwin else get('lscpu')))
finally:
    size=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);put('cleanup',dict(removed=not t.exists(),bytes=size))
