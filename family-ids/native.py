from pathlib import Path
from statistics import median
from math import ceil
import hashlib, json, os, platform, random, shutil, subprocess as sp, tempfile
import corpus, shlex
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
        return ['cmake','-S',source,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCMAKE_C_COMPILER='+cc,'-DCMAKE_C_FLAGS='+flags+' -fstack-usage','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF',*['-DCAPSTONE_'+n+'_SUPPORT=ON' for n in arch],*extra]
    arches=['RISCV']+(['ARM','AARCH64','MIPS','X86']if mixed else [])
    info={};libs={};units=checks['tests']
    for profile,arch,extra in [('full',arches,[]),('diet',['RISCV'],['-DCAPSTONE_BUILD_DIET=ON']),('neverd',['ARM','AARCH64','MIPS','X86'],[])]:
        b=t/profile;variants={}
        for k in (('base','original','lazy','width') if profile=='full' else ('base','width')):
            git('restore','--source','HEAD','--worktree','--staged','--','.')
            if k!='base':
                patch=r/(k+'.patch');assert sha(patch)==stages[k]['sha256'];git('apply','--index',str(patch));assert git('write-tree')==stages[k]['tree']
            run(profile+k+'-config',config(b,arch,extra))
            if profile=='full' and k=='width':run('alias-projection',['python3','-B',source/'suite/synctools/alias_pattern_rows.py','--check'])
            run(profile+k+'-build',['cmake','--build',b,'--parallel','4','--target','capstone_shared','capstone_static',*(units if profile=='full' else [])])
            if profile=='full':run(profile+k+'-test',['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_riscv_'])
            files={str(f.relative_to(b)):sha(f) for f in b.rglob('*.c.o') if '/tests/' not in str(f)}
            so,=[v for v in b.glob('libcapstone.so.*')if not v.is_symlink()]
            variants[k]=dict(so=sha(so),archive=sha(b/'libcapstone.a'),objects=files)
            if profile=='full':libs[k]=t/(k+'.so');shutil.copy2(so,libs[k])
            if profile=='full':
                obj,=b.rglob('RISCVInstPrinter.c.o')
                if k=='base':
                    shutil.copy2(b/'libcapstone.a',t/'baseline.a')
                    item=next(row for row in rd(b/'compile_commands.json') if row['file'].endswith('/RISCVModule.c'))
                    argv=shlex.split(item['command']);argv.extend(['-I',str(source)]);argv[argv.index('-o')+1]=str(t/'select.o');argv[argv.index('-c')+1]=str(r/'select.c')
                    run('compile-selector',argv)
                renamed='copy' if k=='base' else k
                nm=sp.check_output(['nm','--defined-only','--extern-only',obj],text=True).splitlines()
                names=[line.split()[-1] for line in nm if len(line.split())==3]
                assert 'RISCV_LLVM_printInstruction' in names
                symbols=t/(renamed+'.txt');symbols.write_text(''.join(n+' '+renamed+'_'+n+chr(10) for n in names))
                run('rename-'+renamed,['objcopy','--redefine-syms='+str(symbols),obj,t/(renamed+'.o')])
                functions={}
                for line in sp.check_output(['nm','-n','-S',so],text=True).splitlines():
                    cols=line.split()
                    if len(cols)==4 and (cols[3].startswith('RISCV_') or cols[3] in ('cs_disasm_iter','printOperandForms','printCompressedOperandForms','cs_decode_full_insn')):
                        functions[cols[3]]=[int(cols[0],16),int(cols[1],16)]
                assert all(n in functions for n in ('cs_disasm_iter','RISCV_LLVM_getInstruction','RISCV_LLVM_printInstruction'))
                su={}
                for f in obj.parent.glob('*.su'):
                    if 'RISCVInstPrinter' in f.name:
                        for line in f.read_text().splitlines():
                            cols=line.split(chr(9))
                            if len(cols)>=2:
                                n=cols[0].split(':')[-1].split('.')[0]
                                if n in ('RISCV_LLVM_printInstruction','printOperandForms','printCompressedOperandForms','uncompressInst'):su[n]=int(cols[1])
                assert 'RISCV_LLVM_printInstruction' in su
                if k=='width': assert 'printCompressedOperandForms' in su,su
                save('layout-'+k,dict(built=functions,stack=su))

        if profile=='neverd':assert variants['base']==variants['width']
        else:
            for k,row in variants.items():
                assert set(row['objects'])==set(variants['base']['objects'])
                changed=[f for f,v in row['objects'].items() if v!=variants['base']['objects'][f]]
                assert all(f.endswith('/arch/RISCV/RISCVInstPrinter.c.o')for f in changed),changed
                if profile=='full':assert len(changed)==int(k in ('original','width')),(k,changed)
            if profile=='full':
                assert variants['base']['objects']==variants['lazy']['objects'] and variants['width']['objects']==variants['original']['objects']
                fast=('RISCV_LLVM_getInstruction','RISCV_getInstruction','RISCV_get_insn_id','cs_disasm_iter')
                layout={k:rd(out/('layout-'+k+'.json'))['built']for k in variants}
                save('decoder-addresses',{n:{k:layout[k][n] for k in layout} for n in fast})
        info[profile]=variants;shutil.rmtree(b)
    save('profiles',info)
    for k in ('lazy','width'):
        proof=list(map(int,sp.check_output([t/'guard',libs['base'],libs[k]]).split()))
        assert proof[0]==checks['guards'][k][0] and all(proof);save('guard-'+k,proof)
    lib=t/'libcapstone.so.6';(t/'libcapstone.so').symlink_to(lib.name)
    images={k:f.read_bytes() for k,f in libs.items()};length=max(map(len,images.values()));images={k:v+bytes(length-len(v))for k,v in images.items()};images['copy']=images['base'];lib.write_bytes(images['base'])
    for f in ('time','raw'):run(f,['c++','-O3','-std=c++17','-I',source/'include',r/(f+'.cpp'),'-L',t,'-Wl,-rpath,'+str(t),'-lcapstone','-o',t/f])
    run('fixed-image-link',['c++','-O3','-std=c++17','-I',source/'include',r/'time.cpp',t/'select.o',*[t/(k+'.o')for k in ('copy','lazy','width')],t/'baseline.a','-Wl,--wrap=cs_open','-o',t/'fixed'])
    fixed_syms={}
    for line in sp.check_output(['nm','-n','-S',t/'fixed'],text=True).splitlines():
        cols=line.split()
        if len(cols)==4 and (cols[3].endswith('RISCV_LLVM_printInstruction') or cols[3] in ('cs_disasm_iter','RISCV_LLVM_getInstruction')):
            fixed_syms[cols[3]]=[int(cols[0],16),int(cols[1],16)]
    assert len(fixed_syms)==6
    save('fixed-image',dict(sha=sha(t/'fixed'),symbols=fixed_syms))
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    run('fixed',['setarch',platform.machine(),'-R','true'])
    current=None
    def select(k):
        nonlocal current
        if current!=k:
            with lib.open('r+b')as f:assert f.write(images[k])==length
            current=k
    signatures={}
    for name,bits in cases.items():
        f=t/(name+'.text')
        for opt in range(5):
            data=[]
            for k in libs:
                select(k);data.append(sp.check_output([t/'raw',str(bits),f,str(opt)],text=True).strip())
            assert len(set(data))==1;signatures[name+'/'+str(opt)]=data[0]
    save('raw',signatures);rows={};rng=random.Random('RISCV-2260-'+flavor)
    for name,bits in cases.items():
        def sample(k,mode,reps):
            select(k);return list(map(int,sp.check_output(['setarch',platform.machine(),'-R',t/'time',str(bits),str(mode),t/(name+'.text'),'1048576',str(reps)]).split()))
        for mode in (0,1,2):
            v=sample('base',mode,1);reps=max(1,ceil(40e6/max(1,v[0])));cycles=[];keys=list(images)
            for _ in range(17):
                rng.shuffle(keys);obs=[(k,sample(k,mode,reps))for k in keys+keys[::-1]];assert len(set(y[2]for _,y in obs))==1
                cycles.append({k:[sum(a[i]for n,a in obs if n==k)for i in (0,1)]for k in keys})
            rows[name+'/'+str(mode)]=dict(cycles=cycles,reps=reps,checksum=obs[0][1][2]);save('timings',rows)
    paired={};selectors=dict(base='0',copy='1',lazy='2',width='3')
    for name,bits in cases.items():
        def fixed(k,mode,reps):
            env=dict(os.environ,RV_PRINTER=selectors[k])
            return list(map(int,sp.check_output(['setarch',platform.machine(),'-R',t/'fixed',str(bits),str(mode),t/(name+'.text'),'1048576',str(reps)],env=env).split()))
        for mode in (0,1,2):
            v=fixed('base',mode,1);assert v[2]==rows[name+'/'+str(mode)]['checksum']
            reps=max(1,ceil(32e6/max(1,v[0])));cycles=[];keys=list(selectors)
            for _ in range(17):
                rng.shuffle(keys);obs=[(k,fixed(k,mode,reps))for k in keys+keys[::-1]];assert all(y[2]==v[2] for _,y in obs)
                cycles.append({k:[sum(a[i]for n,a in obs if n==k)for i in (0,1)]for k in keys})
            paired[name+'/'+str(mode)]=dict(cycles=cycles,reps=reps,checksum=v[2]);save('fixed-timings',paired)
    save('complete',dict(source=meta,mixed=mixed,cases=cases,cc=cc,clock=platform.platform(),cpu=sp.check_output(['lscpu'],text=True),fixed_inode=lib.stat().st_ino))
t=Path(tempfile.mkdtemp())
try:measure(t)
finally:
    size=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);save('cleanup',dict(bytes=size,removed=not t.exists()))
