from pathlib import Path
import hashlib,json,os,shutil,struct,subprocess as sp,tempfile
import corpus
r=Path(__file__).resolve().parent
src=r.parent/'source'
out=r.parent/'evidence'
out.mkdir()
read=lambda f:json.loads(f.read_text())
q=read(r/'tree.json')
def sha(f):return hashlib.file_digest(f.open('rb'),'sha256').hexdigest() if hasattr(hashlib,'file_digest') else hashlib.sha256(f.read_bytes()).hexdigest()
def get(*args):return sp.check_output(args,text=True).strip()
def run(*args):sp.run(args,check=True)
def save(k,z):(out/(k+'.json')).write_text(json.dumps(z,indent=2)+'\n')
def git(*args):return get('git','-C',src,*args)
assert git('rev-parse','HEAD')==q['parent'] and sha(r/'candidate.patch')==q['sha256']
t=Path(tempfile.mkdtemp())
try:
    b=t/'build';libs={};images={}
    for label in ('base','candidate'):
        if label=='candidate':
            git('apply','--index',r/'candidate.patch')
            assert git('write-tree')==q['tree']
        run('cmake','-S',src,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_PPC_SUPPORT=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_STATIC_LIBS=OFF','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF')
        run('cmake','--build',b,'--parallel','4','--target','capstone_shared')
        so,=[f for f in b.glob('libcapstone*.dylib') if not f.is_symlink()]
        libs[label]=t/(label+'.dylib')
        shutil.copy2(so,libs[label])
        images[label]=dict(sha256=sha(so),objects={str(f.relative_to(b)):sha(f) for f in b.rglob('*.c.o')})
    assert images['base']['sha256']!=images['candidate']['sha256']
    before=images['base']['objects'];after=images['candidate']['objects']
    assert set(before)==set(after) and [Path(f).name for f in before if before[f]!=after[f]]==['PPCInstPrinter.c.o']
    save('images',images)
    shutil.rmtree(b)
    driver=t/'measure';check=t/'states'
    for exe,file in ((driver,'compare.cpp'),(check,'ppc-states.cpp')):
        run('clang++','-O3','-std=c++17','-I',src/'include',r/file,'-ldl','-o',exe)
    states=get(check,libs['base'],libs['candidate'],'4096')
    assert 'for 1258240 inputs' in states
    save('states',dict(check=states))
    copy=t/'copy.dylib';shutil.copy2(libs['base'],copy);assert sha(copy)==sha(libs['base'])
    manifest=read(r/'manifest.json');row,=[x for x in manifest['inputs'] if x['name']=='ppc64el-ls']
    pkg=t/'coreutils.deb'
    run('curl','-fsSL','--retry','3','--max-time','120',row['url'],'-o',pkg)
    assert sha(pkg)==row['package_sha256']
    records={};timings={};inputs={}
    for name in ('ls','cat','sort','cp'):
        image=corpus.deb_binary(pkg,name);body=corpus.elf_text(image)
        f=t/(name+'.text');f.write_bytes(body)
        hdr=struct.unpack_from('<16sHHIQQQIHHHHHH',image)
        sections=[struct.unpack_from('<IIQQQQIIQQ',image,hdr[6]+i*hdr[11]) for i in range(hdr[12])]
        section,=[z for z in sections if z[5]==len(body) and image[z[4]:z[4]+z[5]]==body]
        ip=str(section[3]);inputs[name]=dict(text=sha(f),ip=ip,package=row['package_sha256'])
        if name=='ls':assert sha(f)==row['text_sha256']
        records[name]=json.loads(get(driver,libs['base'],libs['candidate'],'verify',f,'ppc',ip))
        for seed in range(24):
            lines=get(driver,libs['base'],copy,libs['candidate'],'paired',f,ip,str(seed+612))
            result=[list(map(int,line.split()))for line in lines.splitlines()]
            assert len(result)==18
            for m in (0,1,2):
                for api in (0,1):
                    rows=[v for v in result if v[:2]==[m,api]]
                    assert len(rows)==3 and {x[2]for x in rows}=={0,1,2} and len({tuple(x[5:])for x in rows})==1
                    key=name+'/'+('iter' if api else 'batch')+'/'+str(m)
                    timings.setdefault(key,[]).append({('base','copy','candidate')[x[2]]:x[3:]for x in rows})
        save('timings',timings);save('verified',records);save('inputs',inputs)
    cpu=get('sysctl','-n','machdep.cpu.brand_string');save('hardware',dict(cpu=cpu,compiler=get('clang','--version')))
    save('complete',dict(source=q,panels=len(timings),cpu=cpu))
finally:
    size=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t)
    save('cleanup',dict(removed=not t.exists(),bytes=size))
