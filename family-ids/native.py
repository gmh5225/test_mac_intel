from pathlib import Path
import hashlib, json, os, platform, random, re, shutil, subprocess as sp, tempfile
from corpus import deb_binary, elf_text

r = Path(__file__).resolve().parent
source = r.parent / 'source'
out = r.parent / 'evidence'
out.mkdir()
def put(name, data):
    (out / (name+'.json')).write_text(json.dumps(data, indent=2)+'\n')
def sha(data):
    return hashlib.sha256(data).hexdigest()
def run(args, name):
    with (out / (name+'.log')).open('wb') as log:
        sp.run(args, check=True, stdout=log, stderr=sp.STDOUT)
def git(*args):
    return sp.check_output(['git','-C',source,*args],text=True).strip()

meta = json.loads((r/'tree.json').read_text())
assert git('rev-parse','HEAD')==meta['parent'] and sha((r/'candidate.patch').read_bytes())==meta['sha256']
tmp=Path(tempfile.mkdtemp())
try:
    manifest=json.loads((r/'arm64.json').read_text())
    corpus={}
    for item in manifest:
        package=tmp/item['package_sha256']
        if not package.exists():
            run(['curl','-fsSL','--retry','3','--max-time','120',item['url'],'-o',package],'download-'+item['package_sha256'][:8])
        assert sha(package.read_bytes())==item['package_sha256']
        binary=deb_binary(package,item.get('command',''),item.get('member'))
        raw=elf_text(binary)
        if item.get('text_sha256'): assert sha(raw)==item['text_sha256']
        file=tmp/(item['name']+'.text')
        file.write_bytes(raw)
        corpus[item['name']]={'package':package.name,'text':sha(raw),'binary':sha(binary),'bytes':len(raw)}
    put('corpus',corpus)
    build=tmp/'build'
    cc=os.environ['CC']
    run(['cmake','-S',source,'-B',build,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_AARCH64_SUPPORT=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF'],'configure')
    images={};objects={}
    for label in ('base','candidate'):
        if label=='candidate':
            git('apply','--index',str(r/'candidate.patch'))
            assert git('write-tree')==meta['tree']
        run(['cmake','--build',build,'--parallel','4','--target','capstone_shared','aarch64_postprocess','aarch64_scan'],'build-'+label)
        run(['ctest','--test-dir',build,'--no-tests=error','--output-on-failure','-R','^unit_aarch64_'],'units-'+label)
        assert re.search(r'0 tests failed out of 5\b',(out/('units-'+label+'.log')).read_text())
        so,=(f for f in build.glob('libcapstone.so.*') if not f.is_symlink())
        images[label]=so.read_bytes()
        objects[label]={str(f.relative_to(build)):sha(f.read_bytes()) for f in build.glob('CMakeFiles/capstone*.dir/**/*.c.o')}
        (tmp/(label+'.so')).write_bytes(images[label])
    old,new=objects.values()
    changes=[f for f in old if old[f]!=new[f]]
    assert len(old)>4 and old.keys()==new.keys() and len(changes)==1 and changes[0].endswith('AArch64Mapping.c.o')
    put('objects',objects)
    run(['c++','-O2','-std=c++17','-I',source/'include','-I',source,r/'aarch64-states.cpp','-ldl','-o',tmp/'states'],'compile-state')
    run([tmp/'states',tmp/'base.so',tmp/'candidate.so',*[tmp/(name+'.text') for name in corpus]],'public-state')
    public=(out/'public-state.log').read_text()
    assert '16777216 inputs' in public and len(re.findall(r'equal real AArch64 records for \d+ inputs',public))==len(corpus)
    images['copy']=images['base']
    fixed=tmp/'fixed';fixed.mkdir()
    dest=fixed/'libcapstone.so.6'
    dest.write_bytes(images['base'])
    (fixed/'libcapstone.so').symlink_to(dest.name)
    run(['c++','-O3','-std=c++17','-I',source/'include',r/'time.cpp','-L',fixed,'-Wl,-rpath,'+str(fixed),'-lcapstone','-o',tmp/'time'],'compile-time')
    bind=['setarch',platform.machine(),'-R']
    sp.run([*bind,'/bin/true'],check=True)
    cpu=min(os.sched_getaffinity(0));os.sched_setaffinity(0,{cpu})
    hashes={k:sha(v)for k,v in images.items()}
    size=max(map(len,images.values()))
    images={k:v.ljust(size,b'\0') for k,v in images.items()}
    def measure(label,case,mode,reps):
        dest.write_bytes(images[label])
        return list(map(int,sp.check_output([*bind,tmp/'time','102',str(mode),tmp/(case+'.text'),'0x100000',str(reps)],text=True).split()))
    rows=[];rng=random.Random(1680)
    for case in corpus:
        for mode in (0,1,2):
            first=measure('base',case,mode,1)
            assert first[0]>0 and first[1]>0 and first[2]>0
            reps=max(1,min(4096,round(45_000_000/first[0])))
            cycles=[]
            for i in range(15):
                keys=list(images);rng.shuffle(keys)
                cyc={k:[] for k in keys}
                for k in keys+keys[::-1]:
                    result=measure(k,case,mode,reps)
                    assert result[2]==first[2]
                    cyc[k].append(result[:2])
                cycles.append(cyc)
            rows.append(dict(case=case,mode=mode,reps=reps,signature=first[2],cycles=cycles))
            put('rows',rows)
    put('complete',dict(tree=meta['tree'],libs=hashes,changed=changes,host=platform.machine(),compiler=sp.check_output([cc,'--version'],text=True).splitlines()[0],core=cpu,aslr_disabled=True))
finally:
    size=sum(f.stat().st_size for f in tmp.rglob('*') if f.is_file() and not f.is_symlink())
    shutil.rmtree(tmp)
    put('cleanup',dict(bytes=size,removed=not tmp.exists()))
