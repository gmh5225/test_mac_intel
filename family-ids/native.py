from pathlib import Path
import hashlib,json,re,os,platform,random,shutil,subprocess as sp,tempfile
d=Path(__file__).resolve().parent;s=d.parent/'source';out=d.parent/'evidence';out.mkdir(exist_ok=True)
def load(p):return json.loads(p.read_text())
def save(n,v):(out/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def cmd(n,a,cwd=None):
    with (out/(n+'.log')).open('w')as f:z=sp.run(a,cwd=cwd,stdout=f,stderr=sp.STDOUT)
    if z.returncode:print((out/(n+'.log')).read_text(errors='replace')[-2200:]);z.check_returncode()
def g(*a):return sp.check_output(['git','-C',s,*a],text=True).strip()
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
cc=os.environ['CC'];meta=load(d/'tree.json');osrel='22.04'if '22.04' in Path('/etc/os-release').read_text() else '24.04'
t=Path(tempfile.mkdtemp());b=t/'build';assert g('rev-parse','HEAD')==meta['parent']
try:
    cmd('configure',['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCMAKE_C_COMPILER='+cc,'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_SHARED_LIBS=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),*['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in ('ARM','AARCH64','MIPS','RISCV','PPC','SYSTEMZ','LOONGARCH','SPARC','XTENSA')]])
    patch=d/'candidate.patch';assert sha(patch)==meta['sha256'];g('apply','--index',str(patch));assert g('write-tree')==meta['tree']
    file=s/'SStream.c';body=file.read_text()
    start=body.index('#ifdef SSTREAM_NEON_HEX');conditional=body.index('#else',start);end=body.index('#endif',conditional)
    simd=body[start:conditional].split(chr(10),1)[1].replace('char *p = end','p = end')
    scalar=body[conditional:end].split(chr(10),1)[1].replace('char *p = end','p = end')
    assert 'vqtbl1q_u8' in simd and 'while (value)' in scalar and 'p = end' in simd
    body=body[:start]+'char *p; if (hex_variant) {'+chr(10)+simd+'} else {'+chr(10)+scalar+'}'+chr(10)+body[end+6:]
    file.write_text('unsigned hex_variant;'+chr(10)+body)
    units=['x86_simple_output','x86_scan_batch','x86_buffer_bounds','x86_reg_access','aarch64_scan','aarch64_postprocess','mips_scan','mips_single','text_option','detail_option']
    cmd('build',['cmake','--build',b,'--parallel','4','--target','capstone_static',*units])
    cmd('units',['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','--parallel','4','-R','^unit_('+'|'.join(units)+')$'])
    lib=b/'libcapstone.a';target=t/'time'
    cmd('link',['c++','-O3','-std=c++17','-DTIMED_PRIVATE_READERS','-no-pie','-I',s/'include',d/'time.cpp',lib,'-lm','-o',target])
    ids={k:sha(target) for k in ('base','copy','candidate')};assert len(set(ids.values()))==1
    expected=load(d/'reach.json')[cc];libs={};imgs=dict.fromkeys(ids)
    shutil.copy2(d/'fetch.py',t/'fetch.py');cmd('pe',['python3','-B',t/'fetch.py'])
    for f in ('libmvec.py','libmvec.json'):shutil.copy2(d/f,t/f)
    cmd('libmvec',['python3','-B',t/'libmvec.py'])
    import corpus
    foreign=corpus.prepare(d,t,out,lambda args,n:cmd(n,args));extra=[q for q in foreign if q['name'] in ('arm-ls', 'arm64-ls', 'mips64el-ls', 'ppc64el-ls', 'riscv64-ls', 'sparc64-ls', 's390x-ls', 'loong64-ls')]
    from xtensa import get
    xfile,xsource=get(t,load(d/'xtensa-source.json'));save('xtensa-source',xsource);extra.append(dict(name='xtensa-picolibc',path=xfile))
    assert len(extra)==9
    selectors={'arm': 101, 'arm64': 102, 'mips64el': 103, 'ppc64el': 104, 'riscv64': 105, 'sparc64': 106, 's390x': 107, 'loong64': 108, 'xtensa': 109}
    panels=[('putty32',32,t/'putty-0.85-32.text',0x401000,(0,1,2,3)),('putty64',64,t/'putty-0.85-64.text',0x140001000,(0,1,2))]
    panels.append(('libmvec-amd64',64,t/'libmvec.text',load(t/'libmvec.json')['address'],(0,1,2)))
    panels.extend((q['name'],selectors[q['name'].split('-')[0]],Path(q['path']),0x100000,(0,1,2))for q in extra)
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))});rng=random.Random(1756);rows=[]
    save('host',dict(cpu=sp.check_output(['lscpu'],text=True),compiler=sp.check_output([cc,'--version'],text=True),images=ids,osrel=osrel,machine=platform.machine(),cc=cc))
    def invoke(k,arch,mode,path,ip,n):
        env=dict(os.environ,FORMAT_SELECT=('1' if k=='candidate' else '0'))
        return list(map(int,sp.check_output(['setarch',platform.machine(),'-R',target,str(arch),str(mode),path,str(ip),str(n)],text=True,env=env).split()))
    for name,arch,path,ip,modes in panels:
        for mode in modes:
            one=invoke('base',arch,mode,path,ip,1);assert one[2]==expected[name+'/'+str(mode)]['signature'];n=max(1,round(65e6/one[0]));rows_=[]
            for i in range(21):
                order=list(imgs);rng.shuffle(order);cyc={k:[]for k in order}
                for k in order+order[::-1]:
                    v=invoke(k,arch,mode,path,ip,n)
                    expect=one[2]
                    assert v[2]==expect,(name,mode,k,v[2],expect);cyc[k].append(v[0])
                rows_.append(cyc)
            rows.append(dict(name=name,arch=arch,mode=mode,cycles=rows_,sha=sha(path),reps=n));save('timings',rows)
    save('complete',dict(done=True,panels=len(rows),revisions=meta,images=ids))
finally:
    count=sum(p.stat().st_size for p in t.rglob('*') if p.is_file()and not p.is_symlink());shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=count))
