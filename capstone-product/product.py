from pathlib import Path
import hashlib, json, os, platform, random, shutil, subprocess as sp, sys, tempfile
import xml.etree.ElementTree as ET
import corpus
r=Path(__file__).resolve().parent;nd=r.parent/'neverd';out=r.parent/'product-evidence';out.mkdir(exist_ok=True)
cs=nd/'third_party/capstone';ll=nd/'third_party/llvm-project';rd=lambda f:json.loads(f.read_text())
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def get(*a):return sp.check_output(a,text=True).strip()
def git(repo,*a):return get('git','-C',repo,*a)
def save(n,v):(out/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def command(args,label,cwd=None):
    print(label,flush=True)
    with (out/(label+'.log')).open('w') as f:z=sp.run(list(map(str,args)),cwd=cwd,stdout=f,stderr=sp.STDOUT)
    if z.returncode:print((out/(label+'.log')).read_text(errors='replace')[-4000:],flush=True);z.check_returncode()
m=rd(r/'source.json');q=m['candidate'];llvm=git(ll,'rev-parse','HEAD')
assert git(nd,'rev-parse','HEAD')==m['dev'] and git(cs,'rev-parse','HEAD')==q['parent'] and sha(r/'candidate.patch')==q['sha256']
assert llvm==git(ll,'ls-remote','origin','refs/heads/main').split()[0]
save('source',dict(m,llvm=llvm,main_at_start=llvm,prebuilt=False))
w=Path(tempfile.mkdtemp(dir=os.environ['RUNNER_TEMP']))
try:
    cases=corpus.prepare(r,w,out,command)
    selected={'putty-32-0.85','putty-64-0.85','arm64-ls','arm-ls','riscv64-ls','ppc64el-ls','mips64el-ls'}
    cases=[c for c in cases if c['name'] in selected];assert {c['name'] for c in cases}==selected
    for f in ('libmvec.py','libmvec.json'):shutil.copyfile(r/f,w/f)
    command([sys.executable,w/'libmvec.py'],'libmvec')
    z=rd(w/'libmvec.json');assert sha(w/'libmvec.text')==z['text_sha256']
    cases.append(dict(name='libmvec-amd64',selector=64,path=str(w/'libmvec.text'),text_sha256=z['text_sha256']))
    shutil.copyfile(r/'probe.cpp',nd/'capstone-product.cpp')
    with (nd/'CMakeLists.txt').open('a') as f:f.write('\nadd_executable(capstone-product capstone-product.cpp)\ntarget_link_libraries(capstone-product PRIVATE NeverDDecode)\n')
    build=w/'build'
    command(['cmake','-S',nd,'-B',build,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCMAKE_C_COMPILER=clang','-DCMAKE_CXX_COMPILER=clang++','-DNEVERD_LLVM_PREBUILT=OFF','-DBUILD_TESTING=ON','-DNEVERD_ENABLE_WEB_ANALYSIS=OFF','-DNEVERD_ENABLE_CPU_EMULATION=OFF','-DNEVERD_ENABLE_DRIVER_EMULATION=OFF','-DNEVERD_ENABLE_PYTHON_PLUGINS=OFF','-DNEVERD_BUILD_GUI=OFF'],'configure')
    cache=(build/'CMakeCache.txt').read_text();assert 'NEVERD_LLVM_PREBUILT:BOOL=OFF' in cache and 'CAPSTONE_BUILD_MACOS_THIN:BOOL=OFF' in cache
    targets=['NeverDX86DecodeDetailTests','NeverDX86MpxEncodingTests','NeverDX86NoIndexAddressTests']
    images={};tests={};labels=['base','copy','candidate']
    for label in ('base','candidate'):
        if label=='candidate':command(['git','apply','--index',r/'candidate.patch'],'apply',cs)
        tree=git(cs,'write-tree')
        assert tree==(q['tree'] if label=='candidate' else git(cs,'rev-parse','HEAD^{tree}'))
        command([sys.executable,nd/'scripts/build.py',build,'--target','LLVMSwiftDemangle','capstone-product',*targets,'--parallel','4'],'build-'+label,nd)
        assert git(cs,'write-tree')==tree and not git(cs,'diff','--name-only') and git(ll,'rev-parse','HEAD')==llvm
        archive,=build.rglob('libcapstone.a')
        archs=sorted(get('lipo','-archs',archive).split());assert archs==['arm64','x86_64'],archs
        compiler=rd(build/'compile_commands.json');flags=next(i['command']for i in compiler if Path(i['file']).name=='cs.c' and 'capstone' in i['file'])
        assert ('-DCAPSTONE_STATIC_X86_READERS' in flags)==(label=='candidate') and '-arch x86_64' in flags and '-arch arm64' in flags
        binary,=build.rglob('capstone-product');shutil.copy2(binary,w/label)
        names=get('nm','-n',binary).splitlines()
        assert any(l.endswith(' _X86_scanNativeBatch') for l in names) and any(l.endswith(' _cs_disasm_iter') for l in names)
        images[label]=dict(exe=sha(binary),archive=sha(archive),cpu=platform.machine(),archs=archs,flags=flags.replace(str(nd),'$SOURCE').replace(str(w),'$BUILD'),tree=tree)
        command(['ctest','--test-dir',build,'--no-tests=error','--parallel','4','--output-on-failure','--output-junit',out/(label+'.xml'),'-L','^('+'|'.join(targets)+')$'],'tests-'+label)
        nodes=ET.parse(out/(label+'.xml')).findall('.//testcase');assert len(nodes)>=43 and all(n.find('error') is None and n.find('failure') is None for n in nodes)
        tests[label]={n.get('name'):'skipped' if n.find('skipped') is not None else 'pass' for n in nodes}
    assert tests['base']==tests['candidate'] and images['base']['archive']!=images['candidate']['archive']
    shutil.copy2(w/'base',w/'copy');assert sha(w/'copy')==images['base']['exe']
    save('products',images);save('tests',tests)
    rows={}
    for c in cases:
        sel=str(c['selector']) if c['selector'] in (32,64) else {0:'arm64',1:'arm',2:'riscv64',3:'ppc64el',4:'mips64el'}[c['selector']]
        for mode in range(4 if c['name'] in ('putty-32-0.85','putty-64-0.85','libmvec-amd64') else 3):
            def take(label,n):return list(map(int,get(w/label,c['path'],sel,str(mode),str(n)).split()))
            once=take('base',1);assert once[0]>0 and once[1]>0
            n=max(1,round(35000/once[0]));expect=take('base',n)[1:];rng=random.Random(c['name']+'/'+str(mode));cycles=[]
            for _ in range(21):
                rng.shuffle(labels);pair={k:0 for k in labels}
                for k in labels+labels[::-1]:
                    row=take(k,n);assert row[1:]==expect;pair[k]+=row[0]
                cycles.append(pair)
            rows[c['name']+'/'+str(mode)]=dict(repeats=n,sha256=c['text_sha256'],checks=expect,cycles=cycles);save('timings',rows)
    assert len(rows)==27
    save('complete',dict(complete=True,source=m,llvm=llvm,panels=len(rows),pairs=21,cpu=platform.machine()))
finally:
    amount=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink())
    shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=amount))
