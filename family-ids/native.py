from pathlib import Path
import hashlib,json,os,platform,shutil,subprocess as sp,sys,tempfile
r=Path(__file__).resolve().parent;local=len(sys.argv)>1 and sys.argv[1]=='local'
def read(f):return json.loads(f.read_text())
out=r if local else r.parent/'evidence';out.mkdir(exist_ok=True)
def save(k,v):(out/(k+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def cmd(k,a,cwd=None,allow=False):
    with (out/(k+'.log')).open('w')as f:z=sp.run(a,stdout=f,stderr=sp.STDOUT,cwd=cwd)
    if not allow and z.returncode:print((out/(k+'.log')).read_text()[-1300:]);z.check_returncode()
    return z.returncode
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
q=read(r/'tree.json');t=Path(tempfile.mkdtemp(dir=r if local else None));s=t/'c' if local else r.parent/'source';b=t/'b'
def g(*a):return sp.check_output(['git','-C',s,*a],text=True).strip()
try:
    if local:
        c=next(r.parent.glob('round579-*'))/'source';cmd('clone-diff',['git','clone','--shared','--no-checkout','-q',c,s]);g('checkout','--detach','-q',q['parent'])
    assert g('rev-parse','HEAD')==q['parent'] and sha(r/'candidate.patch')==q['sha256']
    imgs={};raw={};digests={};testcodes={};stages=('full','diet','newdiet','newfull')
    for stage in stages:
        diet=stage in ('diet','newdiet')
        if stage=='newdiet':g('apply','--index',str(r/'candidate.patch'));assert g('write-tree')==q['tree']
        args=['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_DIET='+('ON'if diet else 'OFF'),'-DCAPSTONE_BUILD_CSTEST=ON']
        if not local:args+=['-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if os.environ['CC']=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),*['-DCAPSTONE_'+v+'_SUPPORT=ON' for v in ('ARM','AARCH64','MIPS','RISCV','PPC')]]
        cmd('diff-config-'+stage,args);cmd('diff-build-'+stage,['cmake','--build',b,'--parallel','4','--target','capstone_shared','x86_evex_detail','x86_evex_vpcmp_id'])
        cand=[f for f in b.glob('libcapstone*') if f.is_file() and not f.is_symlink() and ('.so.'in f.name or f.suffix=='.dylib')];assert len(cand)==1,cand
        target=t/(stage+cand[0].suffix);shutil.copy2(cand[0],target);imgs[stage]=target;digests[stage]=sha(target)
        testcodes[stage]=cmd('diff-test-'+stage,['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_x86_evex_(detail|vpcmp_id)$'],allow=True);assert (testcodes[stage]!=0)==(stage=='diet')
        if stage=='newfull' and not local:assert digests['full']==digests[stage],digests
    cmd('diff-link',[os.environ.get('CXX','c++'),'-std=c++17','-O2','-I',s/'include',r/'diet.cpp','-ldl','-o',t/'compare'])
    cases=[('encodings',bits,[])for bits in (32,64)]
    if not local:
        for n in ('fetch.py','libmvec.py','libmvec.json'):shutil.copy2(r/n,t/n)
        cmd('diff-pe',[sys.executable,'-B',t/'fetch.py']);cmd('diff-libmvec',[sys.executable,'-B',t/'libmvec.py'])
        cases.extend([('putty32',32,[t/'putty-0.85-32.text']),('putty64',64,[t/'putty-0.85-64.text']),('libmvec',64,[t/'libmvec.text'])])
    for name,n,paths in cases:
        key=name+'-'+str(n);cmd('diff-records-'+key,[t/'compare',imgs['full'],imgs['diet'],imgs['newdiet'],str(n),*paths])
        row=list(map(int,(out/('diff-records-'+key+'.log')).read_text().split()));assert len(row)==5 and row[0]>=row[1] and (name!='encodings' or (row[2]>100 and row[3]>100)),row
        raw[key]=dict(count=row[0],accepted=row[1],broadcasts=row[2],mask_widths=row[3],compare_ids=row[4],files=[sha(p)for p in paths]);save('records',raw)
    save('diff-review'if local else 'complete',dict(complete=True,source=q,tests=testcodes,raw=raw,images=digests,host=platform.platform()))
finally:
    volume=sum(x.stat().st_size for x in t.rglob('*')if x.is_file()and not x.is_symlink());shutil.rmtree(t);save('diff-cleanup' if local else 'cleanup',dict(removed=not t.exists(),bytes=volume))
