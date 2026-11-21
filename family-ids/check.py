from pathlib import Path
import hashlib,json,os,platform,resource,shutil,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;root=r.parent
if os.environ.get('GITHUB_ACTIONS')=='true':
    s=root/'source';out=root/'evidence'
else:
    s=None;out=r/'mac-result'
out.mkdir(exist_ok=True)
m=json.loads((r/'tree.json').read_text())
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def save(n,x):(out/(n+'.json')).write_text(json.dumps(x,indent=2)+'\n')
def run(args,name,check=True):
    with (out/(name+'.log')).open('w') as f:
        result=sp.run(args,stdout=f,stderr=sp.STDOUT)
    if check and result.returncode:print((out/(name+'.log')).read_text()[-1800:],flush=True);result.check_returncode()
    return result.returncode
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
w=Path(tempfile.mkdtemp());b=w/'build'
try:
    if s is None:
        s=w/'source';run(['git','clone','--shared','--no-checkout',root/'round579-custom-formatter-coverage/source',s],'clone')
        run(['git','-C',s,'checkout','--detach',m['parent']],'checkout')
    cc=os.environ.get('CC','cc');flavor=os.environ.get('FLAVOR','diet');diet=flavor=='diet';att=flavor!='intel'
    opts=['-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON']
    if diet:opts.append('-DCAPSTONE_BUILD_DIET=ON')
    if not att:opts.append('-DCAPSTONE_X86_ATT_DISABLE=ON')
    run(['cmake','-S',s,'-B',b,*opts],'configure')
    target='x86_kmask_width';cases={};hashes=[]
    for k in ('base','candidate'):
        if k=='candidate':
            assert sha(r/'candidate.patch')==m['sha256']
            sp.run(['git','-C',s,'apply','--index',r/'candidate.patch'],check=True)
            assert sp.check_output(['git','-C',s,'write-tree'],text=True).strip()==m['tree']
        run(['cmake','--build',b,'--parallel','4','--target',target],'build-'+k)
        # The runtime is the same archive, using the exact code linked into the unit.
        library=next(b.rglob('libcapstone.a'));hashes.append(sha(library))
        rv=run(['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_x86_kmask_width$'],'result-'+k,False)
        cases[k]=dict(status=rv,text=(out/('result-'+k+'.log')).read_text())
        if diet and k=='base':assert rv!=0 and ('Seg' in cases[k]['text'] or 'SEG' in cases[k]['text'] or 'Exception' in cases[k]['text'])
        else:assert rv==0,cases[k]
    assert len(set(hashes))==1
    save('complete',dict(tree=m['tree'],config=flavor,result=cases,identical_runtime=hashes[0],machine=platform.machine(),compiler=sp.check_output([cc,'--version'],text=True).splitlines()[0]))
finally:
    num=sum(v.stat().st_size for v in w.rglob('*') if v.is_file() and not v.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=num))
