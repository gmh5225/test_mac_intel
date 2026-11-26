from pathlib import Path
import hashlib,json,os,platform,re,shutil,stat,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;local=(r.parent/'round3874-riscv-unnamed-csr').is_dir()
d=lambda n:next(r.parent.glob(f'round{n}-*'))
q=json.loads(((d(3874)/'tree.json') if local else r/'source.json').read_text());e=r if local else r.parent/'evidence';e.mkdir(exist_ok=True)
def run(*a):sp.run(a,check=True)
def get(*a):return sp.check_output(a,text=True)
def put(name,v):(e/(name+'.json')).write_text(json.dumps(v,indent=2)+'\n')
w=Path(tempfile.mkdtemp(dir=r if local else None));s=w/'source';b=w/'build'
try:
    seed=d(579)/'source' if local else r.parent/'source';run('git','clone','-q','--no-checkout','--shared',seed,s)
    run('git','-C',s,'config','core.autocrlf','false');run('git','-C',s,'checkout','-q','--detach',q['parent'])
    raw=(d(3874)/'candidate.patch').read_bytes() if local else sp.check_output(['git','-C',r.parent,'cat-file','blob','HEAD:capstone-make/candidate.patch'])
    assert hashlib.sha256(raw).hexdigest()==q['sha256'];pt=w/'trial.patch';pt.write_bytes(raw);run('git','-C',s,'apply','--index',pt)
    assert get('git','-C',s,'write-tree').strip()==q['tree']
    args=['-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_RISCV_SUPPORT=ON','-DCAPSTONE_BUILD_CSTOOL=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=OFF']
    run('cmake','-S',s,'-B',b,*args);run('cmake','--build',b,'--target','cstest','cstool','riscv_sysreg','--parallel','4')
    exe,=[f for f in b.rglob('cstest.exe' if os.name=='nt' else 'cstest') if f.is_file()]
    native=get('ctest','--test-dir',b,'--output-on-failure','-R','^unit_riscv_sysreg$','--no-tests=error');assert '100% tests passed' in native
    fixture=s/'tests/details/riscv.yaml';positive=get(exe,fixture)
    assert '[o] All tests succeeded.' in positive
    cases=int(re.search(r'Decoded instructions:\s*(\d+)',positive).group(1));assert cases>50
    bad=w/'expectation.yaml';new_case=fixture.read_text().rsplit('  - input:',1)[1]
    bad.write_text('test_cases:\n  - input:'+new_case.replace('csr: "0x7cb"','csr: "0x123"'))
    negative=sp.run([exe,bad],text=True,stdout=sp.PIPE,stderr=sp.STDOUT)
    assert negative.returncode==1 and "CSR mismatch: '0x7cb' != '0x123'\n" in negative.stdout,negative.stdout
    tool,=[f for f in b.rglob('cstool.exe' if os.name=='nt' else 'cstool') if f.is_file()]
    cli=get(tool,'-d','riscv64','7395b57c');assert any(l.endswith('CSR = 0x7cb')for l in cli.splitlines())
    put('suite-complete',dict(complete=True,source=q,host=platform.system(),machine=platform.machine(),positive=positive,negative=negative.stdout,cli=cli,unit=native,decoded=cases))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink())
    def retry(fn,path,error):os.chmod(path,stat.S_IWRITE);fn(path)
    shutil.rmtree(w,onerror=retry);put('suite-cleanup',dict(removed=not w.exists(),bytes=n))
