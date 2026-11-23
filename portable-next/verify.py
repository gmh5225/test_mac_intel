from pathlib import Path
import hashlib,json,os,re,shutil,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;s=r.parent/'source';e=r.parent/'evidence';e.mkdir(exist_ok=True);t=Path(tempfile.mkdtemp());p=os.environ['SCAN_PROFILE']
def save(n,v):(e/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def git(*args):return sp.check_output(['git','-C',s,*args],text=True).strip()
def run(n,*args):
    with (e/(n+'.log')).open('w') as log:res=sp.run(args,stdout=log,stderr=sp.STDOUT)
    content=(e/(n+'.log')).read_text(errors='replace')
    if res.returncode:print(content[-2000:]);res.check_returncode()
    return content
try:
    q=json.loads((r/'tree.json').read_text());assert git('rev-parse','HEAD')==q['parent']
    patch=t/'fix.patch';patch.write_bytes(sp.check_output(['git','-C',r.parent,'cat-file','blob','HEAD:portable-next/fix.patch']))
    assert hashlib.sha256(patch.read_bytes()).hexdigest()==q['sha256'];git('apply','--index',patch);assert git('write-tree')==q['tree']
    b=t/'build';flags=dict(full=[],diet=['-DCAPSTONE_BUILD_DIET=ON'],noatt=['-DCAPSTONE_X86_ATT_DISABLE=ON'],reduced=['-DCAPSTONE_X86_REDUCE=ON'])[p]
    if os.name=='posix' and Path('/etc/os-release').exists():flags+=['-DCMAKE_C_COMPILER=gcc','-DCMAKE_CXX_COMPILER=g++']
    run('configure','cmake','-G','Ninja','-S',s,'-B',b,'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF',*['-DCAPSTONE_'+a+'_SUPPORT=ON'for a in ('ARM','AARCH64','MIPS','RISCV','X86')],*flags)
    units=['api','instruction_bytes','x86_buffer_bounds','x86_scan_batch','riscv_scan_options']
    if p in ('noatt','full'):units+=['x86_simple_output','x86_exchange_access']
    if p in ('full','noatt'):units+=['detail_option','text_option','arm_reg_access','riscv_op_count_iter','riscv_reg_access','x86_reg_access']
    run('build','cmake','--build',b,'--parallel','4','--target','capstone_shared','capstone_static',*units)
    text=run('tests','ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(units)+')$')
    assert '100% tests passed' in text and ('out of '+str(len(units))) in text
    save('complete',dict(source=q,profile=p,units=units,static=True,shared=True))
finally:
    n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);save('cleanup',dict(bytes=n,removed=not t.exists()))
