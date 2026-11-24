from snapshot import snapshots
from pathlib import Path
import hashlib,json,os,platform,shutil,subprocess as sp,tempfile
p=Path(__file__).resolve().parent
s=p.parent/'source'
e=p.parent/'evidence'
e.mkdir(exist_ok=True)
q=json.loads((p/'source.json').read_text())
profile=os.environ['SCAN_PROFILE']
def save(name,v):
    (e/(name+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def git(*args):
    return sp.check_output(['git','-C',s,*args],text=True).strip()
def run(label,*args):
    with (e/(label+'.log')).open('wb') as log:
        ret=sp.run(args,stdout=log,stderr=sp.STDOUT)
    if ret.returncode:
        print((e/(label+'.log')).read_text(errors='replace')[-3200:],flush=True)
        ret.check_returncode()
t=Path(tempfile.mkdtemp())
b=t/'build'
try:
    assert git('rev-parse','HEAD')==q['base'] and git('status','--porcelain')==''
    arches=['X86','AARCH64','ARM','MIPS','PPC','RISCV'] if profile not in ('diet','reduced') else ['X86']
    flags=['-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF',*['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in arches]]
    flags+=dict(full=[],noatt=['-DCAPSTONE_X86_ATT_DISABLE=ON'],diet=['-DCAPSTONE_BUILD_DIET=ON'],reduced=['-DCAPSTONE_X86_REDUCE=ON'],gcc=['-DCMAKE_C_COMPILER=gcc','-DCMAKE_CXX_COMPILER=g++'],clang=['-DCMAKE_C_COMPILER=clang','-DCMAKE_CXX_COMPILER=clang++'])[profile]
    units=['mcinst','x86_reg_access','x86_buffer_bounds','x86_scan_batch','x86_mapping_counts','x86_bound_access','x86_exchange_access','x86_encoding_accuracy']
    if profile not in ('diet','reduced'):
        units+=['x86_simple_output','x86_integer_vector_access','x86_scalar_vector_access','x86_evex_move_access']
    if len(arches)>1:
        units+=['aarch64_scan','aarch64_postprocess','arm_private_stream','arm_reg_access','riscv_scan_options','riscv_reg_access','mips_scan','mips_single']
    run('configure','cmake','-G','Ninja','-S',s,'-B',b,*flags)
    rows={}
    for name,tree in [('base',None),*q['variants'].items()]:
        if tree:
            git('restore','--staged','--worktree','--source=HEAD','--','.')
            patch=t/(name+'.patch')
            patch.write_bytes(sp.check_output(['git','-C',p.parent,'cat-file','blob','HEAD:portable-next/'+name+'.patch']))
            assert hashlib.sha256(patch.read_bytes()).hexdigest()==tree['sha256']
            git('apply','--index',patch)
            assert git('write-tree')==tree['tree']
        run(name+'-build','cmake','--build',b,'--parallel','4','--target','capstone_static','capstone_shared',*units)
        run(name+'-units','ctest','--test-dir',b,'--output-on-failure','--no-tests=error','-R','^unit_('+'|'.join(units)+')$')
        log=(e/(name+'-units.log')).read_text(errors='replace')
        assert '100% tests passed' in log and all('unit_'+n in log for n in units)
        rows[name]=dict(units=units,skipped=[line.strip() for line in log.splitlines() if '***Skipped' in line])
        result=snapshots(s,p,b,t,profile,name,run)
        rows[name]['public']=result
        baseline=rows['base']['public']['snapshots']
        for key,x in result['snapshots'].items():
            if name!='prefix' or not key.startswith('16/'):
                assert x==baseline[key],(name,profile,key,x,baseline[key])
        assert set(result['snapshots'])==set(baseline)
        save('results',rows)
    save('complete',dict(complete=True,source=q,profile=profile,architectures=arches,results=rows))
finally:
    n=sum(f.stat().st_size for f in t.rglob('*') if f.is_file() and not f.is_symlink())
    shutil.rmtree(t)
    save('cleanup',dict(removed=not t.exists(),bytes=n))
