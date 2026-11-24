from pathlib import Path
import hashlib,json,os,platform,subprocess as sp,tempfile,shutil
p=Path(__file__).resolve().parent;s=p.parent/'source';e=p.parent/'evidence';e.mkdir(exist_ok=True)
rd=lambda f:json.loads(f.read_text());q=rd(p/'tree.json');t=Path(tempfile.mkdtemp());b=t/'build'
def git(*a):return sp.check_output(['git','-C',s,*a],text=True).strip()
def save(n,z):(e/(n+'.json')).write_text(json.dumps(z,indent=2)+'\n')
def run(label,*args):
    with (e/(label+'.log')).open('wb')as f:ret=sp.run(args,stdout=f,stderr=sp.STDOUT)
    if ret.returncode:
        print((e/(label+'.log')).read_text(errors='replace')[-2200:]);ret.check_returncode()
def measure_probe(label):
    if os.name=='nt':
        names=[b/'capstone_static.lib',b/'capstone.lib']
        target=next(k for k in names if k.is_file())
    else:target=b/'libcapstone.a'
    exe=t/('probe.exe' if os.name=='nt' else 'probe')
    if os.name=='nt':run(label+'-probe-build','cl','/nologo','/O2','/MT' if 'CAPSTONE_BUILD_STATIC_MSVC_RUNTIME:BOOL=ON' in (b/'CMakeCache.txt').read_text() else '/MD','/std:c11','/I'+str(s/'include'),p/'probe.c',target,'/Fo:'+str(t/'probe.obj'),'/Fe:'+str(exe))
    else:run(label+'-probe-build',profile if profile in ('gcc','clang') else 'clang','-O2','-I',s/'include',p/'probe.c',target,'-o',exe)
    check=sp.run([exe],text=True,capture_output=True)
    (e/(label+'-probe.log')).write_text(check.stderr+check.stdout)
    return check.returncode,check.stderr.splitlines(),check.stdout.splitlines()
try:
 profile=os.environ['SCAN_PROFILE'];assert git('rev-parse','HEAD')==q['parent']
 patch=t/'candidate.patch';patch.write_bytes(sp.check_output(['git','-C',p.parent,'cat-file','blob','HEAD:portable-next/candidate.patch']))
 assert hashlib.sha256(patch.read_bytes()).hexdigest()==q['sha256']
 git('apply','--index',patch);assert git('write-tree')==q['tree']
 run('generator','python','-B',s/'suite/synctools/x86_mapping_counts.py','--check')
 if platform.system()=='Linux' and profile=='clang':
    for script in ('x86_operand_specializations.py','x86_disassembler_tables.py'):
        run(script[:-3],'python','-B',s/'suite/synctools'/script,'--check')
 arches=['X86','ARM','AARCH64','MIPS']if platform.system()=='Linux' else ['X86']
 flags=['-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF',*['-DCAPSTONE_'+a+'_SUPPORT=ON'for a in arches]]
 flags+=dict(full=[],noatt=['-DCAPSTONE_X86_ATT_DISABLE=ON'],diet=['-DCAPSTONE_BUILD_DIET=ON'],reduced=['-DCAPSTONE_X86_REDUCE=ON'],gcc=['-DCMAKE_C_COMPILER=gcc','-DCMAKE_CXX_COMPILER=g++'],clang=['-DCMAKE_C_COMPILER=clang','-DCMAKE_CXX_COMPILER=clang++'])[profile]
 units=['x86_reg_access','x86_scan_batch','x86_mapping_counts','x86_buffer_bounds']
 if profile not in ('diet','reduced'):units+=['x86_integer_vector_access','x86_scalar_vector_access','x86_packed_move_access','x86_evex_move_access','x86_simple_output']
 if profile not in ('noatt','diet','reduced'):units+=['x86_kmask_access','x86_apx_evex_kmov']
 run('configure','cmake','-G','Ninja','-S',s,'-B',b,*flags)
 run('build','cmake','--build',b,'--parallel','4','--target','capstone_static','capstone_shared',*units)
 run('units','ctest','--test-dir',b,'--output-on-failure','--no-tests=error','-R','^unit_('+'|'.join(units+['x86_mapping_counts_generator','x86_mapping_counts_validation'])+')$')
 text=(e/'units.log').read_text(errors='replace');assert '100% tests passed' in text and all('unit_'+n in text for n in units)
 cases=0
 if profile not in ('diet','reduced'):
    candidate=measure_probe('candidate')
    git('reset','--hard',q['parent'])
    run('base-build','cmake','--build',b,'--parallel','4','--target','capstone_static')
    original=measure_probe('base')
    cases=9088
    assert original==(0,[],['9088 144 1008']) and candidate==(0,[],['9088 144 0']),(original,candidate)
    save('extrq-register-selectors',dict(reference=q['parent'],candidate=q['commit'],records=cases,original=original,updated=candidate))
 save('complete',dict(complete=True,source=q,profile=profile,architectures=arches,units=units,case_count=cases))
finally:
 n=sum(f.stat().st_size for f in t.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=n))
