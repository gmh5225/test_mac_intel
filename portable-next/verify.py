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
    arches=['X86','AARCH64','ARM','MIPS','PPC','RISCV'] if profile not in ('diet','reduced') else ['X86','PPC']
    flags=['-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF',*['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in arches]]
    flags+=dict(full=[],noatt=['-DCAPSTONE_X86_ATT_DISABLE=ON'],diet=['-DCAPSTONE_BUILD_DIET=ON'],reduced=['-DCAPSTONE_X86_REDUCE=ON'],gcc=['-DCMAKE_C_COMPILER=gcc','-DCMAKE_CXX_COMPILER=g++'],clang=['-DCMAKE_C_COMPILER=clang','-DCMAKE_CXX_COMPILER=clang++'])[profile]
    units=['mapping','mcinst','x86_reg_access','x86_buffer_bounds','x86_scan_batch','x86_mapping_counts','x86_evex_vpcmp_id','x86_bound_access','x86_exchange_access','x86_encoding_accuracy']
    if profile not in ('diet','reduced'):
        units+=['x86_vex_legacy_prefix','x86_evex_detail','x86_evex_vpcmp_mask_size','x86_evex_mask_conversion_access','x86_simple_output','x86_integer_vector_access','x86_scalar_vector_access','x86_evex_move_access','x86_legacy_address_size']
    if len(arches)>2:
        units+=['aarch64_scan','aarch64_postprocess','arm_private_stream','arm_reg_access','riscv_scan_options','riscv_reg_access','mips_scan','mips_single']
    if profile in ('full','gcc','clang'):
        for name in ('x86_valign_access','x86_evex_move_access','x86_packed_move_access','x86_scalar_vector_access','x86_integer_vector_access','x86_reg_access','x86_bextr_flags'):
            if name not in units:units.append(name)
    flags+=['-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCAPSTONE_X86_NEAR_INDIRECT_OUTPUT=ON']
    run('configure','cmake','-G','Ninja','-S',s,'-B',b,*flags)
    rows={}
    ordinary_units=tuple(units)
    for name,tree in [('base',None),*q['variants'].items()]:
        units=list(ordinary_units)
        if tree:
            git('restore','--staged','--worktree','--source=HEAD','--','.')
            patch=t/(name+'.patch')
            patch.write_bytes(sp.check_output(['git','-C',p.parent,'cat-file','blob','HEAD:portable-next/'+name+'.patch']))
            assert hashlib.sha256(patch.read_bytes()).hexdigest()==tree['sha256']
            git('apply','--index',patch)
            assert git('write-tree')==tree['tree']
            units.append('detail_views')
        run(name+'-typed-register-mappings',os.sys.executable,'-B',s/'suite/synctools/x86_mapping_counts.py','--check')
        run(name+'-register-projection',os.sys.executable,'-B',s/'suite/synctools/x86_register_name_sizes.py','--check')
        run(name+'-printer-projection',os.sys.executable,'-B',s/'suite/synctools/x86_printer_dispatch.py','--check')
        run(name+'-alias-projection',os.sys.executable,'-B',s/'suite/synctools/alias_mnemonic_trie.py','--check')
        run(name+'-build','cmake','--build',b,'--parallel','4','--target','capstone_static','capstone_shared',*units)
        run(name+'-units','ctest','--test-dir',b,'--output-on-failure','--no-tests=error','-R','^unit_('+'|'.join(units)+')$')
        log=(e/(name+'-units.log')).read_text(errors='replace')
        assert '100% tests passed' in log and all('unit_'+n in log for n in units)
        rows[name]=dict(units=units,skipped=[line.strip() for line in log.splitlines() if '***Skipped' in line])
        for linkage in ('static','shared'):
            result=snapshots(s,p,b,t,profile,name+'-'+linkage,run,linkage)
            rows[name][linkage]=result
            if profile not in ('diet','reduced') and name in ('base','search','uniform'):
                from spelling_link import spelling
                rows[name].setdefault('spelling',{})[linkage]=spelling(s,p,b,t,profile,name+'-'+linkage,run,linkage)
                assert rows[name]['spelling'][linkage]==rows['base']['spelling'][linkage]
            if name.startswith('mips'):run(name+'-mips-projection',os.sys.executable,'-B',s/'suite/synctools/mips_register_names.py','--check')

            baseline=rows['base'][linkage]['snapshots']
            base_ids=rows['base'][linkage]['comparisons']
            assert base_ids.keys()==result['comparisons'].keys()
            assert result['comparisons']==base_ids
            assert baseline.keys()==result['snapshots'].keys()
            for key,entry in result['snapshots'].items():
                assert entry['counts']==baseline[key]['counts']
                if key.startswith('powerpc/') or profile=='diet':assert entry==baseline[key]
            if name!='base':
                assert result['snapshots']==rows['base'][linkage]['snapshots'],(name,linkage,profile)
        assert rows[name]['static']['snapshots']==rows[name]['shared']['snapshots']
        mac = platform.system()=='Darwin' and profile in ('full','noatt')
        linux = platform.system()=='Linux' and profile=='clang'
        win = platform.system()=='Windows' and profile in ('full','noatt')
        if linux:
            solo=t/'static-only'
            run(name+'-static-config','cmake','-G','Ninja','-S',s,'-B',solo,*flags,'-DCAPSTONE_BUILD_SHARED_LIBS=OFF')
            run(name+'-static-build','cmake','--build',solo,'--parallel','4','--target','capstone_static',*units)
            run(name+'-static-units','ctest','--test-dir',solo,'--output-on-failure','--no-tests=error','-R','^unit_('+'|'.join(units)+')$')
            commands=json.loads((solo/'compile_commands.json').read_text())
            amd=next(c['command']for c in commands if Path(c['file']).name=='X86Sse64Output.c')
            assert 'CAPSTONE_X86_NEAR_INDIRECT_OUTPUT' in amd
            access=next(c['command']for c in commands if Path(c['file']).name=='X86Mapping.c')
            import re
            clang_ver=sp.check_output(['clang','--version'],text=True)
            active=(platform.machine().lower() in ('amd64','x86_64') and re.search(r'clang version 18[.]',clang_ver) is not None)
            assert ('-DX86_CACHED_OPERAND_ACCESS' in access)==active
            dis=next(c['command']for c in commands if Path(c['file']).name=='X86Disassembler.c')
            assert ('-DX86_CHECK_EVEX_WRITEMASK' in dis)==active
            batch=next(c['command']for c in commands if Path(c['file']).name=='X86BatchScan.c')
            assert ('-DX86_BATCH_FALLBACK_ADDRESS' in batch)==active
            rows[name]['batch_address']=active 
            rows[name]['evex_only']=active
            rows[name]['cached_access']=active
            vex=next(c['command']for c in commands if Path(c['file']).name=='X86VectorFallback64.c')
            arm18=platform.machine().lower() in ('aarch64','arm64') and re.search(r'clang version 18[.]',clang_ver) is not None
            assert ('-DX86_VEX3_RIP_MEMORY' in vex)==(arm18 and name=='search')
            rows[name]['arm_vex3_memory']=arm18 and name=='search'
            result=snapshots(s,p,solo,t,profile,name+'-only',run,'static')
            assert result['snapshots']==rows[name]['static']['snapshots']
            rows[name]['static_only']=result
        save('results',rows)
    save('complete',dict(complete=True,source=q,profile=profile,architectures=arches,results=rows))
finally:
    n=sum(f.stat().st_size for f in t.rglob('*') if f.is_file() and not f.is_symlink())
    shutil.rmtree(t)
    save('cleanup',dict(removed=not t.exists(),bytes=n))
