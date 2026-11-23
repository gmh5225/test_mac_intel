from pathlib import Path
import hashlib,json,os,shutil,subprocess as sp,sys,tempfile
r=Path(__file__).resolve().parent;s=r.parent/'source';e=r.parent/'evidence';e.mkdir(exist_ok=True);t=Path(tempfile.mkdtemp())
rd=lambda p:json.loads(p.read_text());profile=os.environ['SCAN_PROFILE']
def put(n,v):(e/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def git(*args):return sp.check_output(['git','-C',s,*args],text=True).strip()
def run(n,*args):
    with (e/(n+'.log')).open('w')as o:z=sp.run(args,cwd=t,stdout=o,stderr=sp.STDOUT)
    text=(e/(n+'.log')).read_text(errors='replace')
    if z.returncode:print(text[-5000:]);z.check_returncode()
    return text.strip()
def stage(name,q):
    patch=t/(name+'.patch')
    patch.write_bytes(sp.check_output(['git','-C',r.parent,'cat-file','blob','HEAD:portable-next/'+name+'.patch']))
    assert hashlib.sha256(patch.read_bytes()).hexdigest()==q['sha256'];git('apply','--index',patch);assert git('write-tree')==q['tree']
try:
    q=rd(r/'tree.json');assert git('rev-parse','HEAD')==q['parent']
    results={};units=['api','mcinst','sstream','instruction_bytes'];b=t/'build';sample=t/'op.bin';sample.write_bytes(bytes((0,0)))
    for k in ('base','candidate'):
        if k=='candidate':
            stage(k,q);run('generated',sys.executable,s/'suite/synctools/xcore_literal_operands.py','--check')
        flags=['-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_XCORE_SUPPORT=ON','-DCAPSTONE_BUILD_DIET='+('ON'if profile=='diet' else 'OFF')]
        if sys.platform.startswith('linux'):flags.append('-DCMAKE_C_COMPILER=clang')
        run('configure-'+k,'cmake','-G','Ninja','-S',s,'-B',b,*flags)
        fixture_target=sys.platform.startswith('linux')and profile=='full' and k=='candidate'
        run('build-'+k,'cmake','--build',b,'--parallel','4','--target','capstone_static','capstone_shared',*units,*(['cstest']if fixture_target else []))
        assert '100% tests passed' in run('unit-'+k,'ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(units)+')$')
        if fixture_target:
            exe,=[f for f in b.rglob('cstest')if f.is_file()and os.access(f,os.X_OK)]
            log=run('fixture',exe,s/'tests/details/xcore.yaml')
            assert 'All tests succeeded' in log and 'Test files found: 1' in log
        exe=t/('records.exe'if os.name=='nt' else 'records')
        if os.name=='nt':
            archive,=b.rglob('capstone_static.lib');run('link-'+k,'cl','/nologo','/MT','/O2','/std:c11','/I'+str(s/'include'),r/'records.c',archive,'/Fe:'+str(exe))
        else:run('link-'+k,'cc','-std=c11','-O2','-I',s/'include',r/'records.c',b/'libcapstone.a','-o',exe)
        rows=results[k]={}
        for flags in (1,2,3,4,5,8,9,14,15):
            metrics=list(map(int,run(k+'-'+str(flags),exe,str(flags)).split()));assert metrics[:2]==[161450,297302]and len(metrics)==5
            rows[str(flags)]=metrics
            if k=='candidate':
                assert metrics=={'full': [161450, 297302, 121907, 10219016543264875195, 12164662004825336988], 'diet': [161450, 297302, 121907, 2646856490324891446, 12164662004825336988]}[profile] and results['base'][str(flags)][3]==metrics[3]and metrics==rows['1']
                if profile=='full':assert run('single-'+str(flags),exe,str(flags),sample)=='stw r0, r0[0]\tR,r0;M,r0,,0,1;'
                if profile=='full':
                    literal=t/'literal.bin';literal.write_bytes(bytes((0x00,0xf0,0x49,0x7f)))
                    assert run('literal-'+str(flags),exe,str(flags),literal)=='ldaw r11, cp[9]\tR,r11;M,cp,,9,1;' 
        if k=='base':assert rows['1'][2]==2920
    if sys.platform.startswith('linux'):
        # Fill unconstructed slots after the partial initializer. A changed public field
        # or a changed callback's input would expose any read of one of those slots.
        file=s/'MCInst.h';original=file.read_text();needle='const size_t operands_end =';assert original.count(needle)==1
        for fill in (0x5a,0xa5):
            file.write_text(original.replace(needle,
                'memset(inst->Operands + 1, '+str(fill)+', sizeof(inst->Operands) - sizeof(inst->Operands[0])); '+needle))
            run('poison-build-'+str(fill),'cmake','--build',b,'--target','capstone_static','--parallel','4')
            run('poison-link','cc','-std=c11','-O2','-I',s/'include',r/'records.c',b/'libcapstone.a','-o',exe)
            for flag in (1,2,14):
                record=list(map(int,run('poison-'+str(fill)+'-'+str(flag),exe,str(flag)).split()))
                assert record==results['candidate'][str(flag)]
            if profile=='full':
                hook=t/'callbacks'
                run('callback-link','cc','-std=c11','-O2','-DCAPSTONE_HAS_XCORE','-I',s,'-I',s/'include',r/'callbacks.c',b/'libcapstone.a','-o',hook)
                assert run('callback-'+str(fill),hook)=='6 0'
        file.write_text(original)
    put('complete',dict(source=q,units=units,profile=profile,static=True,shared=True,official_fixture=fixture_target,rows=results))
finally:
    n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);put('cleanup',dict(removed=not t.exists(),bytes=n))
